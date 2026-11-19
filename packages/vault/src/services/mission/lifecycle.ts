// Mission lifecycle transitions. open() signs the mission_open claim and inserts the denormalized
// row; complete() and revoke() each sign a new claim sharing the mission_id, update the row and
// end every Passport bound to the mission inside the same transaction. A Mission's end kills its
// Passports, and a failed Passport revoke rolls the transition back.

import { createHash, randomBytes } from 'node:crypto';
import {
  DEFAULT_CAP_TIME_ZONE,
  InvalidRequestError,
  isIanaTimeZone,
  safeErrorSummary,
  canonicalize,
  SchemaValidationError,
  ServiceUnavailableError,
  assertBoundedJsonValue,
} from '@stack/shared';
import { ConflictError, NotFoundError, type MissionClaim, ids } from '@stack/shared';
import type { MissionRevokeReason, MissionTerminalState } from '../../repositories/mission-repo.js';
import { assertScopeIsSubset } from './helpers.js';
import {
  computeMissionDiff,
  endBoundPassports,
  fireTwinDivergenceEvaluation,
  publishMissionEnd,
  syncEndedPassports,
} from './lifecycle-effects.js';
import {
  type MissionServiceDeps,
  type OpenInput,
  type OpenResult,
  type CompleteInput,
  type CompleteResult,
  type RevokeInput,
  type RevokeResult,
  type ExtendInput,
  type ExtendResult,
} from './types.js';
import {
  CLAIM_CAP_BEHAVIOR,
  DEFAULT_MISSION_TTL_SECONDS,
  type TwinPolicyEnum,
  assertMissionEnd,
  resolveTwinPolicy,
  isOperatorCleanReason,
  compileOutputSchema,
} from './helpers.js';

/**
 * Open a mission. Signs the `mission_open` claim envelope, inserts
 * the denormalized missions row, and returns the mission_id +
 * claim_id for the caller to embed in subsequent passport-issue
 * calls (passport.mission_ids[]).
 */
export async function open(deps: MissionServiceDeps, input: OpenInput): Promise<OpenResult> {
  if (input.expected_output_shape) compileOutputSchema(input.expected_output_shape);
  // Scope subset validation. When parentPassportServices is provided,
  // the mission's intent_services must be a subset.
  if (input.parentPassportServices) {
    assertScopeIsSubset(input.intent_services ?? [], input.parentPassportServices);
  }

  const capTimeZone = input.cap_time_zone ?? DEFAULT_CAP_TIME_ZONE;
  if (!isIanaTimeZone(capTimeZone)) throw new InvalidRequestError('cap_time_zone must be an IANA time zone, such as Europe/Stockholm.');
  const ttl = Math.max(1, input.expiresInSeconds ?? DEFAULT_MISSION_TTL_SECONDS);
  const now = new Date();
  assertMissionEnd(now.getTime() + ttl * 1000);
  const expiresAt = new Date(now.getTime() + ttl * 1000);
  const missionId = input.missionId ?? ids.mission();

  // baseline snapshot + drift detector re-arm.
  // When passportJti + behavioralGenome are present, fetch the
  // passport's latest behavioral_genome and seal its full payload as
  // baseline_profile. Best-effort: failure logs + falls through to
  // input.baseline_profile (or null) so mission open never blocks on
  // a slow genome lookup.
  let baselineProfile: Record<string, unknown> | null = input.baseline_profile ?? null;
  const passportJti = input.passportJti ?? null;

  if (passportJti && deps.behavioralGenome) {
    try {
      const latest = await deps.behavioralGenome.getLatestForPassport(passportJti);
      if (latest) {
        baselineProfile = latest.body_json as Record<string, unknown>;
      }
    } catch (err) {
      console.warn(
        '[MissionService.open] genome baseline fetch failed:', passportJti,
        safeErrorSummary(err),
      );
    }
    if (deps.redis) {
      // Best-effort: re-arm the drift detector for the new
      // baseline window. Mission open MUST NOT fail if Redis is down.
      deps.redis.del(`genome_drift_fired:${passportJti}`).catch((err: unknown) => {
        console.warn(
          '[MissionService.open] genome_drift_fired key delete failed:', passportJti,
          safeErrorSummary(err),
        );
      });
    }
  }

  const payload: MissionClaim = {
    assigned_agent_id: input.assignedAgentId ?? null,
    authorization_digest: input.authorizationDigest ?? null,
    type: 'mission',
    mission_id: missionId,
    operator_id: input.operatorId,
    passport_jti: passportJti,
    intent_summary: input.intent_summary,
    intent_services: input.intent_services ?? [],
    expected_counterparties: input.expected_counterparties ?? [],
    baseline_profile: baselineProfile,
    behavioral_diff: null,
    expected_output_shape: input.expected_output_shape ?? null,
    max_actions: input.max_actions ?? null,
    max_dropoff_bytes: input.max_dropoff_bytes ?? null,
    coverage_cap_cents: input.coverage_cap_cents ?? null,
    max_duration_seconds: input.max_duration_seconds ?? null,
    max_concurrent_intents: input.max_concurrent_intents ?? null,
    max_actions_per_service: input.max_actions_per_service ?? {},
    // The behaviour of each cap is on the Mission row: the published claim schema names only the earlier values.
    cap_behavior: CLAIM_CAP_BEHAVIOR,
    started_at: now.getTime(),
    expires_at: expiresAt.getTime(),
    completed_at: null,
    terminal_state: null,
    revoke_reason: null,
  };

  const created = await deps.repo.createWithClaim(
    {
      assigned_agent_id: input.assignedAgentId ?? null,
      authorization_digest: input.authorizationDigest ?? null,
      mission_id: missionId,
      operator_id: input.operatorId,
      passport_jti: passportJti,
      intent_summary: input.intent_summary,
      intent_services: input.intent_services ?? [],
      expected_counterparties: input.expected_counterparties ?? [],
      baseline_profile: baselineProfile,
      expected_output_shape: input.expected_output_shape ?? null,
      max_actions: input.max_actions ?? null,
      max_dropoff_bytes: input.max_dropoff_bytes ?? null,
      coverage_cap_cents: input.coverage_cap_cents ?? null,
      max_duration_seconds: input.max_duration_seconds ?? null,
      max_concurrent_intents: input.max_concurrent_intents ?? null,
      max_actions_per_service: input.max_actions_per_service ?? {},
      cap_behavior: input.cap_behavior ?? {},
      coverage_cap_period: input.coverage_cap_period ?? 'mission',
      cap_time_zone: capTimeZone,
      making_orders_up_to_cents: input.making_orders_up_to_cents ?? null,
      // Fixed here and never updated: parallel calls under the Mission all read the same pins.
      recipient_pins: input.recipient_pins ?? null,
      started_at: now,
      expires_at: expiresAt,
    },
    async (persistence) =>
      (
        await deps.claimRegistry.registerClaim(
          {
            operatorId: input.operatorId,
            claimType: 'mission',
            payload,
            subjectOverride: 'operator',
          },
          { persistence },
        )
      ).claimId,
  );

  // twin runtime opt-in. Best-effort: if anything
  // fails the mission lifecycle still ships. Requires passportJti
  // (no passport → no agent → no policy → skip twin) AND all three
  // deps (agentRepo + passportRepo + twinOrchestration) wired. Same
  // best-effort pattern as the baseline snapshot above.
  if (
    passportJti &&
    deps.agentRepo &&
    deps.passportRepo &&
    deps.twinOrchestration
  ) {
    try {
      const passportRow = await deps.passportRepo.findByJti(passportJti);
      const agent = passportRow ? await deps.agentRepo.findById(passportRow.agent_id) : null;
      if (agent) {
        const shouldRun = resolveTwinPolicy({
          policy: (agent.twin_policy ?? 'per_mission') as TwinPolicyEnum,
          explicitRunTwin: input.run_twin,
          mission: {
            coverage_cap_cents: input.coverage_cap_cents ?? null,
            cap_behavior: input.cap_behavior ?? {},
          },
        });
        if (shouldRun) {
          await deps.twinOrchestration.startTwinForMission({
            missionId,
            realPassportJti: passportJti,
          });
        }
      }
    } catch (err) {
      console.error(
        '[MissionService.open] twin start failed:', missionId,
        safeErrorSummary(err),
      );
    }
  }

  return {
    mission_id: missionId,
    claim_id: created.claim_id,
    expires_at: expiresAt,
  };
}

/**
 * Complete a mission. Idempotent — second call returns the prior
 * terminal state without transitioning. Emits a NEW mission claim
 * with terminal_state set; the row's claim_id pointer updates to
 * the new claim.
 */
export async function complete(
  deps: MissionServiceDeps,
  missionId: string,
  input: CompleteInput = {},
): Promise<CompleteResult> {
  const existing = await deps.repo.findById(missionId);
  if (!existing) {
    throw new NotFoundError('mission', missionId);
  }

  if (input.actor) {
    const actor = input.actor;
    const ownsMission =
      existing.operator_id === actor.operatorId &&
      (!actor.agentId ||
        (existing.assigned_agent_id
          ? existing.assigned_agent_id === actor.agentId
          : await deps.repo.hasAgent(missionId, actor.operatorId, actor.agentId)));
    if (!ownsMission) throw new NotFoundError('mission', missionId);
  }

  // Idempotency on prior terminal state.
  if (existing.completed_at) {
    return {
      mission_id: missionId,
      claim_id: existing.claim_id,
      terminal_state: existing.terminal_state as MissionTerminalState,
      completed_at: existing.completed_at,
      transitioned: false,
    };
  }
  if (existing.revoked_at) {
    throw new ConflictError(
      `mission ${missionId} is already revoked (reason: ${existing.revoked_reason}); cannot complete`,
    );
  }

  const terminalState: MissionTerminalState = input.capBreached
    ? 'completed_cap_breached'
    : input.expired ||
        existing.expires_at.getTime() <= Date.now() ||
        (existing.max_duration_seconds !== null &&
          Date.now() >= existing.started_at.getTime() + existing.max_duration_seconds * 1000)
      ? 'completed_expired'
      : 'completed_successful';
  const now = new Date();

  if (input.output !== undefined) {
    try {
      assertBoundedJsonValue(input.output);
    } catch {
      throw new SchemaValidationError({ field: 'output' });
    }
  }
  if (terminalState === 'completed_successful' && existing.expected_output_shape) {
    const validate = compileOutputSchema(existing.expected_output_shape);
    if (!validate(input.output)) throw new SchemaValidationError({ field: 'output' });
  }
  let outputRecord:
    | { output_encrypted: string; output_digest: string; key_ref: string }
    | undefined;
  if (input.output !== undefined) {
    if (!deps.kms) throw new ServiceUnavailableError();
    const serialized = canonicalize(input.output);
    if (Buffer.byteLength(serialized) > 1_048_576)
      throw new SchemaValidationError({ field: 'output' });
    const committed = canonicalize({
      salt: randomBytes(32).toString('hex'),
      output: input.output,
    });
    const encrypted = await deps.kms.encrypt(committed, {
      operator_id: existing.operator_id,
      mission_id: missionId,
      store: 'mission_output',
    });
    outputRecord = {
      output_encrypted: encrypted.ciphertext,
      key_ref: encrypted.keyRef,
      output_digest: createHash('sha256').update(committed).digest('hex'),
    };
  }

  // compute behavioral_diff if baseline + passport_jti
  // present + behavioralGenome wired. Best-effort: any failure here
  // (parse error on legacy baseline, computeGenome throw, etc.) MUST
  // NOT block mission completion. The mission completion is primary;
  // the diff is forensic icing.
  const behavioralDiff = await computeMissionDiff(
    deps,
    existing.passport_jti,
    existing.baseline_profile,
    existing.started_at.getTime(),
    existing.mission_id,
  );

  // Emit the new mission claim carrying terminal_state.
  const newPayload: MissionClaim = {
    assigned_agent_id: existing.assigned_agent_id ?? null,
    authorization_digest: existing.authorization_digest ?? null,
    output_digest: outputRecord?.output_digest ?? null,
    type: 'mission',
    mission_id: existing.mission_id,
    operator_id: existing.operator_id,
    passport_jti: existing.passport_jti,
    intent_summary: existing.intent_summary,
    intent_services: existing.intent_services,
    expected_counterparties: existing.expected_counterparties,
    baseline_profile: existing.baseline_profile,
    behavioral_diff: behavioralDiff,
    expected_output_shape: existing.expected_output_shape,
    max_actions: existing.max_actions,
    max_dropoff_bytes: existing.max_dropoff_bytes,
    coverage_cap_cents: existing.coverage_cap_cents,
    max_duration_seconds: existing.max_duration_seconds,
    max_concurrent_intents: existing.max_concurrent_intents,
    max_actions_per_service: existing.max_actions_per_service,
    cap_behavior: CLAIM_CAP_BEHAVIOR,
    started_at: existing.started_at.getTime(),
    expires_at: existing.expires_at.getTime(),
    completed_at: now.getTime(),
    terminal_state: terminalState,
    revoke_reason: null,
  };
  const ended = endBoundPassports(
    deps,
    existing.operator_id,
    missionId,
    `mission ${missionId} ended (${terminalState})`,
    false,
  );
  const completedRow = await deps.repo.transitionWithClaim(
    missionId,
    existing.claim_id,
    {
      completed_at: now,
      terminal_state: terminalState,
    },
    async (persistence) =>
      (
        await deps.claimRegistry.registerClaim(
          {
            operatorId: existing.operator_id,
            claimType: 'mission',
            payload: newPayload,
            subjectOverride: 'operator',
          },
          { persistence },
        )
      ).claimId,
    outputRecord,
    ended.step,
  );
  const endedJtis = await syncEndedPassports(deps, ended.rows());
  if (endedJtis.length > 0) {
    await publishMissionEnd(deps, existing.operator_id, missionId, terminalState, endedJtis);
  }

  fireTwinDivergenceEvaluation(deps, missionId, existing.operator_id, 'complete');

  return {
    mission_id: missionId,
    claim_id: completedRow.claim_id,
    terminal_state: terminalState,
    completed_at: now,
    transitioned: true,
  };
}

/**
 * Revoke a mission. Idempotent. Emits a NEW mission claim with
 * revoke_reason + terminal_state set; updates the row.
 *
 * every reason revokes every Passport bound to the Mission
 * (and their delegated descendants) in the same transaction.
 * adversarial and cap_breach_hard also revoke the claims those
 * Passports carried. A Passport revoke never revokes its Mission;
 * 'cascade_from_passport' survives only as a historical reason.
 */
export async function revoke(
  deps: MissionServiceDeps,
  missionId: string,
  input: RevokeInput,
): Promise<RevokeResult> {
  const existing = await deps.repo.findById(missionId);
  if (!existing) {
    throw new NotFoundError('mission', missionId);
  }

  // Idempotency: if already revoked, return existing state without re-emitting.
  if (existing.revoked_at) {
    return {
      mission_id: missionId,
      claim_id: existing.claim_id,
      terminal_state: existing.terminal_state as MissionTerminalState,
      revoked_at: existing.revoked_at,
      revoke_reason: existing.revoked_reason as MissionRevokeReason,
      transitioned: false,
    };
  }
  if (existing.completed_at) {
    throw new ConflictError(
      `mission ${missionId} is already completed (terminal_state: ${existing.terminal_state}); cannot revoke`,
    );
  }

  const terminalState: MissionTerminalState = isOperatorCleanReason(input.reason)
    ? 'revoked_operator_clean'
    : 'revoked_adversarial';
  const now = new Date();

  // also compute behavioral_diff on revoke. Adversarial
  // + cap_breach_hard revokes especially benefit from this forensic
  // signal (often the agent's behavior was the reason for the revoke).
  // Operator_initiated_clean + cascade_from_passport revokes also get
  // the diff so the post-incident review has consistent shape across
  // all terminal paths.
  const behavioralDiff = await computeMissionDiff(
    deps,
    existing.passport_jti,
    existing.baseline_profile,
    existing.started_at.getTime(),
    existing.mission_id,
  );

  const newPayload: MissionClaim = {
    type: 'mission',
    mission_id: existing.mission_id,
    assigned_agent_id: existing.assigned_agent_id ?? null,
    authorization_digest: existing.authorization_digest ?? null,
    operator_id: existing.operator_id,
    passport_jti: existing.passport_jti,
    intent_summary: existing.intent_summary,
    intent_services: existing.intent_services,
    expected_counterparties: existing.expected_counterparties,
    baseline_profile: existing.baseline_profile,
    behavioral_diff: behavioralDiff,
    expected_output_shape: existing.expected_output_shape,
    max_actions: existing.max_actions,
    max_dropoff_bytes: existing.max_dropoff_bytes,
    coverage_cap_cents: existing.coverage_cap_cents,
    max_duration_seconds: existing.max_duration_seconds,
    max_concurrent_intents: existing.max_concurrent_intents,
    max_actions_per_service: existing.max_actions_per_service,
    cap_behavior: CLAIM_CAP_BEHAVIOR,
    started_at: existing.started_at.getTime(),
    expires_at: existing.expires_at.getTime(),
    completed_at: null,
    terminal_state: terminalState,
    revoke_reason: input.reason,
  };
  // Every revoke reason ends the Mission's Passports. Adversarial and
  // hard-cap revokes also revoke the claims those Passports carried, as a
  // direct Passport revoke does; a clean revoke keeps them as evidence.
  const ended = endBoundPassports(
    deps,
    existing.operator_id,
    missionId,
    `mission ${missionId} revoked (${input.reason})`,
    input.reason === 'adversarial' || input.reason === 'cap_breach_hard',
  );
  const updatedRow = await deps.repo.transitionWithClaim(
    missionId,
    existing.claim_id,
    {
      revoked_at: now,
      revoked_reason: input.reason,
      terminal_state: terminalState,
    },
    async (persistence) =>
      (
        await deps.claimRegistry.registerClaim(
          {
            operatorId: existing.operator_id,
            claimType: 'mission',
            payload: newPayload,
            subjectOverride: 'operator',
          },
          { persistence },
        )
      ).claimId,
    undefined,
    ended.step,
  );
  const cascadedJtis = await syncEndedPassports(deps, ended.rows());

  fireTwinDivergenceEvaluation(deps, missionId, existing.operator_id, 'revoke');

  // Publish the bulk_mission RevocationEvent on stack:revoked so
  // subscribers see the revoke and the Passports it ended.
  await publishMissionEnd(deps, existing.operator_id, missionId, input.reason, cascadedJtis);

  return {
    mission_id: missionId,
    claim_id: updatedRow.claim_id,
    terminal_state: terminalState,
    revoked_at: now,
    revoke_reason: input.reason,
    transitioned: true,
  };
}

/**
 * Move a live Mission's expiry and coverage cap forward. Emits a new mission
 * claim with the new values, as every other transition does, so the signed
 * record shows each renewal. Refuses a Mission that has ended: an ended
 * Mission never comes back.
 */
export async function extend(
  deps: MissionServiceDeps,
  missionId: string,
  input: ExtendInput,
): Promise<ExtendResult> {
  const existing = await deps.repo.findById(missionId);
  if (!existing) throw new NotFoundError('mission', missionId);
  if (existing.completed_at || existing.revoked_at) {
    throw new ConflictError(`mission ${missionId} has ended; it cannot be extended`);
  }
  const expiresAt = input.expiresAt;
  assertMissionEnd(expiresAt.getTime());
  const payload: MissionClaim = {
    type: 'mission',
    mission_id: existing.mission_id,
    assigned_agent_id: existing.assigned_agent_id ?? null,
    authorization_digest: existing.authorization_digest ?? null,
    operator_id: existing.operator_id,
    passport_jti: existing.passport_jti,
    intent_summary: existing.intent_summary,
    intent_services: existing.intent_services,
    expected_counterparties: existing.expected_counterparties,
    baseline_profile: existing.baseline_profile,
    behavioral_diff: null,
    expected_output_shape: existing.expected_output_shape,
    max_actions: existing.max_actions,
    max_dropoff_bytes: existing.max_dropoff_bytes,
    coverage_cap_cents: input.coverageCapCents,
    max_duration_seconds: existing.max_duration_seconds,
    max_concurrent_intents: existing.max_concurrent_intents,
    max_actions_per_service: existing.max_actions_per_service,
    cap_behavior: CLAIM_CAP_BEHAVIOR,
    started_at: existing.started_at.getTime(),
    expires_at: expiresAt.getTime(),
    completed_at: null,
    terminal_state: null,
    revoke_reason: null,
  };
  const row = await deps.repo.transitionWithClaim(
    missionId,
    existing.claim_id,
    { expires_at: expiresAt, coverage_cap_cents: input.coverageCapCents },
    async (persistence) =>
      (
        await deps.claimRegistry.registerClaim(
          {
            operatorId: existing.operator_id,
            claimType: 'mission',
            payload,
            subjectOverride: 'operator',
          },
          { persistence },
        )
      ).claimId,
  );
  return {
    mission_id: missionId,
    claim_id: row.claim_id,
    expires_at: expiresAt,
    coverage_cap_cents: input.coverageCapCents,
  };
}

/**
 * Hard auto-revoke triggered by a hard-cap breach (default response
 * for coverage_cap_cents, max_dropoff_bytes, max_concurrent_intents).
 * Convenience wrapper around revoke() with reason='cap_breach_hard'.
 * Caller (proxy gate) invokes after checkGate returns a cap-shape
 * denial with capBehavior === 'auto_revoke'.
 */
export async function autoRevokeForCapBreach(
  deps: MissionServiceDeps,
  missionId: string,
  capName: string,
): Promise<RevokeResult> {
  return revoke(deps, missionId, {
    reason: 'cap_breach_hard',
    notes: `auto-revoke triggered by ${capName} cap breach`,
  });
}
