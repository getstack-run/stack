// TwinOrchestrationService.
//
// Substrate for Mission Layer Pillar 2 ground truth: the twin runs
// every mission's actions a SECOND time against a different model or
// provider, in parallel; divergence between real + twin chains at
// mission close becomes a signed TwinDivergenceClaim (5.3.1 schema).
//
// This service owns the twin runtime lifecycle:
//
//   - startTwinForMission(missionId, realPassportJti)
//       Issues a twin passport mirroring the real passport's scope
//       and inserts the twin_runs lookup row. Idempotent on
//       mission_id.
//
//   - mirrorIntent(twinRunId, realIntentClaim, realClaimId)
//       Registers a paired twin intent_claim via claimRegistry under
//       the twin passport + records the (real, twin) pair in
//       twin_runs.claim_pairs. Best-effort: failure logs + returns
//       null so mission flow never fails on twin bookkeeping.
//
//   - mirrorOutcome(twinRunId, realOutcomeClaimId, twinOutcomeClaimId)
//       Records the (real, twin) outcome pair. The twin's actual
//       intent_outcome emission lands in 5.3.5 (sealed-exec runtime);
//       5.3.2 just provides the bookkeeping hook.
//
//   - evaluateDivergence(missionId, operatorId)
//       Mission-close hook. **5.3.2 STUB**: emits an empty
//       TwinDivergenceClaim so the wire-shape from 5.3.1 gets
//       exercised end-to-end on day 1. **5.3.4 replaces this with
//       real per-dimension math** (output_shape / counterparty /
//       cost / detector_signal_set diffs).
//
// **No call sites yet** — 5.3.2 ships the substrate only. 5.3.3 wires
// startTwinForMission into MissionService.open (gated by
// agent.twin_policy + per-mission run_twin override) + mirrorIntent
// into a ClaimRegistryService post-persist hook for intent_claim.
// 5.3.5 wires the actual twin execution runtime.

import {
  ids,
  type IntentClaim,
  type IntentOutcomeClaim,
  type TwinDivergenceClaim,
} from '@stack/shared';
import { safeErrorSummary } from '@stack/shared';
import type { TwinRunsRepository } from '../repositories/twin-runs-repo.js';
import type { PassportRepository } from '../repositories/passport-repo.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { PassportService } from './passport-service.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import { computeDivergence, type OutcomeEntry } from './twin-divergence-math.js';

export interface TwinOrchestrationServiceDeps {
  repo: TwinRunsRepository;
  passportService: PassportService;
  passportRepo: PassportRepository;
  claimRegistry: ClaimRegistryService;
  /**
   * required for evaluateDivergence to load paired
   * outcome payloads + detector_signal claims for both sides of the
   * twin run. Constructed alongside everything else at boot
   * (apps/api/src/config/services.ts). The other methods don't touch
   * it but it's a required dep so production wiring never silently
   * loses the divergence math.
   */
  passportClaimsRepo: PassportClaimsRepository;
  /**
   * optional agent lookup used by
   * `resolveTwinInvocationContext` to read the agent's
   * `twin_llm_model` field. When unwired, twin invocations fall
   * through to "use same model as real" (lower divergence signal but
   * structurally identical). Production wiring at
   * apps/api/src/config/services.ts always passes the same `agentRepo`
   * already in use by MissionService.
   */
  agentRepo?: { findById(agentId: string): Promise<{ twin_llm_model?: string | null; [key: string]: unknown } | null | undefined> };
  /**
   * bounded-wait settling window before `evaluateDivergence`
   * reads `twin_runs.claim_pairs`. Closes the late-outcome race: twin
   * invocations are fire-and-forget from the skills route, so a late
   * `mirrorOutcome` can land after `MissionService.complete` fires
   * `evaluateDivergence`. The wait polls until intent-pair count equals
   * outcome-pair count, or the timeout expires. On timeout, falls back to
   * today's best-effort behaviour (evaluate with whatever's persisted).
   *
   * Mission close stays fire-and-forget — only the divergence claim
   * emission is delayed by the settling window, never the agent flow.
   *
   * Defaults: 10000ms timeout, 200ms poll.
   */
  twinSettleTimeoutMs?: number;
  twinSettlePollMs?: number;
}

export interface StartTwinForMissionInput {
  missionId: string;
  realPassportJti: string;
}

export interface StartTwinForMissionResult {
  twinPassportJti: string;
  twinRunId: string;
}

export interface MirrorIntentInput {
  twinRunId: string;
  /** Operator id (the real operator — twin claims belong to the same
   * operator per the v1 ownership decision). 5.3.3's
   * ClaimRegistryService post-persist hook already has this in
   * context, so we thread it explicitly rather than re-deriving via
   * passport lookup. */
  operatorId: string;
  /** Twin passport JTI — the same value as TwinRunRow.twin_passport_jti.
   * Caller has it from findByRealPassportJti(); passing it avoids a
   * second repo read inside mirrorIntent. */
  twinPassportJti: string;
  realIntentClaim: IntentClaim;
  realClaimId: string;
}

export interface EvaluateDivergenceInput {
  missionId: string;
  operatorId: string;
}

export interface EvaluateDivergenceResult {
  /** Null when there's no twin_run for the mission (no twin was
   * opened) OR when evaluation failed irrecoverably. */
  divergenceClaimId: string | null;
}

export class TwinOrchestrationService {
  constructor(private deps: TwinOrchestrationServiceDeps) {}

  /**
   * Open a twin run for an active mission. Issues a twin passport
   * mirroring the real passport's scope, inserts the twin_runs row,
   * returns the twin passport JTI for the caller to thread.
   *
   * Idempotent on mission_id: if a twin run already exists for the
   * mission, returns the existing twin passport JTI without
   * re-issuing.
   *
   * Twin passport semantics (v1 — see plan §5.3.2 decision 1):
   *   - operator_id: REAL operator (not op_stack_system). The "shadow
   *     operator" in the macro spec refers to cost-bearing (5.3.4/5.3.5
   *     billing carve-out), not identity.
   *   - agent_id: REAL agent. The twin IS the same agent under a
   *     different model — preserving agent identity is required for
   *     divergence math.
   *   - intent.summary: `[TWIN] <real summary>` — grep-friendly.
   *   - intent.services: mirrors real passport's intent_services.
   *   - accountability_mode: 'logged' (NOT 'enforced' — twin must not
   *     gate via approvals; NOT 'standard' — twin must emit claims).
   *   - TTL: matches real passport's remaining lifetime.
   */
  async startTwinForMission(input: StartTwinForMissionInput): Promise<StartTwinForMissionResult> {
    // Idempotency: existing run wins.
    const existing = await this.deps.repo.findByMissionId(input.missionId);
    if (existing) {
      return {
        twinPassportJti: existing.twin_passport_jti,
        twinRunId: existing.id,
      };
    }

    const realPassport = await this.deps.passportRepo.findByJti(input.realPassportJti);
    if (!realPassport) {
      throw new Error(`startTwinForMission: real passport ${input.realPassportJti} not found`);
    }

    const remainingTtlSec = Math.max(
      60,
      Math.floor((realPassport.expires_at.getTime() - Date.now()) / 1000),
    );

    const realServices = realPassport.intent_services ?? [];
    const realSummary = realPassport.intent_summary ?? '(unspecified)';

    const issued = await this.deps.passportService.issue(realPassport.operator_id, {
      agent_id: realPassport.agent_id,
      ttl_seconds: remainingTtlSec,
      intent: {
        summary: `[TWIN] ${realSummary}`,
        services: realServices,
      },
      // Bind to the same mission so the twin claims chain into the
      // mission's own claim_pairs at mission close.
      mission_ids: [input.missionId],
    });

    const twinRunId = ids.twinRun();
    await this.deps.repo.insert({
      id: twinRunId,
      mission_id: input.missionId,
      real_passport_jti: input.realPassportJti,
      twin_passport_jti: issued.jti,
    });

    return {
      twinPassportJti: issued.jti,
      twinRunId,
    };
  }

  /**
   * Register a twin intent_claim that mirrors the real one. The twin
   * gets its own signed intent_claim under the twin passport so the
   * divergence eval can compare the chain shapes.
   *
   * Best-effort: failure logs + returns null. The mission must not
   * fail because twin bookkeeping failed.
   */
  async mirrorIntent(input: MirrorIntentInput): Promise<{ twinClaimId: string } | null> {
    // The twin's intent_claim is structurally identical to the real
    // one — same shape, same parameters. 5.3.4's divergence math
    // compares the OUTCOMES under each passport, not the intents.
    // Keeping payloads bit-identical makes divergence attribution
    // cleaner.
    try {
      const result = await this.deps.claimRegistry.registerClaim({
        operatorId: input.operatorId,
        passportJti: input.twinPassportJti,
        claimType: 'intent_claim',
        payload: input.realIntentClaim,
      });
      await this.deps.repo.appendClaimPair({
        twinRunId: input.twinRunId,
        realClaimId: input.realClaimId,
        twinClaimId: result.claimId,
        kind: 'intent',
      });
      return { twinClaimId: result.claimId };
    } catch (err) {
      console.error('[TwinOrchestrationService.mirrorIntent] failed:', safeErrorSummary(err));
      return null;
    }
  }

  /**
   * Record a (real, twin) outcome pair. The twin's intent_outcome
   * emission happens in 5.3.5 (sealed-exec runtime); this method just
   * records the pair so evaluateDivergence can walk both chains.
   *
   * Best-effort: failure logs + swallows. Outcome divergence is
   * eventually-consistent.
   */
  async mirrorOutcome(args: {
    twinRunId: string;
    realOutcomeClaimId: string;
    twinOutcomeClaimId: string;
  }): Promise<void> {
    try {
      await this.deps.repo.appendClaimPair({
        twinRunId: args.twinRunId,
        realClaimId: args.realOutcomeClaimId,
        twinClaimId: args.twinOutcomeClaimId,
        kind: 'outcome',
      });
    } catch (err) {
      console.error('[TwinOrchestrationService.mirrorOutcome] failed:', safeErrorSummary(err));
    }
  }

  /**
   * resolve twin invocation context for a real call
   * about to execute under `realPassportJti` in mission `missionId`.
   * Returns the twin's passport JTI + LLM model override + run id +
   * agent id + the (realIntentClaimId → twinIntentClaimId) map for
   * the caller to look up the twin's intent_claim_ref when emitting
   * the twin's intent_outcome.
   *
   * Returns null for:
   *   - missionId is null (no twin without a mission)
   *   - no active twin_run for the mission (status !== 'running')
   *   - realPassportJti IS the twin passport jti (anti-recursion guard:
   *     prevents a twin invocation from triggering its own twin →
   *     infinite cascade)
   *
   * Best-effort: any internal failure (repo read fails, agentRepo
   * unwired) returns null cleanly. Caller treats null as "no twin
   * mirror for this invocation."
   */
  async resolveTwinInvocationContext(args: {
    realPassportJti: string;
    missionId: string | null;
  }): Promise<{
    twinPassportJti: string;
    twinLlmModel: string | null;
    twinRunId: string;
    agentId: string;
    realIntentClaimToTwinIntentClaim: Map<string, string>;
  } | null> {
    if (!args.missionId) return null;
    let run;
    try {
      run = await this.deps.repo.findByMissionId(args.missionId);
    } catch (err) {
      console.error('[TwinOrchestrationService.resolveTwinInvocationContext] repo lookup failed:', safeErrorSummary(err));
      return null;
    }
    if (!run) return null;
    if (run.status !== 'running') return null;
    // Anti-recursion: a real-side invocation under the twin passport
    // would otherwise trigger a second twin invocation under itself.
    if (args.realPassportJti === run.twin_passport_jti) return null;

    // Resolve the agent for the real passport (twin passport shares
    // the same agent_id per the 5.3.2 ownership decision — preserving
    // agent identity is required for divergence math).
    let agentId = '';
    let twinLlmModel: string | null = null;
    try {
      const realPassport = await this.deps.passportRepo.findByJti(args.realPassportJti);
      if (realPassport) agentId = realPassport.agent_id;
      if (agentId && this.deps.agentRepo) {
        const agent = await this.deps.agentRepo.findById(agentId);
        if (agent && agent.twin_llm_model !== undefined && agent.twin_llm_model !== null) {
          twinLlmModel = agent.twin_llm_model;
        }
      }
    } catch (err) {
      console.error('[TwinOrchestrationService.resolveTwinInvocationContext] agent lookup failed:', safeErrorSummary(err));
      // Continue without model override — twin will fall through to
      // skill default. Better signal than no twin at all.
    }

    const realIntentClaimToTwinIntentClaim = new Map<string, string>();
    for (const pair of run.claim_pairs) {
      if (pair.kind === 'intent') {
        realIntentClaimToTwinIntentClaim.set(pair.real_claim_id, pair.twin_claim_id);
      }
    }

    return {
      twinPassportJti: run.twin_passport_jti,
      twinLlmModel,
      twinRunId: run.id,
      agentId,
      realIntentClaimToTwinIntentClaim,
    };
  }

  /**
   * Mission-close hook: walk real + twin chains, compute divergence,
   * emit TwinDivergenceClaim.
   *
   * real per-dimension math (output_shape
   * counterparty / cost / detector_signal_set). Pure math lives in
   * twin-divergence-math.ts; this method orchestrates loading the
   * paired outcome payloads + per-side detector_signal claims, then
   * delegates to computeDivergence. Severity classification +
   * thresholds are owned by the pure helper.
   *
   * Idempotent via twin_runs.status CAS — repeat calls return the
   * already-emitted divergence_claim_id.
   *
   * Returns `{ divergenceClaimId: null }` cleanly when there's no
   * twin_run for the mission (caller didn't open one) — caller
   * doesn't need to gate the call.
   */
  async evaluateDivergence(input: EvaluateDivergenceInput): Promise<EvaluateDivergenceResult> {
    const run = await this.deps.repo.findByMissionId(input.missionId);
    if (!run) {
      return { divergenceClaimId: null };
    }
    if (run.status === 'evaluated') {
      // Already evaluated — return prior claim id.
      return { divergenceClaimId: run.divergence_claim_id };
    }
    if (run.status === 'failed') {
      return { divergenceClaimId: null };
    }

    // bounded-wait settling window. Twin invocations are
    // fire-and-forget from the skills route, so a late `mirrorOutcome`
    // can land after MissionService.complete fires evaluateDivergence.
    // Poll until intent-pair count == outcome-pair count, or timeout.
    // On timeout, fall through to best-effort partial eval (same as v1).
    const settled = await this.waitForOutcomePairSettlement(input.missionId);
    const claimPairs = settled?.claim_pairs ?? run.claim_pairs;

    const outcomePairs = claimPairs.filter((p) => p.kind === 'outcome');
    const intentPairs = claimPairs.filter((p) => p.kind === 'intent');

    const realOutcomes = await this.loadOutcomes(outcomePairs.map((p) => p.real_claim_id));
    const twinOutcomes = await this.loadOutcomes(outcomePairs.map((p) => p.twin_claim_id));

    // detector_signal claims attributed to intents on each side. v1
    // filters by intent_claim_ref so each detector is bound to the
    // specific intent it fired on. Genome_drift / behavioral_drift
    // fires that aren't action-attributed are excluded; v2 could
    // broaden if false-negatives emerge.
    const realDetectorRows = await this.deps.passportClaimsRepo.findDetectorSignalsByIntentRefs(
      intentPairs.map((p) => p.real_claim_id),
    );
    const twinDetectorRows = await this.deps.passportClaimsRepo.findDetectorSignalsByIntentRefs(
      intentPairs.map((p) => p.twin_claim_id),
    );
    const realDetectorKeys = extractDetectorKeys(realDetectorRows);
    const twinDetectorKeys = extractDetectorKeys(twinDetectorRows);

    const { divergenceDimensions, diffSummary } = computeDivergence({
      realOutcomes,
      twinOutcomes,
      realDetectorKeys,
      twinDetectorKeys,
    });

    const payload: TwinDivergenceClaim = {
      type: 'twin_divergence',
      passport_jti: run.real_passport_jti,
      mission_ref: input.missionId,
      real_intent_outcomes: outcomePairs.map((p) => p.real_claim_id),
      twin_intent_outcomes: outcomePairs.map((p) => p.twin_claim_id),
      divergence_dimensions: divergenceDimensions,
      diff_summary: diffSummary,
      evaluated_at_ms: Date.now(),
    };

    try {
      const result = await this.deps.claimRegistry.registerClaim({
        operatorId: input.operatorId,
        passportJti: run.real_passport_jti,
        claimType: 'twin_divergence',
        payload,
      });
      const flipped = await this.deps.repo.markEvaluated({
        twinRunId: run.id,
        divergenceClaimId: result.claimId,
      });
      if (!flipped) {
        // Race: another caller flipped the CAS first. Re-read the
        // canonical divergence_claim_id from the row.
        const refreshed = await this.deps.repo.findByMissionId(input.missionId);
        return { divergenceClaimId: refreshed?.divergence_claim_id ?? result.claimId };
      }
      return { divergenceClaimId: result.claimId };
    } catch (err) {
      console.error('[TwinOrchestrationService.evaluateDivergence] failed:', safeErrorSummary(err));
      await this.deps.repo.markFailed(run.id).catch(() => {
        /* terminal failure idempotency — best-effort */
      });
      return { divergenceClaimId: null };
    }
  }

  /**
   * bounded-wait settling window for late twin outcomes.
   *
   * Polls `twin_runs.claim_pairs` until either:
   *   - count(intent pairs) === count(outcome pairs) (all twins landed), or
   *   - timeout elapses (best-effort partial eval, same as v1).
   *
   * Returns the latest `twin_runs` row read inside the poll loop so the
   * caller doesn't double-fetch. Returns null when the row disappeared
   * mid-poll (caller falls back to its earlier read).
   *
   * Exits early when the run flips to a terminal status (`evaluated` /
   * `failed`) during the wait — another caller raced through. The caller
   * is already inside `evaluateDivergence` which will re-read on exit.
   */
  private async waitForOutcomePairSettlement(
    missionId: string,
  ): Promise<{ claim_pairs: Array<{ real_claim_id: string; twin_claim_id: string; kind: 'intent' | 'outcome' }> } | null> {
    const timeoutMs = this.deps.twinSettleTimeoutMs ?? 10_000;
    const pollMs = this.deps.twinSettlePollMs ?? 200;
    const deadline = Date.now() + timeoutMs;

    while (true) {
      const row = await this.deps.repo.findByMissionId(missionId);
      if (!row) return null;
      if (row.status !== 'running') return { claim_pairs: row.claim_pairs };

      // Wait only when twins are PENDING — intent pair recorded by the
      // synchronous post-persist hook but the corresponding outcome
      // pair hasn't landed yet from the fire-and-forget twin path. When
      // intentCount <= outcomeCount there's nothing to wait for
      // (outcome > intent is an unusual fixture state, but proceeding
      // is correct: divergence math handles asymmetric pair sets).
      const intentCount = row.claim_pairs.filter((p) => p.kind === 'intent').length;
      const outcomeCount = row.claim_pairs.filter((p) => p.kind === 'outcome').length;
      if (intentCount <= outcomeCount) return { claim_pairs: row.claim_pairs };

      if (Date.now() >= deadline) {
        // Timeout: fall through to best-effort partial eval (same as v1).
        return { claim_pairs: row.claim_pairs };
      }

      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  }

  /**
   * load IntentOutcomeClaim payloads from
   * passport_claims by claim_id. Missing rows (e.g. revoked or never
   * persisted) are silently skipped — the divergence math treats
   * length mismatch as a mismatch, so a missing payload contributes
   * naturally to the output_shape signal.
   */
  private async loadOutcomes(claimIds: string[]): Promise<OutcomeEntry[]> {
    if (claimIds.length === 0) return [];
    const out: OutcomeEntry[] = [];
    for (const id of claimIds) {
      const row = await this.deps.passportClaimsRepo.findByClaimId(id);
      if (row && row.body_json) {
        out.push({ claim_id: id, outcome: row.body_json as IntentOutcomeClaim });
      }
    }
    return out;
  }
}

function extractDetectorKeys(
  rows: Array<{ body_json: unknown }>,
): string[] {
  const set = new Set<string>();
  for (const r of rows) {
    const body = r.body_json as { detector_key?: unknown };
    if (typeof body?.detector_key === 'string') set.add(body.detector_key);
  }
  return [...set].sort();
}
