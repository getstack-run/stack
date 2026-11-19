import {
  ids,
  safeErrorSummary,
  NotFoundError,
  PassportExpiredError,
  PassportRevokedError,
  PassportBlockedError,
  AccountabilityRequiredError,
  ScopeEscalationError,
  ForbiddenError,
  PASSPORT_DEFAULT_TTL_SECONDS,
  PASSPORT_MAX_TTL_SECONDS,
  CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
  ANY_OF_BUDGET_MESSAGE,
  withinAnyOfBudget,
  expandIntents,
  allowDataFromIsSubset,
  resolveAllowDataFromGrant,
  type AuthorityReference,
  type Constraint,
  type FleetPassportBinding,
  type IssuePassportInput,
  type WorkspaceCommandBinding,
} from '@stack/shared';
import type { PassportPayload } from '../../crypto/passport-signer.js';
import {
  linkAuthorityRefs,
  resolveRequestedAuthorityRefs,
} from './authority-refs.js';
import { requireActiveAgent, withActiveOperatorLock } from './context.js';
import { fleetDeadline } from './fleet.js';
import { clampToMission, requireLiveMission } from './mission.js';
import type { PassportContext } from './types.js';

/** Issue a Passport for an agent that no fleet binds. */
export async function issuePassport(
  ctx: PassportContext,
  operatorId: string,
  input: IssuePassportInput,
) {
  await ctx.fleetLookup().assertUnboundIssue(operatorId, input.agent_id);
  return issuePassportInternal(ctx, operatorId, input);
}

export async function issuePassportInternal(
  ctx: PassportContext,
  operatorId: string,
  input: IssuePassportInput,
  fleet?: FleetPassportBinding,
  fleetSessionId?: string,
  workspaceCommand?: WorkspaceCommandBinding,
) {
  const agent = await ctx.agentRepo.findById(input.agent_id);
  if (!agent) throw new NotFoundError('Agent', input.agent_id);
  if (agent.operator_id !== operatorId) throw new NotFoundError('Agent', input.agent_id);
  if (agent.status !== 'active') throw new PassportRevokedError();

  // Check if agent is blocked from passport issuance
  if (agent.passport_blocked) {
    throw new PassportBlockedError(agent.id);
  }

  // Accountability: enforce intent requirement for enforced/logged modes.
  // The column is NOT NULL, so the fallback is unreachable today; it reads
  // 'enforced' because an agent whose mode we cannot determine is the last
  // one that should get the mode that skips the approval gate.
  const mode = agent.accountability_mode ?? 'enforced';
  if (
    fleet &&
    (mode !== 'enforced' ||
      input.mission_ids?.length !== 1 ||
      input.mission_ids[0] !== fleet.mission_id)
  ) {
    throw new ForbiddenError();
  }
  if ((mode === 'enforced' || mode === 'logged') && !input.intent) {
    throw new AccountabilityRequiredError('intent (required for enforced/logged agents)');
  }

  // ─── Platform-intent issuance gate ─────────────────────────────────
  // platform_intent turns this passport into inbound-auth for STACK's
  // own /v1/admin/* surface. Issuance is gated at TWO levels:
  //   1. issuer must be platform-staff (is_platform_staff = true).
  //   2. for 'monitor', issuer must be the dedicated system operator
  //      (op_stack_system); no other platform-staff operator can
  //      mint a monitor passport.
  // Defense-in-depth: the request middleware will RE-CHECK the staff
  // flag at verify time, so removing is_platform_staff invalidates
  // every existing platform passport even before TTL.
  const platformIntent = input.intent?.platform_intent;
  if (platformIntent) {
    // No co-existence with delegation. A platform passport that was
    // also will_delegate=true could be chained into a child without
    // platform_intent (which is the safe shape) but the JWT-level
    // claim itself never carries through to children. Refuse the
    // combination at issuance to keep the model uniform.
    if (input.intent?.will_delegate) {
      throw new ForbiddenError('platform_intent cannot be combined with will_delegate');
    }
    const issuer = await ctx.operatorRepo.findById(operatorId);
    if (!issuer || issuer.status !== 'active') {
      throw new PassportRevokedError();
    }
    if (!issuer.is_platform_staff) {
      throw new ForbiddenError('platform_intent requires is_platform_staff on the issuing operator');
    }
    if (platformIntent === 'monitor') {
      if (!ctx.systemOperatorId) {
        throw new ForbiddenError('platform_intent=monitor requires STACK_SYSTEM_OPERATOR_ID configured');
      }
      if (operatorId !== ctx.systemOperatorId) {
        throw new ForbiddenError('platform_intent=monitor restricted to the system operator');
      }
    }
  }

  // Resolve service grants for this agent (single JOIN, not an N+1 fan-out)
  const grantRows = await ctx.serviceRepo.findGrantsWithConnectionByAgent(agent.id);
  if (fleet) {
    if (
      !input.scopes ||
      new Set(input.scopes.map((scope) => scope.service_connection_id)).size !== input.scopes.length
    ) {
      throw new ScopeEscalationError();
    }
    for (const requested of input.scopes) {
      const granted = grantRows.find(
        ({ grant, connection }) =>
          grant.service_connection_id === requested.service_connection_id &&
          connection?.status === 'active' &&
          connection.operator_id === operatorId,
      );
      if (
        !granted ||
        requested.scopes.length === 0 ||
        requested.scopes.some(
          (scope) => !granted.grant.scopes.includes('*') && !granted.grant.scopes.includes(scope),
        )
      ) {
        throw new ScopeEscalationError();
      }
    }
  }
  const activeGrantedProviders = grantRows
    .filter(({ connection }) => connection?.status === 'active')
    .map(({ connection }) => connection!.provider);
  const serviceScopes = grantRows.map(({ grant, connection: conn }) => {
    if (!conn || conn.status !== 'active') return null;

    // Per-scope tightening from input (if the caller specified this
    // connection in input.scopes). Baseline constraints from the
    // grant always ride through; tightening only adds more.
    let tightening: Constraint[] = [];
    let validScopes = grant.scopes;
    let requestedAllowDataFrom: string[] | undefined;
    if (input.scopes) {
      const requested = input.scopes.find(
        (s) => s.service_connection_id === grant.service_connection_id,
      );
      if (!requested) return null;
      // Ensure requested scopes are subset of granted
      validScopes = requested.scopes.filter(
        (s) => grant.scopes.includes(s) || (fleet && grant.scopes.includes('*')),
      );
      if (validScopes.length === 0) return null;
      const intentExpanded = requested.intents ? expandIntents(requested.intents) : [];
      tightening = [...intentExpanded, ...(requested.constraints ?? [])];
      requestedAllowDataFrom = requested.allow_data_from;
    }

    const baseline: Constraint[] = grant.constraints ?? [];
    const mergedConstraints = [...baseline, ...tightening];
    if (!withinAnyOfBudget(mergedConstraints)) {
      throw new ForbiddenError(`${ANY_OF_BUDGET_MESSAGE} Passport scope for ${conn.provider} holds more.`);
    }
    if (mergedConstraints.length > 32) {
      throw new ForbiddenError(
        `Too many constraints on passport scope for ${conn.provider}: ` +
          `${mergedConstraints.length} (max 32 per ServiceScope).`,
      );
    }

    // ─── Data-flow declaration (allow_data_from) ────────────────────
    // Mirror of constraints, narrowing the OTHER way. The grant's
    // `allow_data_from` is the standing inbound-flow authority the
    // operator granted for this agent+service. An issued Passport may
    // inherit or narrow it; it may NEVER add a flow the grant lacked.
    // `*` exists only on the grant and becomes an exact snapshot of the
    // agent's currently active providers before the Passport is signed.
    //   - input declares  → assert ⊆ grant ceiling (fail closed on widen)
    //   - input omits it  → inherit the grant ceiling (as constraints do)
    const grantAllowDataFrom = resolveAllowDataFromGrant(
      grant.allow_data_from ?? [],
      activeGrantedProviders,
      conn.provider,
    );
    let effectiveAllowDataFrom: string[] | undefined;
    if (requestedAllowDataFrom !== undefined) {
      if (!allowDataFromIsSubset(requestedAllowDataFrom, grantAllowDataFrom)) {
        const widened = requestedAllowDataFrom.filter((f) => !grantAllowDataFrom.includes(f));
        throw new ForbiddenError(
          `Passport scope for ${conn.provider} declares allow_data_from flow(s) the ` +
            `grant does not permit: [${widened.join(', ')}]. Widen the grant's ` +
            `allow_data_from baseline first (issue can only narrow it, never add a ` +
            `flow). Grant permits: [${grantAllowDataFrom.join(', ') || 'none'}].`,
        );
      }
      effectiveAllowDataFrom = requestedAllowDataFrom;
    } else if (grantAllowDataFrom.length > 0) {
      effectiveAllowDataFrom = grantAllowDataFrom;
    }

    return {
      service_id: conn.service_id,
      service_name: conn.provider,
      scopes: validScopes,
      credential_ref: conn.credential_ref,
      connection_id: conn.id,
      ...(mergedConstraints.length > 0 ? { constraints: mergedConstraints } : {}),
      ...(effectiveAllowDataFrom && effectiveAllowDataFrom.length > 0
        ? { allow_data_from: effectiveAllowDataFrom }
        : {}),
    };
  });

  const filteredScopes = serviceScopes.filter((s): s is NonNullable<typeof s> => s !== null);

  // ─── Intent is tighten-only, never a grant substitute ──────────────
  // A passport's `intent.services` may only NARROW the granted set; it
  // can never authorize a service the agent was not granted. Enforce the
  // subset at issue time so a bad intent fails loudly HERE instead of
  // silently minting a passport that gets denied at first call. (The
  // credential lanes also enforce grant-authority at call time via
  // isServiceInScope; this is the issue-time half of the same rule and is
  // what makes revoke a real kill switch: a re-issued passport can't
  // declare its way back into a revoked service.)
  const grantedServiceNames = new Set(filteredScopes.map((s) => s.service_name));
  const ungrantedIntent = (input.intent?.services ?? []).filter((s) => !grantedServiceNames.has(s));
  if (ungrantedIntent.length > 0) {
    throw new ForbiddenError(
      `intent declares service(s) the agent is not granted: [${ungrantedIntent.join(', ')}]. ` +
        `Grant the connection first (intent can only narrow granted scope, not add to it). ` +
        `Granted: [${[...grantedServiceNames].join(', ') || 'none'}].`,
    );
  }

  // ─── Exactly one live Mission ──────────────────────────────────────
  // Every agent Passport is issued for exactly one Mission (the route
  // schema already says so; this is the service-level re-check). The
  // Mission must exist under this operator and be live. Platform
  // staff/monitor Passports are the single exemption and carry none.
  //
  // The Mission's required services must be covered by the agent's GRANTED
  // scope: a Passport cannot satisfy a Mission requirement with a service it
  // is not granted (intent is tighten-only, already asserted ⊆ granted above).
  // Runtime per-call enforcement happens at the agent admission check.
  const boundMission = await requireLiveMission(
    ctx,
    operatorId,
    input.mission_ids,
    platformIntent,
  );
  const validatedMissionIds = boundMission ? [boundMission.mission_id] : undefined;
  // A Mission opened for one agent binds only that agent's Passports.
  // Otherwise any key of the operator (a Connect grant, a workload) could
  // attach its agent to another agent's Mission, its caps and its record.
  // A fleet Mission is the exception by construction: it is assigned to the
  // worker, the root Passport is the fleet root's and is delegated straight
  // to that worker, and FleetService.liveMission has already proven the
  // worker's membership and the Mission's binding.
  if (!fleet && boundMission?.assigned_agent_id && boundMission.assigned_agent_id !== input.agent_id) {
    throw new ForbiddenError(`Mission ${boundMission.mission_id} is assigned to another agent`);
  }
  if (boundMission) {
    const missing = boundMission.intent_services.filter((s) => !grantedServiceNames.has(s));
    if (missing.length > 0) {
      throw new ForbiddenError(
        `Passport scope does not cover the Mission's services. ` +
          `Mission ${boundMission.mission_id} requires [${boundMission.intent_services.join(', ')}] ` +
          `but the Passport covers [${[...grantedServiceNames].join(', ')}]. ` +
          `Missing: [${missing.join(', ')}]`,
      );
    }
  }

  // Aggregate intent refs (name + params) for preservation on the
  // passport. Prefer an explicit top-level `intent.refs` list when the
  // caller supplies one; otherwise fall back to aggregating the
  // per-scope `intents` arrays. Either way we end up with the original
  // named intents the agent declared, which we preserve on the JWT
  // claims and the DB row so downstream telemetry (proxy
  // upstream_not_found) can identify the specific intent that led to
  // an upstream failure instead of only the service list.
  const aggregatedScopeIntents = (input.scopes ?? []).flatMap((s) => s.intents ?? []);
  const preservedIntentRefs =
    input.intent?.refs && input.intent.refs.length > 0
      ? input.intent.refs
      : aggregatedScopeIntents.length > 0
        ? aggregatedScopeIntents
        : undefined;

  // TTL: enforced mode uses checkpoint interval as TTL (short leash)
  const checkpointInterval =
    input.checkpoint_interval_seconds ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS;
  let ttl: number;
  if (mode === 'enforced') {
    ttl = Math.min(checkpointInterval, PASSPORT_MAX_TTL_SECONDS);
  } else {
    ttl = Math.min(input.ttl_seconds ?? PASSPORT_DEFAULT_TTL_SECONDS, PASSPORT_MAX_TTL_SECONDS);
  }

  const jti = ids.passport();
  if (fleetSessionId !== undefined && (!fleet || !/^ses_[A-Za-z0-9_-]+$/.test(fleetSessionId)))
    throw new ForbiddenError();
  const sessionId = fleetSessionId ?? ids.session();

  // Load operator's verified identity claims and build passport claim refs.
  //
  // Precedence on which claims to embed:
  //   1. input.identity_claim_ids: explicit per-call override (SDK caller
  //      is specific about which claims this passport should carry).
  //   2. agent.identity_claim_ids: per-agent default stored on the agent
  //      row, set via the dashboard settings tab. Used when the operator
  //      is in identity_claim_inheritance='opt_in' and has assigned a
  //      specific claim set to this agent.
  //   3. undefined: falls through to buildPassportClaimRefs's operator
  //      inheritance rule: 'auto' → all valid claims, 'opt_in' → none.
  //
  // The dashboard claim picker writes (2); the SDK can still override per
  // call via (1). An explicit empty array means "no claims". Only an
  // omitted value reaches the operator inheritance rule.
  const effectiveClaimIds = input.identity_claim_ids ?? agent.identity_claim_ids ?? undefined;
  const identityClaims: PassportPayload['identity_claims'] =
    await ctx.identityVerification.buildPassportClaimRefs(operatorId, effectiveClaimIds);

  let authorityRefs: AuthorityReference[] | undefined;
  if (input.authority_binding_ids && input.authority_binding_ids.length > 0) {
    authorityRefs = await resolveRequestedAuthorityRefs(ctx, {
      operatorId,
      agentId: agent.id,
      bindingIds: input.authority_binding_ids,
      ...(validatedMissionIds ? { missionIds: validatedMissionIds } : {}),
    });
  }

  const payload: PassportPayload = {
    operator_id: operatorId,
    agent_id: agent.id,
    agent_name: agent.name,
    services: filteredScopes,
    identity_claims: identityClaims,
    delegation_depth: 0,
    session_id: sessionId,
    // Accountability claims in JWT
    accountability: mode as 'enforced' | 'logged' | 'standard',
    ...(input.intent
      ? {
          intent_summary: input.intent.summary,
          intent_services: input.intent.services,
        }
      : {}),
    ...(preservedIntentRefs ? { intent_refs: preservedIntentRefs } : {}),
    ...(mode === 'enforced' ? { checkpoint_interval: checkpointInterval } : {}),
    // platform-intent claim (gated above).
    ...(platformIntent ? { platform_intent: platformIntent } : {}),
    // mission binding (validated above).
    ...(validatedMissionIds ? { mission_ids: validatedMissionIds } : {}),
    ...(authorityRefs ? { authority_refs: authorityRefs } : {}),
    ...(fleet ? { fleet } : {}),
    ...(workspaceCommand ? { workspace_command: workspaceCommand } : {}),
  };

  const signed = await withActiveOperatorLock(ctx, operatorId, async (tx, operator) => {
    await requireActiveAgent(ctx, operatorId, agent.id, tx);
    if (fleet) {
      ttl = Math.min(
        ttl,
        Math.floor(((await fleetDeadline(ctx, operatorId, agent.id, fleet)) - Date.now()) / 1000),
      );
      if (ttl <= 0) throw new PassportExpiredError();
    } else {
      await ctx.fleetLookup().assertUnboundIssue(operatorId, agent.id);
    }
    if (platformIntent && !operator.is_platform_staff) {
      throw new ForbiddenError('platform_intent requires is_platform_staff on the issuing operator');
    }
    // A Mission ends under this same operator lock, so re-reading it here
    // closes the race with a concurrent complete/revoke.
    ttl = clampToMission(
      ttl,
      await requireLiveMission(ctx, operatorId, input.mission_ids, platformIntent),
    );
    const result = await ctx.signer.sign(jti, payload, ttl);

    // Store the record before the lifecycle lock can be released.
    await ctx.passportRepo.create(
      {
        jti,
        operator_id: operatorId,
        agent_id: agent.id,
        session_id: sessionId,
        delegation_depth: 0,
        parent_passport_id: null,
        expires_at: result.expires_at,
        // Track which identity claims this passport carries (for smart revoke)
        identity_claim_ids: identityClaims.length > 0 ? identityClaims.map((c) => c.claim_id) : null,
        // Accountability fields
        ...(input.intent
          ? {
              intent_summary: input.intent.summary,
              intent_services: input.intent.services,
              intent_delegates: input.intent.will_delegate ?? false,
              estimated_duration_seconds: input.intent.estimated_duration_seconds ?? null,
            }
          : {}),
        ...(preservedIntentRefs ? { intent_refs: preservedIntentRefs } : {}),
        ...(mode === 'enforced' ? { checkpoint_interval_seconds: checkpointInterval } : {}),
        // denormalized mission_ids.
        ...(validatedMissionIds ? { mission_ids: validatedMissionIds } : {}),
      },
      tx,
    );
    if (authorityRefs) {
      await linkAuthorityRefs(ctx, { operatorId, passportJti: jti, refs: authorityRefs }, tx);
    }
    return result;
  });

  // ─── A scope with no policy is never silently wide open ────────────
  // A ServiceScope with no constraints grants the WHOLE service: the proxy
  // skips its constraint block by an explicit early-out, so any method, any
  // path and any body on that provider's hosts is permitted. That is a legal
  // thing for an operator to grant, and sometimes the intended one, so this
  // warns rather than refuses. What it stops being is silent.
  //
  // Recorded after the row exists so the event carries the passport's jti and
  // the signed detector_signal claim lands in the same chain the passport is
  // judged by. Deduped per (agent, service set) for an hour: a 15-minute TTL
  // means an agent re-issues four times an hour, and four identical warnings
  // teach an operator to ignore the fifth.
  //
  // Best-effort by design. A passport that was correctly issued must not fail
  // because the warning about it could not be written.
  const unconstrained = filteredScopes
    .filter((s) => !s.constraints || s.constraints.length === 0)
    .map((s) => s.service_name)
    .sort();
  if (unconstrained.length > 0) {
    const securityEvent = ctx.securityEvent();
    try {
      await securityEvent.record({
        operatorId,
        agentId: agent.id,
        passportJti: jti,
        signalType: 'unconstrained_scope',
        severity: 'warning',
        message:
          `Passport issued with no constraints on ${unconstrained.length} ` +
          `service scope(s): [${unconstrained.join(', ')}]. The agent may make ` +
          `any call to those providers. Declare intents or constraints to narrow it.`,
        metadata: { services: unconstrained, accountability_mode: mode },
        missionIds: validatedMissionIds,
        dedupKey: `unconstrained_scope:${agent.id}:${unconstrained.join(',')}`,
        dedupWindowSeconds: 3600,
      });
    } catch (err) {
      console.error('unconstrained_scope warning emission failed:', safeErrorSummary(err));
    }
  }

  return signed;
}
