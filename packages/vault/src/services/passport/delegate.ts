import {
  ids,
  NotFoundError,
  PassportExpiredError,
  PassportRevokedError,
  PassportBlockedError,
  DelegationAccountabilityError,
  ScopeEscalationError,
  ForbiddenError,
  FleetPassportBinding,
  PASSPORT_DEFAULT_TTL_SECONDS,
  PASSPORT_MAX_TTL_SECONDS,
  CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
  expandIntents,
  ANY_OF_BUDGET_MESSAGE,
  compareConstraintSets,
  withinAnyOfBudget,
  allowDataFromIsSubset,
  assertDelegationAllowed,
  type Constraint,
  type DelegatePassportInput,
} from '@stack/shared';
import type { PassportPayload } from '../../crypto/passport-signer.js';
import { linkAuthorityRefs, resolveDelegatedAuthorityRefs } from './authority-refs.js';
import { loadPassportLineage, requireActiveAgent, withActiveOperatorLock } from './context.js';
import { fleetDeadline, validateFleet } from './fleet.js';
import { preserveIdentityClaimsForDelegation } from './identity-requirements.js';
import { clampToMission, requireLiveMission } from './mission.js';
import type { PassportContext } from './types.js';
import { verifyPassportCore } from './verify.js';

/**
 * Delegate a narrower Passport from a parent Passport to a child agent.
 * `allowInternalRoot` and `fleetAuthorityBindingIds` are set only by the fleet
 * Mission coordinator, which holds the root token it just minted.
 */
export async function delegatePassport(
  ctx: PassportContext,
  operatorId: string,
  input: DelegatePassportInput,
  allowInternalRoot = false,
  fleetAuthorityBindingIds?: string[],
) {
  // Verify parent passport
  const parentClaims = (
    await verifyPassportCore(ctx, input.parent_passport_token, undefined, allowInternalRoot)
  ).claims;
  if (parentClaims.stk.operator_id !== operatorId) {
    throw new PassportRevokedError();
  }

  // Check delegation depth (tested in shared/utils/delegation.test.ts)
  assertDelegationAllowed(parentClaims.stk.delegation_depth);

  // The child inherits the parent's one Mission exactly, so the parent must
  // carry one and it must still be live. (Platform Passports carry none and
  // are refused below: they cannot be delegated.)
  await requireLiveMission(
    ctx,
    operatorId,
    parentClaims.stk.mission_ids,
    parentClaims.stk.platform_intent,
  );

  // Verify child agent exists and belongs to same operator
  const childAgent = await ctx.agentRepo.findById(input.child_agent_id);
  if (!childAgent) throw new NotFoundError('Agent', input.child_agent_id);
  if (childAgent.operator_id !== operatorId) throw new NotFoundError('Agent', input.child_agent_id);
  if (childAgent.status !== 'active') throw new PassportRevokedError();

  // Check if child agent is blocked
  if (childAgent.passport_blocked) {
    throw new PassportBlockedError(childAgent.id);
  }

  let fleet: FleetPassportBinding | undefined;
  if (parentClaims.stk.fleet) {
    fleet = FleetPassportBinding.parse(
      await ctx.fleetLookup().validateDelegation(parentClaims, childAgent.id),
    );
    const parentFleet = parentClaims.stk.fleet;
    if (
      fleet.internal_root ||
      fleet.policy_id !== parentFleet.policy_id ||
      fleet.policy_revision !== parentFleet.policy_revision ||
      fleet.mission_id !== parentFleet.mission_id
    ) {
      throw new PassportRevokedError();
    }
  } else {
    // Any agent of the account may hand its authority to any other, a fleet's members included: what it hands over is
    // its own, not the fleet's. (Authority a fleet issued stays inside that fleet: the branch above.)
    await ctx.fleetLookup().assertUnboundIssue(operatorId, childAgent.id, { delegated: true });
  }

  // Signal 4: delegation_without_intent. The parent did not declare intent_delegates.
  const parentRecord = await ctx.passportRepo.findByJti(parentClaims.jti);
  const parentAgent = await ctx.agentRepo.findById(parentClaims.stk.agent_id);
  // The two fallbacks in this block are deliberately asymmetric because
  // fail-closed points opposite ways on either side of the floor rule below.
  // An unknown PARENT reads 'enforced' (highest rank: undeclared delegation
  // throws, and no child can sit below it). An unknown CHILD reads 'standard'
  // (lowest rank: the downgrade rule fires rather than waves it through). Both
  // are unreachable while the column stays NOT NULL.
  const modeRank = { enforced: 3, logged: 2, standard: 1 } as const;
  const configuredParentMode =
    parentAgent?.accountability_mode === 'standard'
      ? 'standard'
      : parentAgent?.accountability_mode === 'logged'
        ? 'logged'
        : 'enforced';
  const signedParentMode = parentClaims.stk.accountability ?? configuredParentMode;
  const parentMode =
    modeRank[signedParentMode] > modeRank[configuredParentMode]
      ? signedParentMode
      : configuredParentMode;

  if (parentRecord && !parentRecord.intent_delegates) {
    if (parentMode === 'enforced') {
      await ctx.securityEvent().record({
        operatorId: operatorId,
        agentId: parentClaims.stk.agent_id,
        passportJti: parentClaims.jti,
        signalType: 'delegation_without_intent',
        severity: 'critical',
        message: `Agent delegated to ${input.child_agent_id} without declaring delegation intent`,
      });
      throw new ForbiddenError('Delegation not declared in passport intent');
    } else if (parentMode === 'logged') {
      await ctx.securityEvent().record({
        operatorId: operatorId,
        agentId: parentClaims.stk.agent_id,
        passportJti: parentClaims.jti,
        signalType: 'delegation_without_intent',
        severity: 'warning',
        message: `Agent delegated to ${input.child_agent_id} without declaring delegation intent`,
      });
    }
  }

  // Delegation floor rule: cannot reduce accountability
  const childMode = childAgent.accountability_mode ?? 'standard';
  if (modeRank[childMode as keyof typeof modeRank] < modeRank[parentMode as keyof typeof modeRank]) {
    // Signal 5: delegation_downgrade. Record before throwing.
    await ctx.securityEvent().record({
      operatorId: operatorId,
      agentId: parentClaims.stk.agent_id,
      passportJti: parentClaims.jti,
      signalType: 'delegation_downgrade',
      severity: 'critical',
      message: `Attempted delegation from ${parentMode} to ${childMode} agent ${input.child_agent_id}`,
    });
    throw new DelegationAccountabilityError(parentMode, childMode);
  }

  // Verify scope narrowing: child scopes must be a strict subset of the parent's.
  // Match by `connection_id` first (canonical). Fall back to credential_ref
  // / service_id only for tokens issued before connection_id was added.
  for (const reqScope of input.scopes) {
    if (
      fleet &&
      !parentClaims.stk.services.some(
        (service) => service.connection_id === reqScope.service_connection_id,
      )
    ) {
      throw new ScopeEscalationError();
    }
    const parentService = parentClaims.stk.services.find(
      (ps) =>
        ps.connection_id === reqScope.service_connection_id ||
        ps.credential_ref === reqScope.service_connection_id ||
        ps.service_id === reqScope.service_connection_id,
    );
    if (!parentService) throw new ScopeEscalationError();

    for (const scope of reqScope.scopes) {
      if (!parentService.scopes.includes(scope)) throw new ScopeEscalationError();
    }
  }

  const checkpointInterval = Math.min(
    parentClaims.stk.checkpoint_interval ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
    parentRecord?.checkpoint_interval_seconds ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
  );
  const ttl = Math.min(
    input.ttl_seconds ?? PASSPORT_DEFAULT_TTL_SECONDS,
    // Child TTL cannot exceed parent remaining TTL
    Math.ceil((parentClaims.exp * 1000 - Date.now()) / 1000),
    PASSPORT_MAX_TTL_SECONDS,
    childMode === 'enforced' ? checkpointInterval : PASSPORT_MAX_TTL_SECONDS,
  );

  const jti = ids.passport();

  // Preserve intent refs on the delegated passport. Child-declared
  // per-scope intents override parent-carried refs; if the child
  // doesn't declare any, we fall back to what the parent was
  // carrying so the named-intent trail survives through delegation.
  const aggregatedChildIntents = input.scopes.flatMap((s) => s.intents ?? []);
  const preservedIntentRefs =
    aggregatedChildIntents.length > 0
      ? aggregatedChildIntents
      : parentClaims.stk.intent_refs && parentClaims.stk.intent_refs.length > 0
        ? parentClaims.stk.intent_refs
        : undefined;

  // platform_intent NEVER carries to a child. A platform passport
  // authenticates the issuing platform-staff operator's own agent; delegating
  // it would let that agent grant platform privilege to any operator's child
  // agent, which is the obvious privilege-escalation path. The child gets a
  // regular passport, period. (Issuance also refuses platform_intent +
  // will_delegate combined, so this branch is belt-and-braces against legacy
  // or off-path tokens.)
  if (parentClaims.stk.platform_intent) {
    throw new ForbiddenError('platform passports cannot be delegated');
  }

  const delegatedAuthorityRefs = await resolveDelegatedAuthorityRefs(ctx, {
    operatorId,
    parentClaims,
    childAgent,
    allowInternalRoot,
    fleetAuthorityBindingIds,
    ttl,
  });

  const payload: PassportPayload = {
    operator_id: operatorId,
    agent_id: childAgent.id,
    agent_name: childAgent.name,
    services: parentClaims.stk.services
      .filter((ps) =>
        input.scopes.some(
          (is) =>
            is.service_connection_id === ps.connection_id ||
            is.service_connection_id === ps.service_id ||
            is.service_connection_id === ps.credential_ref,
        ),
      )
      .map((ps) => {
        const reqScope = input.scopes.find(
          (is) =>
            is.service_connection_id === ps.connection_id ||
            is.service_connection_id === ps.service_id ||
            is.service_connection_id === ps.credential_ref,
        )!;
        // Child's constraints = parent's constraints (always carried) +
        // child-specified tightening (additional narrowing). Concat
        // preserves parent's rules under AND semantics; child-added
        // constraints can only further restrict. `constraintsAreSubset`
        // validates the result really is a superset of parent, guarding
        // against future refactors that might otherwise drop baselines.
        const parentConstraints: Constraint[] = ps.constraints ?? [];
        const childIntents = reqScope.intents ? expandIntents(reqScope.intents) : [];
        const childTightening: Constraint[] = [...childIntents, ...(reqScope.constraints ?? [])];
        const mergedConstraints: Constraint[] = [...parentConstraints, ...childTightening];
        if (mergedConstraints.length > 32) {
          throw new ForbiddenError(
            `Too many constraints on delegated scope for ${ps.service_name}: ` +
              `${mergedConstraints.length} (max 32 per ServiceScope).`,
          );
        }
        if (!withinAnyOfBudget(mergedConstraints)) {
          throw new ForbiddenError(`${ANY_OF_BUDGET_MESSAGE} Delegated scope for ${ps.service_name} holds more.`);
        }
        const verdict = compareConstraintSets(mergedConstraints, parentConstraints);
        if (verdict === 'too_many_to_compare') {
          throw new ForbiddenError(
            `The rules on the delegated scope for ${ps.service_name} are too many to compare with its parent's. Delegate with fewer rules.`,
          );
        }
        if (verdict !== 'within') {
          // Should be unreachable since we concatenated parent in, but
          // belt-and-braces: any tampering with mergedConstraints that
          // drops a parent rule is a scope escalation.
          throw new ScopeEscalationError();
        }

        // ─── Data-flow narrowing (allow_data_from): FAIL CLOSED ─────────
        // `allow_data_from` GRANTS a cross-service movement, so on
        // delegation a child scope's set MUST be a subset of the parent
        // scope's for the same service. A child may only inherit or narrow
        // the flows the parent already had; it may NEVER gain a flow the
        // parent lacked (that would let a sub-agent exfiltrate along a path
        // its delegator could not). Widening is a scope escalation and is
        // rejected. Omitting it inherits the parent's set via `...ps`.
        const parentAllowDataFrom: string[] = ps.allow_data_from ?? [];
        let childAllowDataFrom: string[] | undefined;
        if (reqScope.allow_data_from !== undefined) {
          if (!allowDataFromIsSubset(reqScope.allow_data_from, parentAllowDataFrom)) {
            const widened = reqScope.allow_data_from.filter((f) => !parentAllowDataFrom.includes(f));
            throw new ScopeEscalationError({
              requested_invalid: widened,
              parent_scopes: parentAllowDataFrom,
            });
          }
          childAllowDataFrom = reqScope.allow_data_from;
        }

        return {
          ...ps,
          scopes: reqScope.scopes.filter((s) => ps.scopes.includes(s)),
          ...(mergedConstraints.length > 0 ? { constraints: mergedConstraints } : {}),
          // Explicit child declaration overrides the inherited `...ps` value
          // (including narrowing to none with `[]`); omission keeps parent's.
          ...(childAllowDataFrom !== undefined ? { allow_data_from: childAllowDataFrom } : {}),
        };
      }),
    // Identity claims flow down through delegation unchanged
    identity_claims: preserveIdentityClaimsForDelegation(parentClaims.stk.identity_claims),
    delegation_depth: parentClaims.stk.delegation_depth + 1,
    parent_passport_id: parentClaims.jti,
    session_id: parentClaims.stk.session_id,
    accountability: childMode as 'enforced' | 'logged' | 'standard',
    ...(parentClaims.stk.intent_summary ? { intent_summary: parentClaims.stk.intent_summary } : {}),
    ...(parentClaims.stk.intent_services ? { intent_services: parentClaims.stk.intent_services } : {}),
    ...(childMode === 'enforced' ? { checkpoint_interval: checkpointInterval } : {}),
    ...(preservedIntentRefs ? { intent_refs: preservedIntentRefs } : {}),
    ...(delegatedAuthorityRefs ? { authority_refs: delegatedAuthorityRefs } : {}),
    ...(parentClaims.stk.mission_ids ? { mission_ids: parentClaims.stk.mission_ids } : {}),
    ...(fleet ? { fleet } : {}),
    // The marker never comes off: a child of a command's Passport is still a command's Passport.
    ...(parentClaims.stk.workspace_command ? { workspace_command: parentClaims.stk.workspace_command } : {}),
  };

  const signed = await withActiveOperatorLock(ctx, operatorId, async (tx) => {
    const lineage = await loadPassportLineage(ctx, parentClaims, tx);
    await requireActiveAgent(ctx, operatorId, childAgent.id, tx);
    const now = Date.now();
    await validateFleet(ctx, parentClaims, allowInternalRoot);
    const fleetExpiry = fleet ? await fleetDeadline(ctx, operatorId, childAgent.id, fleet) : Infinity;
    if (!fleet) await ctx.fleetLookup().assertUnboundIssue(operatorId, childAgent.id, { delegated: true });
    const remainingTtl = clampToMission(
      Math.min(
        ttl,
        Math.floor((fleetExpiry - Date.now()) / 1000),
        Math.floor((parentClaims.exp * 1000 - now) / 1000),
        ...lineage.map((ancestor) => Math.floor((ancestor.expires_at.getTime() - now) / 1000)),
      ),
      await requireLiveMission(
        ctx,
        operatorId,
        parentClaims.stk.mission_ids,
        parentClaims.stk.platform_intent,
      ),
    );
    if (remainingTtl <= 0) throw new PassportExpiredError();
    const result = await ctx.signer.sign(jti, payload, remainingTtl);
    await ctx.passportRepo.create(
      {
        jti,
        operator_id: operatorId,
        agent_id: childAgent.id,
        session_id: parentClaims.stk.session_id,
        delegation_depth: parentClaims.stk.delegation_depth + 1,
        parent_passport_id: parentClaims.jti,
        expires_at: result.expires_at,
        // Inherit will-delegate flag from parent; otherwise the child can
        // never delegate further, capping the chain at 1 hop in practice
        // even though the spec allows up to PASSPORT_MAX_DELEGATION_DEPTH.
        // The depth cap (assertDelegationAllowed) is the real safety bound.
        intent_delegates: parentRecord?.intent_delegates ?? false,
        intent_summary: payload.intent_summary ?? null,
        intent_services: payload.intent_services ?? null,
        estimated_duration_seconds: parentRecord?.estimated_duration_seconds ?? null,
        ...(childMode === 'enforced' ? { checkpoint_interval_seconds: checkpointInterval } : {}),
        // Inherit identity claims from parent passport
        identity_claim_ids: parentClaims.stk.identity_claims?.length
          ? parentClaims.stk.identity_claims.map((c) => c.claim_id)
          : null,
        ...(preservedIntentRefs ? { intent_refs: preservedIntentRefs } : {}),
        ...(parentClaims.stk.mission_ids ? { mission_ids: parentClaims.stk.mission_ids } : {}),
      },
      tx,
    );
    if (delegatedAuthorityRefs) {
      await linkAuthorityRefs(
        ctx,
        { operatorId, passportJti: jti, refs: delegatedAuthorityRefs },
        tx,
      );
    }
    return result;
  });

  return signed;
}
