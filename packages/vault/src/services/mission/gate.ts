// The proxy gate and cap usage. checkGate is the single admission check for every agent action:
// lifecycle, scope narrowing, then each declared cap, with the cap behaviour for the caller to
// dispatch on. sumCoverageSpend is shared by the gate and the dashboard usage read so the bar and
// the enforcer cannot disagree.

import { ForbiddenError, MISSION_ACTIONS_SCOPE, missionServiceActionsScope, startOfDayIn } from '@stack/shared';
import { findById } from './reads.js';
import { type MissionServiceDeps, type GateVerdict } from './types.js';
import { effectiveCapBehavior } from './helpers.js';
import { NO_MISSION_SPEND } from '../spend/spend-ledger.js';

/**
 * proxy gate check.
 *
 * Called only through beginAgentRuntime (apps/api/src/lib/agent-runtime.ts),
 * the single admission check for every agent action. Returns a verdict the
 * caller dispatches on:
 *   - `{ allowed: true, mission }`              → proceed
 *   - `{ allowed: false, reason: 'mission_not_found' | 'mission_revoked' | 'mission_completed' | 'mission_scope_mismatch' }` → hard deny (no cap path)
 *   - `{ allowed: false, reason: 'mission_paused', mission }` → a cap paused it; refused until the owner's review
 *   - `{ allowed: false, reason: 'cap_<name>', capBehavior, mission }` → caller dispatches per cap_behavior
 *
 * Cap behavior dispatch (caller's responsibility, not this method's). A cap reached records no security event: the
 * owner's review of a paused Mission is the record.
 *   - `pause`         → pauseForCap(missionId, cap): the Mission is paused, every action under it refused
 *                       (MISSION_PAUSED), nothing revoked, the owner's review waits
 *   - `refuse_action` → this action is refused (with its intent_denial); the Mission goes on
 *   - `end_mission`   → endForCap(missionId, cap): the Mission ends as completed_cap_breached, and its Passports
 *
 * Cap coverage today:
 *   ✓ max_actions, max_actions_per_service — where the deployment has a counter, reserved
 *     when the gate admits the action, per Mission, in one conditional update
 *     (`MissionActionCounter`), so parallel calls pass at most the limit and every agent
 *     under the Mission shares it; otherwise the Mission's intent claims, queried via
 *     passport_claims body_json JSONB index
 *   ✓ max_concurrent_intents — queried via passport_claims body_json JSONB index
 *   ✓ max_duration_seconds — computed from mission.started_at
 *   ✓ coverage_cap_cents — gross sum of the wallet debits and
 *     llm_usage recorded under the mission; skipped for an agent
 *     account's Mission, whose budget ledger reserves every spend
 *     atomically before it starts
 *   ✗ max_dropoff_bytes — not enforced yet
 *
 * Each cap check incurs ≤1 SQL round-trip; the gate runs on the
 * proxy hot path so any individual passport is at most ~50 ms
 * overhead per call. A Passport without exactly one Mission never
 * reaches this method: beginAgentRuntime refuses it first.
 */
export async function checkGate(deps: MissionServiceDeps, input: {
  missionId: string;
  requestedService: string;
  /** Internal fleet producers use the atomic admission ledger for quantities. */
  accounting?: 'fleet';
  /**
   * STACK-internal operations (drop-offs, A2A, skills, authority) are not
   * services a Mission can list: intent_services is validated as a subset of
   * the Passport's connected services. Skip scope narrowing for them; the
   * lifecycle, duration and every cap still apply.
   */
  internal?: boolean;
  /**
   * The action executes an approved intent whose intent_claim is already
   * counted under this Mission. Discount it once, so the approved action
   * at the cap is not refused for the count its own submission added.
   */
  alreadyCounted?: { target: string };
  /** Optional estimated cost of the pending action, in cents. Added to the
   * spend already recorded under the mission before the coverage_cap_cents check. */
  estimatedWalletCents?: number;
}): Promise<GateVerdict> {
  const mission = await findById(deps, input.missionId);
  if (!mission) {
    return {
      allowed: false,
      reason: 'mission_not_found',
      message: `mission ${input.missionId} not found`,
    };
  }

  // Lifecycle gates — revoked / completed missions deny all new actions.
  if (mission.revoked_at) {
    return {
      allowed: false,
      reason: 'mission_revoked',
      message: `mission ${input.missionId} is revoked (reason: ${mission.revoked_reason})`,
      mission,
    };
  }
  if (mission.completed_at) {
    return {
      allowed: false,
      reason: 'mission_completed',
      message: `mission ${input.missionId} is completed (terminal_state: ${mission.terminal_state})`,
      mission,
    };
  }

  // The Mission's end: refused, whatever its caps do. The expiry sweep completes it.
  if (mission.expires_at.getTime() <= Date.now()) {
    return {
      allowed: false,
      reason: 'cap_max_duration_seconds',
      message: 'Forbidden',
      mission,
      capBehavior: 'refuse_action',
    };
  }

  // A cap paused the Mission: everything under it waits for the owner's review.
  if (mission.paused_at) {
    return {
      allowed: false,
      reason: 'mission_paused',
      message: `mission ${input.missionId} is paused for its owner's review (cap: ${mission.paused_cap ?? 'unknown'})`,
      mission,
    };
  }

  // Scope narrowing — when mission.intent_services is non-empty, the
  // requested service must be in the list. Empty intent_services = no
  // narrowing (mission inherits passport scope).
  if (
    !input.internal &&
    mission.intent_services.length > 0 &&
    !mission.intent_services.includes(input.requestedService)
  ) {
    return {
      allowed: false,
      reason: 'mission_scope_mismatch',
      message: `service ${input.requestedService} not in mission scope (allowed: [${mission.intent_services.join(', ')}])`,
      mission,
    };
  }

  // max_duration_seconds — pure clock comparison, no DB hit.
  if (mission.max_duration_seconds !== null) {
    const elapsedSeconds = Math.floor((Date.now() - mission.started_at.getTime()) / 1000);
    if (elapsedSeconds >= mission.max_duration_seconds) {
      return {
        allowed: false,
        reason: 'cap_max_duration_seconds',
        message: `mission duration ${elapsedSeconds}s exceeds cap ${mission.max_duration_seconds}s`,
        mission,
        capBehavior: effectiveCapBehavior(mission, 'max_duration_seconds'),
      };
    }
  }

  if (input.accounting === 'fleet') {
    if (!mission.authorization_digest) throw new ForbiddenError();
    return { allowed: true, mission };
  }

  // Where the deployment has a counter, the Mission's action limits are reserved atomically as the last step below,
  // when every other check has passed; without one the Mission's intent claims are counted here.
  const countsAtomically = Boolean(deps.missionActions);

  // max_actions — count of intent_claim emissions under this mission.
  // The current intent will add 1; check if cap is already exhausted.
  if (!countsAtomically && mission.max_actions !== null) {
    const used =
      (await deps.repo.countIntentsByMissionId(mission.mission_id)) -
      (input.alreadyCounted ? 1 : 0);
    if (used >= mission.max_actions) {
      return {
        allowed: false,
        reason: 'cap_max_actions',
        message: `mission actions used ${used} of cap ${mission.max_actions}`,
        mission,
        capBehavior: effectiveCapBehavior(mission, 'max_actions'),
      };
    }
  }

  // max_actions_per_service — same shape, scoped to the requested service.
  const perServiceCap = mission.max_actions_per_service[input.requestedService];
  if (!countsAtomically && perServiceCap !== undefined && perServiceCap !== null) {
    const groupedCounts = await deps.repo.countIntentsByMissionIdGroupedByService(
      mission.mission_id,
    );
    const usedForService =
      (groupedCounts[input.requestedService] ?? 0) -
      (input.alreadyCounted?.target === input.requestedService ? 1 : 0);
    if (usedForService >= perServiceCap) {
      return {
        allowed: false,
        reason: 'cap_max_actions_per_service',
        message: `mission actions for ${input.requestedService} used ${usedForService} of cap ${perServiceCap}`,
        mission,
        capBehavior: effectiveCapBehavior(mission, 'max_actions_per_service'),
        capService: input.requestedService,
      };
    }
  }

  // max_concurrent_intents — in-flight count (intent_claim without
  // paired intent_outcome). Approximate but adequate for runaway-loop
  // detection (the cap's purpose).
  if (mission.max_concurrent_intents !== null) {
    const inflight =
      (await deps.repo.countInflightIntentsByMissionId(mission.mission_id)) -
      (input.alreadyCounted ? 1 : 0);
    if (inflight >= mission.max_concurrent_intents) {
      return {
        allowed: false,
        reason: 'cap_max_concurrent_intents',
        message: `mission has ${inflight} in-flight intents at cap ${mission.max_concurrent_intents}`,
        mission,
        capBehavior: effectiveCapBehavior(mission, 'max_concurrent_intents'),
      };
    }
  }

  // coverage_cap_cents. Sum:
  //   (a) the credit spent under this mission (`MissionSpendSource`; none on an install),
  //   (b) past LLM cost attributed to this mission (llm_usage.mission_id),
  //   (c) the call's estimated contribution.
  // The LLM cost counted is the gross, provider cost plus any fee on top, because
  // the operator reasons about their full LLM bill under the mission. Where a
  // deployment's credit spend already contains a fee row, that fee is counted
  // twice on purpose in v1: the over-count is conservative (the operator hits
  // the cap slightly sooner than the gross would suggest) and the credit spend
  // also contains non-LLM debits which legitimately count.
  // Default behavior is auto_revoke (money exhaustion = adversarial
  // shape per the cap_behavior table).
  //
  // A Mission whose spend a budget ledger governs is skipped: that ledger is
  // the authority for its spend. It reserves before every spend under one
  // conditional UPDATE, so it neither races like this check-then-act sum
  // nor counts a fee twice.
  if (
    mission.coverage_cap_cents !== null &&
    !(await (deps.missionSpend ?? NO_MISSION_SPEND).governedByAccountBudget(mission.mission_id))
  ) {
    const {
      walletCents: walletUsedCents,
      llmGrossCents,
      usedCents,
    } = await sumCoverageSpend(deps, mission.operator_id, mission.mission_id, undefined, coverageWindowStart(mission));
    const projected = usedCents + (input.estimatedWalletCents ?? 0);
    if (projected >= mission.coverage_cap_cents) {
      return {
        allowed: false,
        reason: 'cap_coverage_cap_cents',
        message: `mission spend ${usedCents}¢ (wallet ${walletUsedCents}¢ + llm gross ${llmGrossCents}¢) + projected ${input.estimatedWalletCents ?? 0}¢ exceeds cap ${mission.coverage_cap_cents}¢`,
        mission,
        capBehavior: effectiveCapBehavior(mission, 'coverage_cap_cents'),
      };
    }
  }

  // max_dropoff_bytes. Sum encrypted-envelope byte sizes
  // of drop-offs deposited under this mission. Proxy gate doesn't
  // know per-call what byte sum a future drop-off will add, so this
  // check is conservative: deny when the historical total alone is
  // at-or-over the cap. The dropoff service's own deposit path also
  // re-checks before persisting (defense in depth).
  if (mission.max_dropoff_bytes !== null) {
    const usedBytes = await deps.repo.sumDropoffBytesByMission(mission.mission_id);
    if (usedBytes >= mission.max_dropoff_bytes) {
      return {
        allowed: false,
        reason: 'cap_max_dropoff_bytes',
        message: `mission dropoff bytes ${usedBytes} exceeds cap ${mission.max_dropoff_bytes}`,
        mission,
        capBehavior: effectiveCapBehavior(mission, 'max_dropoff_bytes'),
      };
    }
  }

  // The Mission's action limits: this call is reserved in one conditional update per counter, so however many calls
  // arrive together the limits are never passed. Last, so a call another check refused is not counted. The caller gives
  // the reservation back when the call is refused or fails, and commits it when the call is dispatched or ends well. An
  // approved intent being run was counted when it was submitted.
  if (countsAtomically && deps.missionActions) {
    const rules: Array<{ cap: 'max_actions' | 'max_actions_per_service'; limit: number; scope: string }> = [];
    if (mission.max_actions !== null && !input.alreadyCounted) {
      rules.push({ cap: 'max_actions', limit: mission.max_actions, scope: MISSION_ACTIONS_SCOPE });
    }
    if (perServiceCap !== undefined && perServiceCap !== null && input.alreadyCounted?.target !== input.requestedService) {
      rules.push({ cap: 'max_actions_per_service', limit: perServiceCap, scope: missionServiceActionsScope(input.requestedService) });
    }
    if (rules.length > 0) {
      const reserved = await deps.missionActions.reserve({ missionId: mission.mission_id, rules });
      if (!reserved.ok) {
        return reserved.cap === 'max_actions'
          ? {
              allowed: false,
              reason: 'cap_max_actions',
              message: `mission has used its ${reserved.limit} actions`,
              mission,
              capBehavior: effectiveCapBehavior(mission, 'max_actions'),
            }
          : {
              allowed: false,
              reason: 'cap_max_actions_per_service',
              message: `mission has used its ${reserved.limit} actions for ${input.requestedService}`,
              mission,
              capBehavior: effectiveCapBehavior(mission, 'max_actions_per_service'),
              capService: input.requestedService,
            };
      }
      return { allowed: true, mission, reservation: reserved.reservation };
    }
  }

  return { allowed: true, mission };
}

/**
 * current cap usage for a mission.
 *
 * Composes the six cap-counting helpers from MissionRepository
 * (intent counts, in-flight count, wallet debits, dropoff bytes)
 * into a single read for the dashboard detail page's live
 * current-vs-limit bars. All counts are best-effort point-in-time
 * snapshots; the proxy gate's enforcement still re-counts on every
 * action for correctness, this is just a UI read.
 *
 * Returns nulls for caps that aren't declared on the mission, so the
 * UI can render "—" (unbounded) cleanly. Per-service counts are
 * returned in full so the UI can drill into individual services.
 */
export async function getCapUsage(deps: MissionServiceDeps, missionId: string): Promise<{
  actions: { used: number; limit: number | null };
  actions_per_service: { used: Record<string, number>; limits: Record<string, number> };
  concurrent_intents: { used: number; limit: number | null };
  duration_seconds: { used: number; limit: number | null };
  /** For a money cap of one day, what today has spent in the Mission's time zone. */
  coverage_cents: { used: number; limit: number | null; period: 'mission' | 'day' };
  dropoff_bytes: { used: number; limit: number | null };
} | null> {
  const mission = await findById(deps, missionId);
  if (!mission) return null;
  const [claimActions, claimActionsByService, inflightUsed, coverageSpend, dropoffUsed] =
    await Promise.all([
      deps.repo.countIntentsByMissionId(missionId),
      deps.repo.countIntentsByMissionIdGroupedByService(missionId),
      deps.repo.countInflightIntentsByMissionId(missionId),
      sumCoverageSpend(deps, mission.operator_id, missionId, undefined, coverageWindowStart(mission)),
      deps.repo.sumDropoffBytesByMission(missionId),
    ]);
  // An agent account's actions are counted when the gate admits them (see checkGate): the bar reads the
  // counters the gate enforces, so the two cannot disagree. A Mission nothing has been counted for yet reads its claims.
  const services = Object.keys(mission.max_actions_per_service);
  const counted = deps.missionActions
    ? await deps.missionActions.counts({
        missionId,
        scopes: [MISSION_ACTIONS_SCOPE, ...services.map(missionServiceActionsScope)],
      })
    : {};
  const actionsUsed = counted[MISSION_ACTIONS_SCOPE] ?? claimActions;
  const actionsByService: Record<string, number> = { ...claimActionsByService };
  for (const service of services) {
    const used = counted[missionServiceActionsScope(service)];
    if (used !== undefined) actionsByService[service] = used;
  }
  const endedAt = Math.min(
    Date.now(),
    mission.expires_at.getTime(),
    mission.completed_at?.getTime() ?? Infinity,
    mission.revoked_at?.getTime() ?? Infinity,
  );
  const durationSecondsUsed = Math.max(
    0,
    Math.floor((endedAt - mission.started_at.getTime()) / 1000),
  );
  return {
    actions: { used: actionsUsed, limit: mission.max_actions },
    actions_per_service: {
      used: actionsByService,
      limits: mission.max_actions_per_service,
    },
    concurrent_intents: { used: inflightUsed, limit: mission.max_concurrent_intents },
    duration_seconds: { used: durationSecondsUsed, limit: mission.max_duration_seconds },
    coverage_cents: { used: coverageSpend.usedCents, limit: mission.coverage_cap_cents, period: mission.coverage_cap_period },
    dropoff_bytes: { used: dropoffUsed, limit: mission.max_dropoff_bytes },
  };
}

/**
 * Where the money cap starts counting: the Mission's start for a cap of the whole Mission, and the last midnight in the
 * Mission's time zone for a cap of one day.
 */
export function coverageWindowStart(
  mission: { coverage_cap_period: 'mission' | 'day'; cap_time_zone: string },
  now: Date = new Date(),
): Date | undefined {
  return mission.coverage_cap_period === 'day' ? startOfDayIn(now, mission.cap_time_zone) : undefined;
}

/**
 * Spend counted against coverage_cap_cents: wallet debits plus LLM gross
 * cost. The proxy gate and getCapUsage both read this, so the dashboard
 * bar and the enforcer cannot disagree.
 */
export async function sumCoverageSpend(
  deps: MissionServiceDeps,
  operatorId: string,
  missionId: string,
  /** Count only spend recorded before this instant. */
  before?: Date,
  /** Count only spend recorded at or after this instant (a money cap of one day). */
  since?: Date,
): Promise<{ walletCents: number; llmGrossCents: number; usedCents: number }> {
  const llm = deps.llmUsageRepo;
  const credit = deps.missionSpend ?? NO_MISSION_SPEND;
  // Only the bounds that are set are passed on, so a source written before them reads exactly what it always read.
  const bounds: [Date?, Date?] = since ? [before, since] : before ? [before] : [];
  const [walletCents, llmGrossCents] = await Promise.all([
    credit.spentCents(operatorId, missionId, ...bounds),
    llm ? llm.sumTotalCostByMission(operatorId, missionId, ...bounds) : 0,
  ]);
  return { walletCents, llmGrossCents, usedCents: walletCents + llmGrossCents };
}
