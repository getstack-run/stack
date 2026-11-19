// What a Mission's caps do when one is reached, and the owner's review of a Mission a cap paused.
//
//   pause          the Mission is paused (one conditional update, so parallel calls pause it once), every action
//                  under it is refused with MISSION_PAUSED and nothing is revoked; the owner is told and reviews it.
//   refuse_action  only the action is refused (the gate's caller does that); nothing here changes.
//   end_mission    the Mission ends as completed_cap_breached, which ends its Passports.
//
// The owner's review of a paused Mission: `raise` sets the new limit of the cap that paused it and lets it go on,
// `continue` lets it go on with its limits as they are, `close` ends it. The decision is told to the agent the Mission
// was opened for (a `decision` wake in STACK's deployment, kind `mission_review`). Other Missions are not touched.
// A cap reached records no security event: the pause and the review are the record (audit rows).

import {
  ConflictError,
  InvalidRequestError,
  MissionNotPausedError,
  NotFoundError,
  ids,
  safeErrorSummary,
  type MissionCapBehavior,
  type MissionCapName,
} from '@stack/shared';
import { complete } from './lifecycle.js';
import { effectiveCapBehavior, rowToView, type MissionRow } from './helpers.js';
import type { MissionServiceDeps, MissionView, ReviewInput, ReviewResult } from './types.js';

/** The most a limit held in an integer column may be (a Postgres int4). */
const INT32_MAX = 2_147_483_647;

/** The id a review of one pause has: the Mission and when the pause began, so each pause has its own end. */
export function missionReviewId(missionId: string, pausedAt: Date): string {
  return `${missionId}@${pausedAt.getTime()}`;
}

/** The agent a Mission was opened for: the one it names, else the agent of its baseline Passport. */
async function agentOf(deps: MissionServiceDeps, row: Pick<MissionRow, 'assigned_agent_id' | 'passport_jti'>): Promise<string | null> {
  if (row.assigned_agent_id) return row.assigned_agent_id;
  if (!row.passport_jti || !deps.passportRepo) return null;
  try {
    return (await deps.passportRepo.findByJti(row.passport_jti))?.agent_id ?? null;
  } catch (error) {
    console.error('[MissionService] the Mission agent could not be read:', safeErrorSummary(error));
    return null;
  }
}

async function audit(
  deps: MissionServiceDeps,
  row: Pick<MissionRow, 'operator_id'>,
  agentId: string | null,
  action: string,
  outcome: 'success' | 'blocked',
  error?: { code: string; message: string },
): Promise<void> {
  if (!deps.audit) return;
  try {
    await deps.audit.write({
      ctx: { trace_id: ids.session(), span_id: ids.session(), operator_id: row.operator_id, agent_id: agentId ?? 'system', passport_jti: 'none' },
      layer: 'system',
      action,
      outcome,
      duration_ms: 0,
      ...(error ? { error } : {}),
    });
  } catch (failure) {
    console.error('[MissionService] audit write failed:', action, safeErrorSummary(failure));
  }
}

/**
 * A cap with behaviour `pause` was reached: pause the Mission for its owner's review. Returns true when this call paused
 * it (the owner is told once); false when it was already paused or has ended.
 */
export async function pauseForCap(
  deps: MissionServiceDeps,
  missionId: string,
  cap: MissionCapName,
  service: string | null = null,
): Promise<boolean> {
  const row = await deps.repo.pause(missionId, cap, cap === 'max_actions_per_service' ? service : null);
  if (!row) return false;
  const agentId = await agentOf(deps, row);
  await audit(deps, row, agentId, 'mission.paused', 'blocked', {
    code: 'MISSION_PAUSED',
    message: `paused by its ${cap} limit; waiting for the owner's review`,
  });
  if (deps.onPaused) {
    try {
      await deps.onPaused({ operatorId: row.operator_id, missionId, agentId, cap, service: row.paused_service ?? null });
    } catch (error) {
      console.error('[MissionService] the paused-Mission notice failed:', safeErrorSummary(error));
    }
  }
  return true;
}

/** A cap with behaviour `end_mission` was reached: the Mission ends as cap breached, and its Passports with it. */
export async function endForCap(deps: MissionServiceDeps, missionId: string, cap: MissionCapName): Promise<void> {
  try {
    await complete(deps, missionId, { capBreached: true });
  } catch (error) {
    // Revoked in the meantime: it has ended either way.
    if (error instanceof ConflictError) return;
    throw error;
  }
  const row = await deps.repo.findById(missionId);
  if (row) await audit(deps, row, await agentOf(deps, row), 'mission.ended_by_cap', 'blocked', { code: 'MISSION_CAP_REACHED', message: `ended by its ${cap} limit` });
}

/** Apply what a cap does when it is reached (pause or end the Mission; refuse_action changes nothing). */
export async function applyCapBehavior(
  deps: MissionServiceDeps,
  missionId: string,
  cap: MissionCapName,
  behavior: MissionCapBehavior,
  service: string | null = null,
): Promise<void> {
  if (behavior === 'pause') await pauseForCap(deps, missionId, cap, service);
  else if (behavior === 'end_mission') await endForCap(deps, missionId, cap);
}

/**
 * The Mission's money cap refused a spend at its counter (the budget ledger, where a spend reserves): apply the cap's
 * behaviour. Returns it, or null for a Mission that is unknown or has ended.
 */
export async function spendCapReached(deps: MissionServiceDeps, missionId: string): Promise<MissionCapBehavior | null> {
  const row = await deps.repo.findById(missionId);
  if (!row || row.completed_at || row.revoked_at) return null;
  const behavior = effectiveCapBehavior(row, 'coverage_cap_cents');
  await applyCapBehavior(deps, missionId, 'coverage_cap_cents', behavior);
  return behavior;
}

/** The column a raised limit is written to, with the most it may be. */
function raisedLimit(row: MissionRow, limit: number): Record<string, unknown> {
  const cap = row.paused_cap as MissionCapName | null;
  const check = (old: number | null, max: number) => {
    if (limit > max) throw new InvalidRequestError(`That limit is too large; the most it can be is ${max}.`);
    if (old !== null && limit <= old) throw new InvalidRequestError(`A raised limit must be above the old one (${old}).`);
  };
  switch (cap) {
    case 'max_actions':
      check(row.max_actions, INT32_MAX);
      return { max_actions: limit };
    case 'max_duration_seconds':
      check(row.max_duration_seconds, INT32_MAX);
      return { max_duration_seconds: limit };
    case 'max_concurrent_intents':
      check(row.max_concurrent_intents, INT32_MAX);
      return { max_concurrent_intents: limit };
    case 'coverage_cap_cents':
      check(row.coverage_cap_cents, Number.MAX_SAFE_INTEGER);
      return { coverage_cap_cents: limit };
    case 'max_dropoff_bytes':
      check(row.max_dropoff_bytes, Number.MAX_SAFE_INTEGER);
      return { max_dropoff_bytes: limit };
    case 'max_actions_per_service': {
      const service = row.paused_service;
      if (!service) throw new InvalidRequestError('This pause names no service, so its limit cannot be raised; continue or close it.');
      check(row.max_actions_per_service[service] ?? null, INT32_MAX);
      return { max_actions_per_service: { ...row.max_actions_per_service, [service]: limit } };
    }
    default:
      throw new InvalidRequestError('This pause names no limit to raise; continue or close it.');
  }
}

/** The owner's decision on a Mission a cap paused. */
export async function review(deps: MissionServiceDeps, missionId: string, input: ReviewInput): Promise<ReviewResult> {
  const row = await deps.repo.findById(missionId);
  if (!row || row.operator_id !== input.operatorId) throw new NotFoundError('mission', missionId);
  if (!row.paused_at || row.completed_at || row.revoked_at) throw new MissionNotPausedError(missionId);
  const reviewId = missionReviewId(missionId, row.paused_at);

  let result: ReviewResult['result'];
  if (input.decision === 'close') {
    await complete(deps, missionId, { capBreached: true });
    result = 'closed';
  } else {
    const raised = input.decision === 'raise'
      ? raisedLimit(row, input.limit ?? Number.NaN)
      : {};
    const resumed = await deps.repo.resume(missionId, input.operatorId, raised);
    // Another decision of the same review won: this one changes nothing.
    if (!resumed) throw new MissionNotPausedError(missionId);
    result = input.decision === 'raise' ? 'raised' : 'continued';
  }

  const latest = await deps.repo.findById(missionId);
  const view: MissionView = rowToView(latest ?? row);
  const agentId = await agentOf(deps, row);
  if (agentId && deps.onDecision) {
    try {
      await deps.onDecision({ operatorId: row.operator_id, agentId, kind: 'mission_review', itemId: reviewId, result });
    } catch (error) {
      console.error('[MissionService] telling the agent of the review failed:', safeErrorSummary(error));
    }
  }
  return { mission_id: missionId, decision: input.decision, result, mission: view };
}

/** The owner's pre-approval of the Mission's print-on-demand orders (null: none). */
export async function setMakingAllowance(
  deps: MissionServiceDeps,
  missionId: string,
  operatorId: string,
  cents: number | null,
): Promise<MissionView> {
  const row = await deps.repo.setMakingAllowance(missionId, operatorId, cents);
  if (!row) {
    const existing = await deps.repo.findById(missionId);
    if (!existing || existing.operator_id !== operatorId) throw new NotFoundError('mission', missionId);
    throw new ConflictError(`mission ${missionId} has ended; its allowance cannot change`);
  }
  return rowToView(row);
}
