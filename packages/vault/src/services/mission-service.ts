// MissionService.
//
// Lifecycle owner for missions — the bounded unit of agent work that
// sits between passport (the agent's authority) and intent (the
// individual call). A mission seals a declared scope subset of the
// passport's services, hard resource caps, an expected output shape,
// and a counterparty allowlist; the proxy gate enforces those caps
// per-action.
//
// Three lifecycle transitions, each emits a NEW signed mission claim
// (claims are immutable; updates are new claims sharing the same
// mission_id):
//
//   1. open()     — signs mission_open claim, inserts denormalized row
//   2. complete() — signs claim with terminal_state set, updates row,
//                   revokes every Passport bound to the mission
//   3. revoke()   — signs claim with revoke_reason + terminal_state,
//                   updates row, revokes every Passport bound to it
//
// The `missions` row's claim_id always points to the LATEST mission
// claim for the mission_id. To find the open claim (the immutable
// cryptographic anchor that intents reference via mission_ref), query
// passport_claims WHERE type='mission' AND body_json->>'mission_id'=?
// ORDER BY issued_at_ms ASC LIMIT 1.
//
// a Mission's end kills its Passports. The Passport revoke is
// injected as `passportRevoker` (passport-service.ts
// createMissionPassportRevoker) and runs inside the transaction that
// records the terminal state, so the substrate stays testable without a
// PassportService dep and a failed revoke rolls the transition back.
//
// The class holds the dependencies and delegates each method to the module
// that owns it under `./mission/`:
//
//   - lifecycle.ts          open, complete, revoke, autoRevokeForCapBreach
//   - lifecycle-effects.ts  Passport revoke plan, revocation publish, behavioural diff, twin evaluation
//   - gate.ts               checkGate, getCapUsage, the shared coverage spend sum
//   - caps.ts               what a reached cap does (pause, end), the owner's review of a paused Mission, the making allowance
//   - reads.ts              findById, readOutput, listByOperator, listPassports
//   - helpers.ts            limits, cap behaviour table, twin policy, row to view
//   - types.ts              dependencies, views, inputs and verdicts

import { ConflictError, NotFoundError, mergeRecipientPins, readRecipientPins, type RecipientPin } from '@stack/shared';
import * as caps from './mission/caps.js';
import * as gate from './mission/gate.js';
import * as lifecycle from './mission/lifecycle.js';
import * as reads from './mission/reads.js';
import { MissionRepository, type MissionTransaction } from '../repositories/mission-repo.js';
import type { MissionCapBehavior, MissionCapName } from '@stack/shared';
import type {
  CompleteInput,
  ExtendInput,
  MissionServiceDeps,
  OpenInput,
  ReviewInput,
  RevokeInput,
} from './mission/types.js';

export {
  DEFAULT_CAP_BEHAVIOR,
  effectiveCapBehavior,
  resolveTwinPolicy,
  type TwinPolicyEnum,
} from './mission/helpers.js';
export { MissionRecipientPinReader, type MissionRecipients } from './mission/recipient-pins.js';
export { missionReviewId } from './mission/caps.js';
export { coverageWindowStart } from './mission/gate.js';
export { PassportLineageReader, type PassportLineageRow, type PassportLineageSource } from './mission/passport-lineage.js';
export type {
  CompleteInput,
  CompleteResult,
  ExtendInput,
  ExtendResult,
  GateReason,
  GateVerdict,
  MissionListItem,
  MissionListResult,
  MissionAuditInput,
  MissionPausedEvent,
  ReviewInput,
  ReviewResult,
  MissionActionCounter,
  MissionActionReservation,
  MissionPassportRevoker,
  MissionServiceDeps,
  MissionView,
  OpenInput,
  OpenResult,
  RevokeInput,
  RevokeResult,
} from './mission/types.js';

export class MissionService {
  constructor(private deps: MissionServiceDeps) {}

  /**
   * The same service with its Mission rows read and written inside the
   * caller's transaction, so a Mission can be opened or ended atomically with
   * other rows. Its own transitions nest as savepoints; post-commit effects
   * (Redis flags, the revocation broadcast) still run when the call returns.
   */
  forTransaction(tx: MissionTransaction): MissionService {
    return new MissionService({ ...this.deps, repo: new MissionRepository(tx as never) });
  }

  /**
   * Open a mission. Signs the `mission_open` claim envelope, inserts
   * the denormalized missions row, and returns the mission_id +
   * claim_id for the caller to embed in subsequent passport-issue
   * calls (passport.mission_ids[]).
   */
  open(input: OpenInput) {
    return lifecycle.open(this.deps, input);
  }

  /**
   * Complete a mission. Idempotent — second call returns the prior
   * terminal state without transitioning. Emits a NEW mission claim
   * with terminal_state set; the row's claim_id pointer updates to
   * the new claim.
   */
  complete(missionId: string, input: CompleteInput = {}) {
    return lifecycle.complete(this.deps, missionId, input);
  }

  /**
   * Revoke a mission. Idempotent. Emits a NEW mission claim with
   * revoke_reason + terminal_state set; updates the row, and ends every
   * Passport bound to the Mission in the same transaction.
   */
  revoke(missionId: string, input: RevokeInput) {
    return lifecycle.revoke(this.deps, missionId, input);
  }

  /**
   * Proxy gate check, called only through beginAgentRuntime. Returns a verdict the caller
   * dispatches on; see gate.ts for the full contract.
   */
  checkGate(input: Parameters<typeof gate.checkGate>[1]) {
    return gate.checkGate(this.deps, input);
  }

  /**
   * Move a live Mission's expiry and coverage cap forward with a new signed
   * claim. Internal: the agent-account renewal is the only caller.
   */
  extend(missionId: string, input: ExtendInput) {
    return lifecycle.extend(this.deps, missionId, input);
  }

  /** Coverage spend recorded against a Mission before an instant. */
  async coverageSpendBefore(operatorId: string, missionId: string, before: Date): Promise<number> {
    return (await gate.sumCoverageSpend(this.deps, operatorId, missionId, before)).usedCents;
  }

  /**
   * Hard auto-revoke triggered by a hard-cap breach (default response
   * for coverage_cap_cents, max_dropoff_bytes, max_concurrent_intents).
   * Convenience wrapper around revoke() with reason='cap_breach_hard'.
   * Caller (proxy gate) invokes after checkGate returns a cap-shape
   * denial with capBehavior === 'auto_revoke'.
   */
  autoRevokeForCapBreach(missionId: string, capName: string) {
    return lifecycle.autoRevokeForCapBreach(this.deps, missionId, capName);
  }

  /**
   * What a reached cap does: `pause` pauses the Mission for its owner's review, `end_mission` ends it, `refuse_action`
   * changes nothing (the caller refuses the action). Called by the gate's caller after checkGate names the cap.
   */
  applyCapBehavior(missionId: string, cap: MissionCapName, behavior: MissionCapBehavior, service: string | null = null) {
    return caps.applyCapBehavior(this.deps, missionId, cap, behavior, service);
  }

  /** The money cap refused a spend at the budget ledger's counter: apply its behaviour, and say which it was. */
  spendCapReached(missionId: string) {
    return caps.spendCapReached(this.deps, missionId);
  }

  /** The owner's decision on a Mission a cap paused: raise the limit, continue, or close. */
  review(missionId: string, input: ReviewInput) {
    return caps.review(this.deps, missionId, input);
  }

  /** The owner's pre-approval of the Mission's print-on-demand orders, in cents across all of them (null: none). */
  setMakingAllowance(missionId: string, operatorId: string, cents: number | null) {
    return caps.setMakingAllowance(this.deps, missionId, operatorId, cents);
  }

  /**
   * Add recipients to a running Mission (the owner's call, never an agent's): the new pins are merged into the Mission's
   * own, so a per-job rule then allows a send to them too. Throws `NotFoundError` for a Mission that is not the operator's
   * and `ConflictError` for one that has ended. Answers the pins the Mission holds now.
   */
  async addRecipientPins(operatorId: string, missionId: string, added: RecipientPin[]): Promise<RecipientPin[]> {
    const result = await this.deps.repo.updateRecipientPins(operatorId, missionId, (current) => mergeRecipientPins(readRecipientPins(current), added));
    if (result.status === 'missing') throw new NotFoundError('mission', missionId);
    if (result.status !== 'updated') throw new ConflictError('This Mission has ended, so its recipients cannot be changed.');
    return readRecipientPins(result.row.recipient_pins) ?? [];
  }

  findById(missionId: string, scope?: { operatorId: string; agentId?: string }) {
    return reads.findById(this.deps, missionId, scope);
  }

  readOutput(missionId: string, actor: { operatorId: string; agentId?: string }) {
    return reads.readOutput(this.deps, missionId, actor);
  }

  listByOperator(operatorId: string, opts?: Parameters<typeof reads.listByOperator>[2]) {
    return reads.listByOperator(this.deps, operatorId, opts);
  }

  listPassports(
    operatorId: string,
    missionId: string,
    opts: { agentId?: string; page?: number; limit?: number },
  ) {
    return reads.listPassports(this.deps, operatorId, missionId, opts);
  }

  /** Current cap usage for a mission, as one read for the dashboard's current-vs-limit bars. */
  getCapUsage(missionId: string) {
    return gate.getCapUsage(this.deps, missionId);
  }
}
