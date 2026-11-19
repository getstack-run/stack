// IntentApprovalService.
//
// Pre-execution approval gate for enforced Intents. An agent (typically
// via its SDK's `intents.submit` or `intents.submitAndWait`) calls
// `submit()` with a candidate IntentClaim + passport JWT. The service:
//
//   1. Verifies the passport (via PassportService.verify)
//   2. Registers the intent_claim via ClaimRegistryService.registerClaim
//   3. Optionally runs IntentSimulationService.simulate to attach a
//      paired intent_simulation claim
//   4. Creates an intent_approvals row with status='pending' and a TTL
//
// The operator (or a member with role=admin) then approves or rejects
// via `approve()` / `reject()`. Rejection auto-revokes the passport in
// commit 3's notification wiring; this service ONLY transitions the
// approval row's state. Decision-side effects (revoke, notify) are
// callback-driven via deps so the substrate stays testable in isolation.
//
// **Opt-in for v1.** Existing producers (proxy.ts, skills.ts, a2a.ts)
// are NOT rewired to call this service. They continue to behave as
// today (no pre-execution block). Wiring those producers to require
// approval is a separate change per producer.

import { canonicalize, fleetDigest, ForbiddenError, InvalidRequestError, INTENT_APPROVAL_DEFAULT_TTL_SECONDS, INTENT_APPROVAL_MAX_TTL_SECONDS, NotFoundError, type DecisionReachedHook, type IntentClaim, ids } from '@stack/shared';
import type { KmsService } from '../crypto/kms.js';
import { safeErrorSummary } from '@stack/shared';
import type { IntentApprovalRepository } from '../repositories/intent-approval-repo.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { PassportService } from './passport-service.js';
import type { IntentSimulationService, SimulateResult } from './intent-simulation-service.js';

/** How long an approval may be used once a person approved it, counted from the decision, as a control review's is. */
export const INTENT_APPROVAL_USE_WINDOW_SECONDS = 60 * 60;

export interface IntentApprovalDeps {
  kms?: Pick<KmsService, 'encrypt' | 'decrypt'>;
  repo: IntentApprovalRepository;
  passportService: PassportService;
  claimRegistry: ClaimRegistryService;
  /**
   * Optional. When set, `submit()` runs the simulator and attaches the
   * resulting simulation claim_id to the approval row. When absent,
   * approval rows ship without a simulated_claim_id and the dashboard's
   * "simulation result" section is empty for these.
   */
  intentSimulation?: IntentSimulationService;
  /**
   * Optional callback fired after a row transitions to 'rejected'. The
   * production wiring calls `passportService.revoke(...)` here (commit
   * 3) so a rejection auto-revokes the passport. Returning a rejected
   * promise does NOT roll back the row — the decision is committed; the
   * side effect is best-effort. Errors are logged.
   */
  onReject?: (row: ApprovalRowView) => Promise<void>;
  /**
   * Optional callback fired immediately after a pending row is inserted.
   * Production wiring (commit 3) calls `notification.publishEvent` so
   * the operator's configured channels (email / Slack / webhook) get
   * notified. Errors are logged, not propagated.
   */
  onSubmit?: (row: ApprovalRowView) => Promise<void>;
  /**
   * Optional. Told once a pending approval ends (approved, rejected or expired), so the agent that waits on it hears
   * how it ended. Called after the row is written; a failure is logged and never undoes the decision.
   */
  onDecision?: DecisionReachedHook;
}

export interface SubmitInput {
  /**
   * Passport JWT this Intent is being submitted under. Verified by
   * PassportService.verify (signature + revocation + freshness) before
   * any DB write.
   */
  passportToken: string;
  /** Candidate IntentClaim. Must validate against the IntentClaim Zod schema. */
  intent: IntentClaim;
  /**
   * Pending TTL in seconds. Default 900 (15 min); hard max 3600. Values
   * outside the range clamp.
   */
  expiresInSeconds?: number;
  /**
   * When true, the service registers the intent_claim and the approval
   * row but skips the simulation. Useful when the caller has already
   * simulated independently OR doesn't want a paired sim claim.
   */
  skipSimulation?: boolean;
}

export interface SubmitResult {
  approvalId: string;
  intentClaimId: string;
  simulatedClaimId?: string;
  status: 'pending';
  expiresAt: Date;
  /** Inline simulation result for the caller (mirrors what's in the claim). */
  simulation?: SimulateResult;
}

export interface ApproveInput {
  id: string;
  /** The operator on whose account the approval row sits. */
  operatorId: string;
  /** When a team member approved through a dashboard or OAuth session, set this. */
  memberId?: string;
  notes?: string;
}

export interface RejectInput {
  id: string;
  operatorId: string;
  memberId?: string;
  notes?: string;
  /** When true, the agent also gets blocked from future passports. Wired in commit 3 via onReject. */
  blockFuture?: boolean;
}

export interface DecisionResult {
  approvalId: string;
  status: 'approved' | 'rejected';
  decidedAt: Date;
}

/**
 * Subset of the row shape passed to onSubmit / onReject callbacks. Keeps
 * the callback surface stable across schema additions.
 */
export interface ApprovalRowView {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  intent_claim_id: string;
  simulated_claim_id: string | null;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  notes: string | null;
  block_future: boolean;
}

export class IntentApprovalService {
  constructor(private deps: IntentApprovalDeps) {}

  async submitFleetReview(input: {
    operatorId: string; agentId: string; passportJti: string; intentClaimId: string;
    policyId: string; policyRevision: number; missionId: string; requestHash: string;
    reviewKey: string; expiresAt: Date; exactRequest: unknown;
  }) {
    if (!this.deps.kms || fleetDigest(input.exactRequest) !== input.requestHash) throw new ForbiddenError();
    const exact = canonicalize(input.exactRequest);
    if (Buffer.byteLength(exact) > 1_048_576) throw new ForbiddenError();
    const sealed = await this.deps.kms.encrypt(canonicalize({
      operator_id: input.operatorId, agent_id: input.agentId, policy_id: input.policyId,
      policy_revision: input.policyRevision, mission_id: input.missionId, request_hash: input.requestHash,
      review_key: input.reviewKey, request: input.exactRequest,
    }), { operator_id: input.operatorId, store: 'fleet_review', review_key: input.reviewKey });
    const result = await this.deps.repo.insertFleetReview({
      id: ids.intentApproval(), operator_id: input.operatorId, agent_id: input.agentId,
      passport_jti: input.passportJti, intent_claim_id: input.intentClaimId, status: 'pending',
      expires_at: input.expiresAt, fleet_policy_id: input.policyId, fleet_policy_revision: input.policyRevision,
      fleet_mission_id: input.missionId, fleet_request_hash: input.requestHash, fleet_review_key: input.reviewKey,
      fleet_review_encrypted: sealed.ciphertext, fleet_review_key_ref: sealed.keyRef,
    });
    if (result.created && this.deps.onSubmit) {
      this.deps.onSubmit(rowView(result.row)).catch(err => console.error('[IntentApprovalService] onSubmit hook failed:', safeErrorSummary(err)));
    }
    return result.row;
  }

  async readFleetReview(operatorId: string, approvalId: string): Promise<unknown> {
    const row = await this.findById(approvalId, operatorId);
    if (!row || !row.fleet_policy_id || !row.fleet_review_key || !row.fleet_review_encrypted || !this.deps.kms) throw new NotFoundError('Intent review', approvalId);
    const plain = await this.deps.kms.decrypt(row.fleet_review_encrypted,
      { operator_id: operatorId, store: 'fleet_review', review_key: row.fleet_review_key });
    const value = JSON.parse(plain) as Record<string, unknown>;
    if (value.operator_id !== operatorId || value.agent_id !== row.agent_id || value.policy_id !== row.fleet_policy_id ||
        value.policy_revision !== row.fleet_policy_revision || value.mission_id !== row.fleet_mission_id ||
        value.request_hash !== row.fleet_request_hash || value.review_key !== row.fleet_review_key ||
        fleetDigest(value.request) !== row.fleet_request_hash) throw new ForbiddenError();
    const claim = await this.deps.claimRegistry.getClaim(row.intent_claim_id);
    const intent = claim.body_json as IntentClaim;
    const decision = intent.policy_decision;
    if (claim.operator_id !== operatorId || intent.agent_id !== row.agent_id || decision?.origin !== 'fleet_policy' ||
        decision.policy_id !== row.fleet_policy_id || decision.policy_revision !== row.fleet_policy_revision ||
        decision.mission_id !== row.fleet_mission_id || decision.request_hash !== row.fleet_request_hash || decision.effect !== 'review') throw new ForbiddenError();
    return value.request;
  }

  async submit(input: SubmitInput): Promise<SubmitResult> {
    if (input.intent.policy_decision) throw new ForbiddenError();
    // 1. Verify passport. Throws on revocation / freshness / signature.
    const claims = await this.deps.passportService.verify(input.passportToken);
    const operatorId = claims.stk.operator_id;
    const agentId = claims.stk.agent_id;
    const passportJti = claims.jti;

    // 2. Register the intent_claim. The registry handles schema
    //    validation + tier gating + envelope signing.
    const intent = await this.deps.claimRegistry.registerClaim({
      operatorId,
      passportJti,
      claimType: 'intent_claim',
      payload: input.intent,
    });

    // 3. Optionally run the simulation. The simulator itself registers
    //    the intent_simulation claim under the same passport subject.
    let simulation: SimulateResult | undefined;
    let simulatedClaimId: string | undefined;
    if (this.deps.intentSimulation && !input.skipSimulation) {
      simulation = await this.deps.intentSimulation.simulate({
        passportToken: input.passportToken,
        intent: input.intent,
        intentClaimRef: intent.claimId,
      });
      simulatedClaimId = simulation.claimId;
    }

    // 4. Compute pending TTL + insert row.
    const ttlSeconds = pendingTtl(input.expiresInSeconds);
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    const id = ids.intentApproval();
    const row = await this.deps.repo.insert({
      id,
      operator_id: operatorId,
      agent_id: agentId,
      passport_jti: passportJti,
      intent_claim_id: intent.claimId,
      simulated_claim_id: simulatedClaimId ?? null,
      status: 'pending',
      expires_at: expiresAt,
    } as Parameters<IntentApprovalRepository['insert']>[0]);

    // 5. Fire onSubmit best-effort. Errors logged, not propagated —
    //    notification dispatch failure shouldn't fail the submit.
    if (this.deps.onSubmit) {
      this.deps.onSubmit(rowView(row)).catch((err: unknown) => {
        console.error('[IntentApprovalService] onSubmit hook failed:', safeErrorSummary(err));
      });
    }

    return {
      approvalId: id,
      intentClaimId: intent.claimId,
      ...(simulatedClaimId ? { simulatedClaimId } : {}),
      status: 'pending',
      expiresAt,
      ...(simulation ? { simulation } : {}),
    };
  }

  async listPending(operatorId: string, opts?: { agentId?: string; page?: number; limit?: number }) {
    const [items, total] = await Promise.all([
      this.deps.repo.listByOperator(operatorId, { status: 'pending', ...opts }),
      this.deps.repo.countByOperator(operatorId, 'pending', opts?.agentId),
    ]);
    const page = opts?.page ?? 1;
    const limit = opts?.limit ?? 50;
    return { items, total, page, limit, has_more: page * limit < total };
  }

  async findById(id: string, operatorId: string) {
    const row = await this.deps.repo.findById(id);
    if (!row) return null;
    if (row.operator_id !== operatorId) {
      // Treat cross-tenant access as not-found rather than 403 so we
      // don't leak existence of ids belonging to other operators.
      return null;
    }
    return row;
  }

  async approve(input: ApproveInput): Promise<DecisionResult> {
    const existing = await this.findById(input.id, input.operatorId);
    if (!existing) throw new NotFoundError('intent_approval', input.id);
    if (existing.fleet_policy_id) await this.readFleetReview(input.operatorId, input.id);
    if (existing.status !== 'pending') {
      throw new ForbiddenError(
        `approval ${input.id} is already ${existing.status}; only pending approvals can transition`,
      );
    }
    const now = new Date();
    if (existing.expires_at.getTime() <= now.getTime()) {
      throw new ForbiddenError(`approval ${input.id} has expired; the agent can submit the intent again`);
    }
    const row = await this.deps.repo.markDecided(input.id, 'approved', {
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
      ...(input.memberId !== undefined ? { decidedByMemberId: input.memberId } : {}),
      now,
      useUntil: new Date(now.getTime() + INTENT_APPROVAL_USE_WINDOW_SECONDS * 1000),
    });
    if (!row) {
      // CAS lost — another caller decided concurrently, or the pending window ran out in between.
      throw new ForbiddenError(`approval ${input.id} was already decided or has expired`);
    }
    await this.announce(row, 'approved', row.decided_at ?? undefined);
    return { approvalId: row.id, status: 'approved', decidedAt: row.decided_at! };
  }

  /** Flips pending approvals past their TTL to expired. Run by the worker; returns how many it flipped. */
  sweepExpired(now: Date = new Date()): Promise<number> {
    return this.deps.repo.sweepExpired(now);
  }

  async reject(input: RejectInput): Promise<DecisionResult> {
    const existing = await this.findById(input.id, input.operatorId);
    if (!existing) throw new NotFoundError('intent_approval', input.id);
    if (existing.status !== 'pending') {
      throw new ForbiddenError(
        `approval ${input.id} is already ${existing.status}; only pending approvals can transition`,
      );
    }
    const row = await this.deps.repo.markDecided(input.id, 'rejected', {
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
      ...(input.memberId !== undefined ? { decidedByMemberId: input.memberId } : {}),
      ...(input.blockFuture !== undefined ? { blockFuture: input.blockFuture } : {}),
    });
    if (!row) {
      throw new ForbiddenError(`approval ${input.id} was already decided`);
    }
    // Fire onReject best-effort. Production wiring revokes the passport.
    if (this.deps.onReject) {
      this.deps.onReject(rowView(row)).catch((err: unknown) => {
        console.error('[IntentApprovalService] onReject hook failed:', safeErrorSummary(err));
      });
    }
    await this.announce(row, 'rejected', row.decided_at ?? undefined);
    return { approvalId: row.id, status: 'rejected', decidedAt: row.decided_at! };
  }

  /**
   * Pending approvals whose time has passed become `expired`, and the agent waiting on each is told. Returns how many
   * ended. Safe to run on every machine: each row moves once (a conditional update), and only the machine that moved it
   * tells the agent.
   */
  async expireDue(now: Date = new Date(), limit = 200): Promise<number> {
    const rows = await this.deps.repo.expirePending(now, limit);
    for (const row of rows) await this.announce(row, 'expired', now);
    return rows.length;
  }

  /** An intent approval or a fleet review ended: tell the agent that waits on it. */
  private async announce(
    row: { id: string; operator_id: string; agent_id: string; fleet_policy_id: string | null },
    result: 'approved' | 'rejected' | 'expired',
    occurredAt?: Date,
  ): Promise<void> {
    if (!this.deps.onDecision) return;
    try {
      await this.deps.onDecision({
        operatorId: row.operator_id,
        agentId: row.agent_id,
        kind: row.fleet_policy_id ? 'fleet_review' : 'intent_approval',
        itemId: row.id,
        result,
        ...(occurredAt ? { occurredAt } : {}),
      });
    } catch (err) {
      console.error('[IntentApprovalService] onDecision hook failed:', safeErrorSummary(err));
    }
  }
}

/** How long a pending approval waits: the default (15 minutes) when none is named, else the time named, which may not be more than a day. */
function pendingTtl(seconds: number | undefined): number {
  if (!seconds || seconds <= 0) return INTENT_APPROVAL_DEFAULT_TTL_SECONDS;
  if (seconds > INTENT_APPROVAL_MAX_TTL_SECONDS) {
    throw new InvalidRequestError(`An approval waits at most ${INTENT_APPROVAL_MAX_TTL_SECONDS} seconds (24 hours); expires_in_seconds was ${seconds}.`, {
      max_seconds: INTENT_APPROVAL_MAX_TTL_SECONDS,
    });
  }
  return seconds;
}

function rowView(row: {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  intent_claim_id: string;
  simulated_claim_id: string | null;
  status: string;
  notes: string | null;
  block_future: boolean;
}): ApprovalRowView {
  return {
    id: row.id,
    operator_id: row.operator_id,
    agent_id: row.agent_id,
    passport_jti: row.passport_jti,
    intent_claim_id: row.intent_claim_id,
    simulated_claim_id: row.simulated_claim_id,
    status: row.status as ApprovalRowView['status'],
    notes: row.notes,
    block_future: row.block_future,
  };
}
