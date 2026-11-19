// Held actions: a policy rule that holds an action for a person.
//
// The held action is refused like any other (CONTROL_DENIED with reason
// `review_required`) and carries a reference, `retry.ref`, that the agent sends
// back as `X-Control-Ref` when it tries the same call again. A person decides
// through the ordinary governance approval (the approve page, or the chat for
// the actions the chat may carry); this service ties that decision to the one
// call it covers and runs the intent approval gate's own states over it:
//
//   pending -> approved -> consuming -> consumed     (the happy path)
//   consuming -> approved                            (the action did not run: released)
//   pending -> rejected | expired
//
// A review is keyed on the account and the policy, not on a Passport or an
// accountability mode, and on the exact call: the retry must reproduce the
// call's digest. Of two requests presenting one approval at the same instant,
// exactly one reserves it; a call that failed hands it back so the same
// approval can be used again; a call that ran consumes it for good.

import { createHash } from 'node:crypto';
import {
  CONTROL_REVIEW_USE_WINDOW_SECONDS,
  NotFoundError,
  ids,
  safeErrorSummary,
  type ControlReviewRow,
  type ControlReviewView,
  type DecisionReachedHook,
} from '@stack/shared';
import type { ControlReviewRepository } from '../../repositories/control-policy-repo.js';
import type { GovernanceApprovalService } from '../governance-approval-service.js';

export type ReviewReserve =
  | { state: 'reserved'; review: ControlReviewRow; ownerHash: string }
  | { state: 'pending' | 'rejected' | 'expired' | 'consumed' | 'in_use' | 'mismatch' | 'unknown'; review: ControlReviewRow | null };

export interface ControlReviewServiceDeps {
  repo: ControlReviewRepository;
  governance: Pick<GovernanceApprovalService, 'createPending' | 'consume' | 'findForOperator' | 'approvalUrl' | 'decide'>;
  /**
   * Told once a held action's review ends from pending (approved, rejected, expired), so the agent waiting on it hears
   * how it ended. Called after the row moved; a failure is logged and never undoes the decision.
   */
  onDecision?: DecisionReachedHook;
  now?: () => Date;
}

/** What a held action's approval commits to: this review, this exact call, this policy revision. */
export function reviewApprovalPayload(input: { reviewId: string; callDigest: string; policyId: string; policyRevision: number }): Record<string, unknown> {
  return { review_id: input.reviewId, call_digest: input.callDigest, policy_id: input.policyId, policy_revision: input.policyRevision };
}

export function ownerHashOf(operation: string): string {
  return createHash('sha256').update(operation, 'utf8').digest('hex');
}

export class ControlReviewService {
  private readonly now: () => Date;

  constructor(private readonly deps: ControlReviewServiceDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  /**
   * Open the review of a held call, or return the one already open for exactly
   * this call (the agent asking again before anyone decided). Creates the
   * approval a person will see.
   */
  async open(input: {
    operatorId: string;
    accountId: string;
    agentId: string;
    memberId?: string | null;
    policy: { id: string; revision: number };
    rule: { section: string; id: string };
    action: string;
    callDigest: string;
    summary: string;
    /** A held card purchase or wallet payment: what it costs at most, in USD cents. A chat may approve only these. */
    payment?: { surface: 'card' | 'wallet'; amountCents: number };
  }): Promise<{ review: ControlReviewRow; /** False when the agent asked again and the review already existed. */ created: boolean; approvalUrl: string }> {
    const existing = await this.deps.repo.findLive(input.operatorId, input.callDigest);
    if (existing) return { review: existing, created: false, approvalUrl: this.deps.governance.approvalUrl(existing.governance_approval_id) };

    const reviewId = ids.controlReview();
    const created = await this.deps.governance.createPending({
      operatorId: input.operatorId,
      memberId: input.memberId ?? null,
      action: 'control_review',
      resourceId: reviewId,
      payload: reviewApprovalPayload({ reviewId, callDigest: input.callDigest, policyId: input.policy.id, policyRevision: input.policy.revision }),
      summary: input.summary,
      requestedVia: 'operator_key',
    });
    const { row, created: inserted } = await this.deps.repo.insert({
      id: reviewId,
      operator_id: input.operatorId,
      account_id: input.accountId,
      agent_id: input.agentId,
      policy_id: input.policy.id,
      policy_revision: input.policy.revision,
      rule_section: input.rule.section,
      rule_id: input.rule.id,
      action_type: input.action,
      call_digest: input.callDigest,
      summary: input.summary,
      governance_approval_id: created.row.id,
      expires_at: created.row.expires_at,
      ...(input.payment ? { payment_surface: input.payment.surface, amount_cents: input.payment.amountCents } : {}),
    });
    if (!inserted) {
      // A concurrent identical call opened it first: its approval is the one a person will see. The one just
      // made belongs to no review, so it is closed rather than left on the approve page to be answered for nothing.
      await this.deps.governance.decide(created.row.id, input.operatorId, 'reject').catch(() => undefined);
    }
    return { review: row, created: inserted, approvalUrl: inserted ? created.approvalUrl : this.deps.governance.approvalUrl(row.governance_approval_id) };
  }

  /**
   * Follow the person's decision into the review: an approved approval becomes
   * an approved review (once, consuming the approval), a rejected or expired
   * one closes it. Idempotent and safe under concurrency: every step is a
   * compare-and-swap.
   */
  async sync(row: ControlReviewRow): Promise<ControlReviewRow> {
    if (row.status !== 'pending') return this.expireIfDue(row);
    const now = this.now();
    if (row.expires_at.getTime() <= now.getTime()) return this.close(row, 'expired', now);
    const approval = await this.deps.governance.findForOperator(row.governance_approval_id, row.operator_id);
    if (!approval) return row;
    if (approval.status === 'rejected') return this.close(row, 'rejected', now);
    if (approval.status === 'expired') return this.close(row, 'expired', now);
    if (approval.status !== 'approved') return row;
    // The person said yes. Spend the approval (single use, bound to this exact call) and open the review for a while.
    try {
      await this.deps.governance.consume({
        approvalId: approval.id,
        operatorId: row.operator_id,
        action: 'control_review',
        resourceId: row.id,
        payload: reviewApprovalPayload({ reviewId: row.id, callDigest: row.call_digest, policyId: row.policy_id, policyRevision: row.policy_revision }),
      });
    } catch {
      // Already spent by a concurrent sync, or it does not match: whatever the review says now is the truth.
      return this.reload(row);
    }
    const expiresAt = new Date(now.getTime() + CONTROL_REVIEW_USE_WINDOW_SECONDS * 1000);
    const approved = await this.deps.repo.approve(row.id, expiresAt, now);
    if (!approved) return this.reload(row);
    await this.announce(approved, 'approved', now);
    return approved;
  }

  /** pending -> rejected or expired, and the agent told when this call is the one that moved it. */
  private async close(row: ControlReviewRow, status: 'rejected' | 'expired', now: Date): Promise<ControlReviewRow> {
    const closed = await this.deps.repo.close(row.id, status, now);
    if (!closed) return this.reload(row);
    await this.announce(closed, status, now);
    return closed;
  }

  /**
   * Reviews nobody decided before their time ran out become `expired`, and the agent waiting on each is told. Safe on
   * every machine: each row moves once. Returns how many ended.
   */
  async expirePending(limit = 200): Promise<number> {
    const now = this.now();
    const rows = await this.deps.repo.expirePendingDue(now, limit);
    for (const row of rows) await this.announce(row, 'expired', now);
    return rows.length;
  }

  /**
   * The person decided the governance approval of a held action: carry the decision into the review now, so the agent
   * is told at once instead of on its next retry. A decision on any other approval is not a review's.
   */
  async followDecision(operatorId: string, reviewId: string): Promise<void> {
    const row = await this.deps.repo.get(operatorId, reviewId);
    if (row) await this.sync(row);
  }

  private async announce(row: Pick<ControlReviewRow, 'id' | 'operator_id' | 'agent_id'>, result: 'approved' | 'rejected' | 'expired', at: Date): Promise<void> {
    if (!this.deps.onDecision) return;
    try {
      await this.deps.onDecision({ operatorId: row.operator_id, agentId: row.agent_id, kind: 'control_review', itemId: row.id, result, occurredAt: at });
    } catch (error) {
      console.error('[ControlReviewService] onDecision hook failed:', safeErrorSummary(error));
    }
  }

  private async expireIfDue(row: ControlReviewRow): Promise<ControlReviewRow> {
    // A reservation stranded by a crash lapses with its approval's window, and so frees nothing for good.
    if ((row.status === 'approved' || row.status === 'consuming') && row.expires_at.getTime() <= this.now().getTime()) {
      await this.deps.repo.expireDue(this.now());
      return this.reload(row);
    }
    return row;
  }

  private async reload(row: ControlReviewRow): Promise<ControlReviewRow> {
    return (await this.deps.repo.get(row.operator_id, row.id)) ?? row;
  }

  /**
   * The agent retried a held call with its reference. Reserve the approval for
   * this operation if it is approved and the call is the one approved.
   */
  async reserve(input: { operatorId: string; ref: string; agentId: string; callDigest: string; operation: string }): Promise<ReviewReserve> {
    const found = await this.deps.repo.get(input.operatorId, input.ref);
    if (!found) return { state: 'unknown', review: null };
    // A reference names one agent's one call; another agent, or another call, is not covered.
    if (found.agent_id !== input.agentId || found.call_digest !== input.callDigest) return { state: 'mismatch', review: null };
    const review = await this.sync(found);
    switch (review.status) {
      case 'pending':
        return { state: 'pending', review };
      case 'rejected':
      case 'expired':
      case 'consumed':
        return { state: review.status, review };
      case 'consuming':
        return { state: 'in_use', review };
      case 'approved': {
        const ownerHash = ownerHashOf(input.operation);
        const reserved = await this.deps.repo.reserve(review.id, ownerHash, this.now());
        if (!reserved) return { state: 'in_use', review };
        return { state: 'reserved', review: reserved, ownerHash };
      }
      default:
        // A status this code does not know is never an approval.
        return { state: 'unknown', review: null };
    }
  }

  /** The action ran: the approval is spent for good. */
  consume(reviewId: string, ownerHash: string): Promise<boolean> {
    return this.deps.repo.consume(reviewId, ownerHash);
  }

  /** The action did not run: the same approval may be used again. */
  release(reviewId: string, ownerHash: string): Promise<boolean> {
    return this.deps.repo.release(reviewId, ownerHash);
  }

  async get(operatorId: string, id: string): Promise<ControlReviewRow> {
    const row = await this.deps.repo.get(operatorId, id);
    if (!row) throw new NotFoundError('Control review', id);
    return this.sync(row);
  }

  async list(operatorId: string, query: { pendingOnly?: boolean; limit: number }): Promise<ControlReviewRow[]> {
    const rows = await this.deps.repo.list(operatorId, {
      ...(query.pendingOnly ? { statuses: ['pending' as const, 'approved' as const] } : {}),
      limit: query.limit,
    });
    return Promise.all(rows.map((row) => this.sync(row)));
  }

  toView(row: ControlReviewRow): ControlReviewView {
    return {
      id: row.id,
      account_id: row.account_id,
      agent_id: row.agent_id,
      policy_id: row.policy_id,
      policy_revision: row.policy_revision,
      action_type: row.action_type,
      summary: row.summary,
      status: row.status as ControlReviewView['status'],
      approval_id: row.governance_approval_id,
      approval_url: this.deps.governance.approvalUrl(row.governance_approval_id),
      expires_at: row.expires_at.toISOString(),
      created_at: row.created_at.toISOString(),
    };
  }
}
