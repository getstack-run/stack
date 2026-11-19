// IntentApprovalRepository.
//
// Persistence for the pre-execution approval gate. Pending rows have
// a TTL (`expires_at`); the worker's sweep flips past-TTL pending rows to
// status='expired'. Decision transitions go through `markDecided`, an
// atomic CAS on status='pending' (and, for an approval, a pending TTL
// still running), so concurrent approve+reject races resolve
// deterministically. An approval's `expires_at` then becomes its own use
// window, counted from the decision.

import { and, eq, desc, gt, inArray, lte, sql, or, isNull } from 'drizzle-orm';
import { type Database, intentApprovals } from '@stack/shared';

export type IntentApprovalTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export type IntentApprovalStatus =
  | 'pending'
  | 'approved'
  | 'consuming' // reserved at admit (approved → consuming) so a concurrent twin cannot spend the same approval; settles to consumed on success or releases to approved on failure
  | 'rejected'
  | 'expired'
  | 'consumed'; // gate flips approved → consumed on first successful outcome

export class IntentApprovalRepository {
  constructor(private db: Database) {}

  async insert(data: typeof intentApprovals.$inferInsert) {
    const [row] = await this.db.insert(intentApprovals).values(data).returning();
    return row!;
  }

  async insertFleetReview(data: typeof intentApprovals.$inferInsert, now: Date = new Date()) {
    if (!data.fleet_review_key) throw new Error('Invalid input');
    const [created] = await this.db.insert(intentApprovals).values(data).onConflictDoNothing().returning();
    if (created) return { row: created, created: true };
    // A review of the same operation that ran out (never decided in time, or approved and not used in its window) opens
    // again for the same request, so an agent retrying with the same operation key asks the person again.
    const [reopened] = await this.db.update(intentApprovals).set({
      status: 'pending', agent_id: data.agent_id, passport_jti: data.passport_jti, intent_claim_id: data.intent_claim_id,
      expires_at: data.expires_at, requested_at: now, decided_at: null, decided_by_member_id: null, notes: null,
      block_future: false, consuming_owner_hash: null,
      fleet_review_encrypted: data.fleet_review_encrypted ?? null, fleet_review_key_ref: data.fleet_review_key_ref ?? null,
    }).where(and(
      eq(intentApprovals.operator_id, data.operator_id), eq(intentApprovals.fleet_review_key, data.fleet_review_key),
      or(
        eq(intentApprovals.status, 'expired'),
        and(inArray(intentApprovals.status, ['pending', 'approved']), lte(intentApprovals.expires_at, now)),
      ),
    )).returning();
    if (reopened) return { row: reopened, created: true };
    const [row] = await this.db.select().from(intentApprovals).where(and(
      eq(intentApprovals.operator_id, data.operator_id), eq(intentApprovals.fleet_review_key, data.fleet_review_key),
    ));
    if (!row) throw new Error('Invalid input');
    return { row, created: false };
  }

  async findById(id: string) {
    return this.db.query.intentApprovals.findFirst({
      where: eq(intentApprovals.id, id),
    });
  }

  /**
   * List approvals scoped to one operator. When `status` is set, filters
   * to that status (typically 'pending' for the queue surface). Newest
   * first by requested_at.
   */
  async listByOperator(
    operatorId: string,
    opts?: { status?: IntentApprovalStatus; agentId?: string; page?: number; limit?: number },
  ) {
    const limit = opts?.limit ?? 50;
    const offset = ((opts?.page ?? 1) - 1) * limit;
    const where = and(
      eq(intentApprovals.operator_id, operatorId),
      opts?.status ? eq(intentApprovals.status, opts.status) : undefined,
      opts?.agentId ? eq(intentApprovals.agent_id, opts.agentId) : undefined,
    );
    return this.db.query.intentApprovals.findMany({
      where,
      orderBy: [desc(intentApprovals.requested_at), desc(intentApprovals.id)],
      limit,
      offset,
    });
  }

  async countByOperator(operatorId: string, status?: IntentApprovalStatus, agentId?: string) {
    const where = and(
      eq(intentApprovals.operator_id, operatorId),
      status ? eq(intentApprovals.status, status) : undefined,
      agentId ? eq(intentApprovals.agent_id, agentId) : undefined,
    );
    const result = await this.db
      .select({ c: sql<number>`count(*)::int` })
      .from(intentApprovals)
      .where(where);
    return result[0]?.c ?? 0;
  }

  /**
   * Atomically transition a pending row to approved/rejected. Returns
   * the updated row when the CAS hit (was pending), null when the row
   * was already decided / expired / not found. Caller treats null as a
   * stale-decision error.
   */
  async markDecided(
    id: string,
    decision: 'approved' | 'rejected',
    opts: { notes?: string; decidedByMemberId?: string; blockFuture?: boolean; useUntil?: Date; now?: Date },
  ) {
    const now = opts.now ?? new Date();
    const [row] = await this.db
      .update(intentApprovals)
      .set({
        status: decision,
        decided_at: now,
        notes: opts.notes ?? null,
        decided_by_member_id: opts.decidedByMemberId ?? null,
        block_future: opts.blockFuture ?? false,
        // An approval is usable for its own window from the decision, however late in the pending window it came.
        ...(decision === 'approved' && opts.useUntil ? { expires_at: opts.useUntil } : {}),
      })
      .where(and(
        eq(intentApprovals.id, id),
        eq(intentApprovals.status, 'pending'),
        // A pending approval past its TTL cannot be approved any more.
        ...(decision === 'approved' ? [gt(intentApprovals.expires_at, now)] : []),
      ))
      .returning();
    return row ?? null;
  }

  /**
   * atomic CAS approved → consumed.
   *
   * Called by the producer gate after a successful 2xx-3xx outcome.
   * Idempotent: returns false when the row was not in 'approved' state
   * (already consumed by a concurrent in-flight call, or in some other
   * terminal state, or not found). Hot-path predicate is the (id,
   * status='approved') pair — the existing `ia_status_idx` covers
   * status; the primary key covers id; both filter cheap.
   *
   * Does NOT touch decided_at / decided_by_member_id / notes — those
   * reflect the operator decision (approve), not the consume event.
   * The actual call's lineage lives in the paired intent_outcome
   * claim's signed timestamp.
   */
  async markConsumed(
    id: string,
    consumingOwnerHash?: string,
    transaction?: IntentApprovalTransaction,
  ): Promise<boolean> {
    // A deterministic caller may settle only the live reservation it owns.
    // An already-consumed row is never reported as a successful consume: exact
    // retries receive a replay-only gate result and must not finalize again.
    // Legacy callers can consume an approved row or an unowned consuming row.
    const result = await (transaction ?? this.db)
      .update(intentApprovals)
      .set({
        status: 'consumed',
        // Deterministic consumers retain their one-way owner hash. A retry can
        // then prove that this already-consumed approval belongs to the same
        // completed operation without storing the raw idempotency key.
        consuming_owner_hash: consumingOwnerHash ?? null,
      })
      .where(
        and(
          eq(intentApprovals.id, id),
          consumingOwnerHash
            ? and(
                eq(intentApprovals.status, 'consuming'),
                eq(intentApprovals.consuming_owner_hash, consumingOwnerHash),
              )
            : or(
                eq(intentApprovals.status, 'approved'),
                and(
                  eq(intentApprovals.status, 'consuming'),
                  isNull(intentApprovals.consuming_owner_hash),
                ),
              ),
        ),
      )
      .returning({ id: intentApprovals.id });
    return result.length > 0;
  }

  /**
   * CAS approved -> consuming. This is the single-winner ADMIT for a concurrent
   * world: two requests presenting the same approval both used to read
   * status='approved', both dispatch, and only the post-success consume raced -
   * so a human approving ONE action got as many as the agent could start before
   * the first finished (the threat model, cell
   * approval.consume-is-racy). Reserving atomically at admit means exactly one
   * caller proceeds; the losers get false and are denied.
   */
  async markReserved(
    id: string,
    consumingOwnerHash?: string,
    transaction?: IntentApprovalTransaction,
  ): Promise<boolean> {
    const result = await (transaction ?? this.db)
      .update(intentApprovals)
      .set({ status: 'consuming', consuming_owner_hash: consumingOwnerHash ?? null })
      .where(and(eq(intentApprovals.id, id), eq(intentApprovals.status, 'approved'), gt(intentApprovals.expires_at, new Date())))
      .returning({ id: intentApprovals.id });
    return result.length > 0;
  }

  /**
   * CAS consuming -> approved. The reservation is released when the reserved
   * call did NOT complete successfully, so a transient failure does not burn a
   * human's approval - the retry-on-failure contract the direct consume had.
   */
  async releaseReservation(id: string, consumingOwnerHash?: string): Promise<boolean> {
    const result = await this.db
      .update(intentApprovals)
      .set({ status: 'approved', consuming_owner_hash: null })
      .where(and(
        eq(intentApprovals.id, id),
        consumingOwnerHash
          ? and(
              eq(intentApprovals.status, 'consuming'),
              eq(intentApprovals.consuming_owner_hash, consumingOwnerHash),
            )
          : and(
              eq(intentApprovals.status, 'consuming'),
              isNull(intentApprovals.consuming_owner_hash),
            ),
      ))
      .returning({ id: intentApprovals.id });
    return result.length > 0;
  }

  /**
   * The worker's sweep. Flips pending rows whose `expires_at` has passed to
   * status='expired'. Returns the count swept. Idempotent — calling
   * repeatedly is safe.
   */
  /**
   * Pending rows whose `expires_at` has passed become `expired`, at most `limit` at a time, and are returned so the agent
   * waiting on each can be told. A row another machine expired first is not returned here.
   */
  async expirePending(now: Date, limit: number): Promise<Array<{ id: string; operator_id: string; agent_id: string; fleet_policy_id: string | null }>> {
    const due = this.db
      .select({ id: intentApprovals.id })
      .from(intentApprovals)
      .where(and(eq(intentApprovals.status, 'pending'), lte(intentApprovals.expires_at, now)))
      .limit(limit);
    return this.db
      .update(intentApprovals)
      .set({ status: 'expired' })
      .where(and(inArray(intentApprovals.id, due), eq(intentApprovals.status, 'pending'), lte(intentApprovals.expires_at, now)))
      .returning({
        id: intentApprovals.id,
        operator_id: intentApprovals.operator_id,
        agent_id: intentApprovals.agent_id,
        fleet_policy_id: intentApprovals.fleet_policy_id,
      });
  }

  async sweepExpired(now: Date = new Date()) {
    const result = await this.db
      .update(intentApprovals)
      .set({ status: 'expired' })
      .where(and(eq(intentApprovals.status, 'pending'), lte(intentApprovals.expires_at, now)))
      .returning({ id: intentApprovals.id });
    return result.length;
  }
}
