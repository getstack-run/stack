// Rows behind the control socket: the customer's choice of decider and
// addresses (control_sockets), every decision (control_decisions) and the
// record waiting to be delivered (control_event_outbox).
//
// Delivery timing (leases, backoff, ages) runs on the database clock, never a
// machine's, so two API machines with skewed clocks cannot fight over a batch.

import { and, asc, desc, eq, lt, sql } from 'drizzle-orm';
import {
  controlDecisions,
  controlEventOutbox,
  controlSockets,
  ids,
  type ControlDecisionRow,
  type ControlEventOutboxRow,
  type ControlSocketRow,
  type Database,
} from '@stack/shared';

export type ControlSocketPatch = Partial<Omit<typeof controlSockets.$inferInsert, 'operator_id' | 'socket_id' | 'created_at'>>;
export type ControlDecisionInsert = typeof controlDecisions.$inferInsert;
type Tx = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface OutboxCounts {
  pending: number;
  dead: number;
}

export class ControlSocketRepository {
  constructor(private readonly db: Database) {}

  async get(operatorId: string): Promise<ControlSocketRow | null> {
    const [row] = await this.db.select().from(controlSockets).where(eq(controlSockets.operator_id, operatorId)).limit(1);
    return row ?? null;
  }

  /** The customer's socket row, created with its id on first use. */
  async getOrCreate(operatorId: string): Promise<ControlSocketRow> {
    await this.db
      .insert(controlSockets)
      .values({ operator_id: operatorId, socket_id: ids.controlSocket() })
      .onConflictDoNothing();
    const row = await this.get(operatorId);
    if (!row) throw new Error('Control socket row missing after insert');
    return row;
  }

  async update(operatorId: string, patch: ControlSocketPatch): Promise<ControlSocketRow> {
    const [row] = await this.db
      .update(controlSockets)
      .set({ ...patch, updated_at: new Date() })
      .where(eq(controlSockets.operator_id, operatorId))
      .returning();
    if (!row) throw new Error('Control socket row missing');
    return row;
  }

  /**
   * Count one answer that failed its signature check, or reset the count on a
   * good one. Returns the count after the change. The socket pauses at 50 in a
   * row (set by the caller from the returned count).
   */
  async countBadAnswer(operatorId: string, good: boolean): Promise<number> {
    const [row] = await this.db
      .update(controlSockets)
      .set(good ? { decision_bad_answers: 0 } : { decision_bad_answers: sql`${controlSockets.decision_bad_answers} + 1` })
      .where(eq(controlSockets.operator_id, operatorId))
      .returning({ count: controlSockets.decision_bad_answers });
    return row?.count ?? 0;
  }

  // ─── decisions ──────────────────────────────────────────────────

  async insertDecision(row: ControlDecisionInsert): Promise<void> {
    await this.db.insert(controlDecisions).values(row).onConflictDoNothing();
  }

  async listDecisions(
    operatorId: string,
    query: { limit: number; accountId?: string; verdict?: string; before?: Date },
  ): Promise<ControlDecisionRow[]> {
    const conditions = [eq(controlDecisions.operator_id, operatorId)];
    if (query.accountId) conditions.push(eq(controlDecisions.account_id, query.accountId));
    if (query.verdict) conditions.push(eq(controlDecisions.verdict, query.verdict));
    if (query.before) conditions.push(lt(controlDecisions.created_at, query.before));
    return this.db
      .select()
      .from(controlDecisions)
      .where(and(...conditions))
      .orderBy(desc(controlDecisions.created_at), desc(controlDecisions.id))
      .limit(query.limit);
  }

  async getDecision(operatorId: string, id: string): Promise<ControlDecisionRow | null> {
    const [row] = await this.db
      .select()
      .from(controlDecisions)
      .where(and(eq(controlDecisions.operator_id, operatorId), eq(controlDecisions.id, id)))
      .limit(1);
    return row ?? null;
  }

  /** Drop the stored request of old refusals, and the whole row of very old decisions. */
  async pruneDecisions(requestDays: number, rowDays: number): Promise<{ requestsCleared: number; rowsDeleted: number }> {
    const cleared = await this.db
      .update(controlDecisions)
      .set({ request: null })
      .where(sql`${controlDecisions.request} IS NOT NULL AND ${controlDecisions.created_at} < now() - make_interval(days => ${requestDays})`)
      .returning({ id: controlDecisions.id });
    const deleted = await this.db
      .delete(controlDecisions)
      .where(sql`${controlDecisions.created_at} < now() - make_interval(days => ${rowDays})`)
      .returning({ id: controlDecisions.id });
    return { requestsCleared: cleared.length, rowsDeleted: deleted.length };
  }

  // ─── event outbox ───────────────────────────────────────────────

  /**
   * Take the next sequence number for a customer's events and insert the event
   * under it, inside the transaction that writes the audit row it describes.
   * The caller holds the operator's audit lock, so numbers are gapless and in
   * the order of the chain. Returns null (and writes nothing) when the
   * customer has no events address delivering.
   *
   * An address that has stopped delivering (`failing`) still takes its number
   * but stores nothing: nobody is draining the outbox, so keeping rows would
   * grow it without bound. The numbers it skipped are announced by one gap
   * marker when the address is verified again (`activateEvents`).
   */
  async enqueue(
    tx: Tx,
    operatorId: string,
    entryId: string,
    buildEvent: (seq: number) => Record<string, unknown>,
  ): Promise<number | null> {
    const [taken] = await tx
      .update(controlSockets)
      .set({ events_last_seq: sql`${controlSockets.events_last_seq} + 1` })
      .where(and(eq(controlSockets.operator_id, operatorId), sql`${controlSockets.events_status} IN ('active', 'failing')`))
      .returning({ seq: controlSockets.events_last_seq, status: controlSockets.events_status });
    if (!taken) return null;
    if (taken.status === 'failing') return taken.seq;
    await tx.insert(controlEventOutbox).values({
      operator_id: operatorId,
      seq: taken.seq,
      entry_id: entryId,
      event: buildEvent(taken.seq),
    });
    return taken.seq;
  }

  /**
   * Lease the sockets that are due: active, with events not yet acknowledged,
   * not leased, and past their retry time. One machine at a time per socket,
   * which keeps delivery in order.
   */
  async claimDue(leaseSeconds: number, limit: number, operatorId?: string): Promise<ControlSocketRow[]> {
    const claimed = await this.db.execute(sql`
      UPDATE control_sockets
      SET events_lease_until = now() + make_interval(secs => ${leaseSeconds})
      WHERE operator_id IN (
        SELECT operator_id FROM control_sockets
        WHERE events_status = 'active'
          AND events_acked_seq < events_last_seq
          ${operatorId ? sql`AND operator_id = ${operatorId}` : sql``}
          AND (events_lease_until IS NULL OR events_lease_until < now())
          AND (events_next_attempt_at IS NULL OR events_next_attempt_at <= now())
        ORDER BY events_next_attempt_at NULLS FIRST, operator_id
        LIMIT ${limit}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING operator_id
    `) as unknown as Array<{ operator_id: string }>;
    const rows: ControlSocketRow[] = [];
    for (const { operator_id } of claimed) {
      const row = await this.get(operator_id);
      if (row) rows.push(row);
    }
    return rows;
  }

  async releaseLease(operatorId: string): Promise<void> {
    await this.db.update(controlSockets).set({ events_lease_until: null }).where(eq(controlSockets.operator_id, operatorId));
  }

  /** Pending events past their retention become dead, to be announced by one gap marker. */
  async expireStale(operatorId: string, days: number): Promise<number> {
    const expired = await this.db
      .update(controlEventOutbox)
      .set({ status: 'dead' })
      .where(
        and(
          eq(controlEventOutbox.operator_id, operatorId),
          eq(controlEventOutbox.status, 'pending'),
          sql`${controlEventOutbox.created_at} < now() - make_interval(days => ${days})`,
        ),
      )
      .returning({ seq: controlEventOutbox.seq });
    return expired.length;
  }

  /** The next batch: dead events not yet announced that precede it, then the pending ones, in order. */
  async nextBatch(operatorId: string, maxEvents: number): Promise<{
    dead: ControlEventOutboxRow[];
    pending: ControlEventOutboxRow[];
  }> {
    const dead = await this.db
      .select()
      .from(controlEventOutbox)
      .where(
        and(
          eq(controlEventOutbox.operator_id, operatorId),
          eq(controlEventOutbox.status, 'dead'),
          eq(controlEventOutbox.gap_announced, false),
        ),
      )
      .orderBy(asc(controlEventOutbox.seq))
      .limit(maxEvents);
    const pending = await this.db
      .select()
      .from(controlEventOutbox)
      .where(and(eq(controlEventOutbox.operator_id, operatorId), eq(controlEventOutbox.status, 'pending')))
      .orderBy(asc(controlEventOutbox.seq))
      .limit(maxEvents);
    return { dead, pending };
  }

  /** A batch was acknowledged: its rows are deleted and the cursor moves. */
  async acknowledge(operatorId: string, input: { throughSeq: number; deadSeqs: number[] }): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx
        .delete(controlEventOutbox)
        .where(
          and(
            eq(controlEventOutbox.operator_id, operatorId),
            eq(controlEventOutbox.status, 'pending'),
            sql`${controlEventOutbox.seq} <= ${input.throughSeq}`,
          ),
        );
      if (input.deadSeqs.length > 0) {
        await tx
          .update(controlEventOutbox)
          .set({ gap_announced: true })
          .where(
            and(
              eq(controlEventOutbox.operator_id, operatorId),
              eq(controlEventOutbox.status, 'dead'),
              sql`${controlEventOutbox.seq} IN (${sql.join(input.deadSeqs.map((s) => sql`${s}`), sql`, `)})`,
            ),
          );
      }
      await tx
        .update(controlSockets)
        .set({
          events_acked_seq: sql`GREATEST(${controlSockets.events_acked_seq}, ${input.throughSeq})`,
          events_attempts: 0,
          events_client_errors: 0,
          events_first_failure_at: null,
          events_next_attempt_at: null,
          events_last_error: null,
          events_lease_until: null,
        })
        .where(eq(controlSockets.operator_id, operatorId));
      // A delivered gap marker is kept for a week as the receipt of what was lost.
      await tx
        .delete(controlEventOutbox)
        .where(
          and(
            eq(controlEventOutbox.operator_id, operatorId),
            eq(controlEventOutbox.status, 'dead'),
            eq(controlEventOutbox.gap_announced, true),
            sql`${controlEventOutbox.created_at} < now() - make_interval(days => 7)`,
          ),
        );
    });
  }

  /**
   * A delivery failed in a way worth retrying: back off, and note when it began.
   * Only an active socket is touched, so `failing: true` is the one call that
   * moved it into `failing`, and the owner is told exactly once per outage.
   */
  async recordRetry(
    operatorId: string,
    input: { backoffMs: number; error: string; giveUpAfterMs: number },
  ): Promise<{ failing: boolean }> {
    const [row] = await this.db
      .update(controlSockets)
      .set({
        events_attempts: sql`${controlSockets.events_attempts} + 1`,
        events_first_failure_at: sql`COALESCE(${controlSockets.events_first_failure_at}, now())`,
        events_next_attempt_at: sql`now() + make_interval(secs => ${input.backoffMs / 1000})`,
        events_last_error: input.error,
        events_lease_until: null,
        events_status: sql`CASE WHEN COALESCE(${controlSockets.events_first_failure_at}, now()) < now() - make_interval(secs => ${input.giveUpAfterMs / 1000}) THEN 'failing' ELSE ${controlSockets.events_status} END`,
      })
      .where(and(eq(controlSockets.operator_id, operatorId), eq(controlSockets.events_status, 'active')))
      .returning({ status: controlSockets.events_status });
    return { failing: row?.status === 'failing' };
  }

  /** The customer's server refused a batch (a 4xx other than 408 and 429). Returns the refusals in a row. */
  async recordClientError(operatorId: string, error: string): Promise<number> {
    const [row] = await this.db
      .update(controlSockets)
      .set({
        events_client_errors: sql`${controlSockets.events_client_errors} + 1`,
        events_last_error: error,
        events_lease_until: null,
        events_next_attempt_at: sql`now() + make_interval(secs => 1)`,
      })
      .where(eq(controlSockets.operator_id, operatorId))
      .returning({ count: controlSockets.events_client_errors });
    return row?.count ?? 0;
  }

  /** A batch refused too often: its pending events become dead, and one gap marker will announce them. */
  async markBatchDead(operatorId: string, throughSeq: number): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx
        .update(controlEventOutbox)
        .set({ status: 'dead' })
        .where(
          and(
            eq(controlEventOutbox.operator_id, operatorId),
            eq(controlEventOutbox.status, 'pending'),
            sql`${controlEventOutbox.seq} <= ${throughSeq}`,
          ),
        );
      await tx
        .update(controlSockets)
        .set({ events_client_errors: 0, events_next_attempt_at: null, events_lease_until: null })
        .where(eq(controlSockets.operator_id, operatorId));
    });
  }

  /**
   * The events address passed its setup check: delivery starts. Done under the
   * socket's row lock so no audit write takes a number in between. Numbers a
   * paused (`failing`) address took without storing are announced by one dead
   * row carrying their range, which the next batch turns into a gap marker.
   */
  async activateEvents(operatorId: string, patch: ControlSocketPatch): Promise<{ gap: { fromSeq: number; toSeq: number } | null }> {
    return this.db.transaction(async (tx) => {
      const [locked] = await tx
        .select()
        .from(controlSockets)
        .where(eq(controlSockets.operator_id, operatorId))
        .for('update')
        .limit(1);
      if (!locked) throw new Error('Control socket row missing');
      const [stored] = await tx
        .select({ top: sql<number>`COALESCE(MAX(${controlEventOutbox.seq}), 0)::bigint` })
        .from(controlEventOutbox)
        .where(eq(controlEventOutbox.operator_id, operatorId));
      const fromSeq = Math.max(Number(stored?.top ?? 0), Number(locked.events_acked_seq)) + 1;
      const toSeq = Number(locked.events_last_seq);
      await tx.update(controlSockets).set({ ...patch, updated_at: new Date() }).where(eq(controlSockets.operator_id, operatorId));
      if (toSeq < fromSeq) return { gap: null };
      await tx.insert(controlEventOutbox).values({
        operator_id: operatorId,
        seq: toSeq,
        entry_id: `gap_${fromSeq}_${toSeq}`,
        event: { gap: { from_seq: fromSeq, to_seq: toSeq } },
        status: 'dead',
      });
      return { gap: { fromSeq, toSeq } };
    });
  }

  /** The customer took their events address away: nothing is left to deliver. */
  async clearOutbox(operatorId: string): Promise<void> {
    await this.db.delete(controlEventOutbox).where(eq(controlEventOutbox.operator_id, operatorId));
  }

  /**
   * Retention for every customer, whether or not their socket is being
   * delivered: pending events past their age become dead. Delivery does the same
   * for the sockets it claims, but a paused or cleared socket is never claimed.
   */
  async expireAllStale(days: number): Promise<number> {
    const expired = await this.db
      .update(controlEventOutbox)
      .set({ status: 'dead' })
      .where(and(eq(controlEventOutbox.status, 'pending'), sql`${controlEventOutbox.created_at} < now() - make_interval(days => ${days})`))
      .returning({ seq: controlEventOutbox.seq });
    return expired.length;
  }

  /**
   * For a socket nobody is delivering (paused, unverified or off), fold its
   * unannounced dead events into one row carrying their range, so what is kept
   * for a gap marker never grows with the length of the outage. A socket being
   * delivered is left alone: its batches are announcing those rows now.
   */
  async compactDead(): Promise<number> {
    const targets = await this.db.execute(sql`
      SELECT o.operator_id
      FROM control_event_outbox o
      JOIN control_sockets s ON s.operator_id = o.operator_id
      WHERE o.status = 'dead' AND o.gap_announced = false AND s.events_status <> 'active'
      GROUP BY o.operator_id
      HAVING count(*) > 1
      LIMIT 200
    `) as unknown as Array<{ operator_id: string }>;
    let folded = 0;
    for (const { operator_id: operatorId } of targets) {
      await this.db.transaction(async (tx) => {
        const [socket] = await tx.select().from(controlSockets).where(eq(controlSockets.operator_id, operatorId)).for('update').limit(1);
        if (!socket || socket.events_status === 'active') return;
        const dead = await tx
          .select({ seq: controlEventOutbox.seq, event: controlEventOutbox.event })
          .from(controlEventOutbox)
          .where(and(eq(controlEventOutbox.operator_id, operatorId), eq(controlEventOutbox.status, 'dead'), eq(controlEventOutbox.gap_announced, false)))
          .orderBy(asc(controlEventOutbox.seq));
        if (dead.length < 2) return;
        const [pending] = await tx
          .select({ first: sql<number | null>`MIN(${controlEventOutbox.seq})` })
          .from(controlEventOutbox)
          .where(and(eq(controlEventOutbox.operator_id, operatorId), eq(controlEventOutbox.status, 'pending')));
        const last = dead[dead.length - 1]!.seq;
        // A pending event inside the range would be announced as lost: leave such a socket as it is.
        if (pending?.first !== null && pending?.first !== undefined && Number(pending.first) < last) return;
        const gap = (dead[0]!.event as { gap?: { from_seq?: number } }).gap;
        const first = gap?.from_seq ?? dead[0]!.seq;
        await tx
          .delete(controlEventOutbox)
          .where(and(eq(controlEventOutbox.operator_id, operatorId), eq(controlEventOutbox.status, 'dead'), eq(controlEventOutbox.gap_announced, false)));
        await tx.insert(controlEventOutbox).values({
          operator_id: operatorId,
          seq: last,
          entry_id: `gap_${first}_${last}`,
          event: { gap: { from_seq: first, to_seq: last } },
          status: 'dead',
        });
        folded += dead.length - 1;
      });
    }
    return folded;
  }

  async outboxCounts(operatorId: string): Promise<OutboxCounts> {
    const rows = await this.db
      .select({ status: controlEventOutbox.status, count: sql<number>`count(*)::int` })
      .from(controlEventOutbox)
      .where(eq(controlEventOutbox.operator_id, operatorId))
      .groupBy(controlEventOutbox.status);
    const count = (status: string) => rows.find((r) => r.status === status)?.count ?? 0;
    return { pending: count('pending'), dead: count('dead') };
  }
}
