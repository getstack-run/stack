import { randomUUID } from 'node:crypto';
import { and, eq, lt, or, sql } from 'drizzle-orm';
import { type Database, inboundWebhookReceipts, inboundWebhooks } from '@stack/shared';

const LEASE_SECONDS = 120;
export type InboundReceiptClaim =
  | { state: 'completed' | 'busy' | 'conflict' }
  | { state: 'acquired'; attemptId: string; firstSeenAt: Date; metered: boolean; scanVerdict: 'clean' | 'warning' | null };

/** Durable delivery state. Every mutation is fenced by the processing attempt. */
export class InboundWebhookReceiptsRepository {
  constructor(private db: Database) {}

  async claim(webhookId: string, messageId: string, bodyHash: string): Promise<InboundReceiptClaim> {
    return this.db.transaction(async (tx) => {
      await tx.insert(inboundWebhookReceipts).values({
        webhook_id: webhookId, provider_message_id: messageId, body_hash: bodyHash, state: 'pending',
      }).onConflictDoNothing();
      const [receipt] = await tx.select().from(inboundWebhookReceipts).where(and(
        eq(inboundWebhookReceipts.webhook_id, webhookId), eq(inboundWebhookReceipts.provider_message_id, messageId),
      )).for('update');
      if (!receipt) throw new Error('Inbound delivery receipt is unavailable');
      if (receipt.body_hash && receipt.body_hash !== bodyHash) return { state: 'conflict' };
      if (receipt.state === 'completed') return { state: 'completed' };
      const attemptId = randomUUID();
      const claimed = await tx.update(inboundWebhookReceipts).set({
        state: 'processing', attempt_id: attemptId,
        lease_expires_at: sql`now() + ${LEASE_SECONDS} * interval '1 second'`,
      }).where(and(
        eq(inboundWebhookReceipts.webhook_id, webhookId), eq(inboundWebhookReceipts.provider_message_id, messageId),
        or(eq(inboundWebhookReceipts.state, 'pending'), and(eq(inboundWebhookReceipts.state, 'processing'),
          lt(inboundWebhookReceipts.lease_expires_at, sql`now()`))),
      )).returning({ id: inboundWebhookReceipts.webhook_id });
      if (!claimed.length) return { state: 'busy' };
      return { state: 'acquired', attemptId, firstSeenAt: receipt.seen_at, metered: receipt.metered_at !== null,
        scanVerdict: receipt.scan_verdict === 'clean' || receipt.scan_verdict === 'warning' ? receipt.scan_verdict : null };
    });
  }

  private owns(webhookId: string, messageId: string, attemptId: string) {
    return and(eq(inboundWebhookReceipts.webhook_id, webhookId),
      eq(inboundWebhookReceipts.provider_message_id, messageId), eq(inboundWebhookReceipts.attempt_id, attemptId),
      eq(inboundWebhookReceipts.state, 'processing'), sql`${inboundWebhookReceipts.lease_expires_at} > now()`);
  }

  async renew(webhookId: string, messageId: string, attemptId: string): Promise<boolean> {
    const rows = await this.db.update(inboundWebhookReceipts)
      .set({ lease_expires_at: sql`now() + ${LEASE_SECONDS} * interval '1 second'` })
      .where(this.owns(webhookId, messageId, attemptId)).returning({ id: inboundWebhookReceipts.webhook_id });
    return rows.length > 0;
  }

  async markMetered(webhookId: string, messageId: string, attemptId: string): Promise<boolean> {
    const rows = await this.db.update(inboundWebhookReceipts).set({ metered_at: sql`now()` })
      .where(this.owns(webhookId, messageId, attemptId)).returning({ id: inboundWebhookReceipts.webhook_id });
    return rows.length > 0;
  }

  async markScanned(webhookId: string, messageId: string, attemptId: string, verdict: 'clean' | 'warning'): Promise<boolean> {
    const rows = await this.db.update(inboundWebhookReceipts).set({ scan_verdict: verdict })
      .where(this.owns(webhookId, messageId, attemptId)).returning({ id: inboundWebhookReceipts.webhook_id });
    return rows.length > 0;
  }

  async release(webhookId: string, messageId: string, attemptId: string): Promise<boolean> {
    const rows = await this.db.update(inboundWebhookReceipts).set({ state: 'pending', attempt_id: null, lease_expires_at: null })
      .where(and(eq(inboundWebhookReceipts.webhook_id, webhookId), eq(inboundWebhookReceipts.provider_message_id, messageId),
        eq(inboundWebhookReceipts.attempt_id, attemptId), eq(inboundWebhookReceipts.state, 'processing')))
      .returning({ id: inboundWebhookReceipts.webhook_id });
    return rows.length > 0;
  }

  /** Receipt completion and logical-delivery counters commit together. */
  async complete(webhookId: string, messageId: string, attemptId: string, blocked: boolean): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      const rows = await tx.update(inboundWebhookReceipts).set({
        state: 'completed', completed_at: sql`now()`, attempt_id: null, lease_expires_at: null,
      }).where(this.owns(webhookId, messageId, attemptId)).returning({ id: inboundWebhookReceipts.webhook_id });
      if (!rows.length) return false;
      await tx.update(inboundWebhooks).set({ total_calls: sql`${inboundWebhooks.total_calls} + 1`, last_used_at: sql`now()`,
        ...(blocked ? { total_blocked: sql`${inboundWebhooks.total_blocked} + 1`, last_block_at: sql`now()` } : {}),
      }).where(eq(inboundWebhooks.id, webhookId));
      return true;
    });
  }

  /** Failed and in-progress deliveries remain recoverable; only completed history expires. */
  async sweepOlderThan(cutoff: Date): Promise<number> {
    const rows = await this.db.delete(inboundWebhookReceipts).where(and(eq(inboundWebhookReceipts.state, 'completed'),
      sql`coalesce(${inboundWebhookReceipts.completed_at}, ${inboundWebhookReceipts.seen_at}) < ${cutoff.toISOString()}::timestamptz`,
    )).returning({ id: inboundWebhookReceipts.webhook_id });
    return rows.length;
  }

  async exists(webhookId: string, messageId: string): Promise<boolean> {
    const receipt = await this.db.query.inboundWebhookReceipts.findFirst({ where: and(
      eq(inboundWebhookReceipts.webhook_id, webhookId), eq(inboundWebhookReceipts.provider_message_id, messageId),
    ) });
    return receipt !== undefined;
  }
}
