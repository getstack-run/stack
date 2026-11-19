// InboundWebhookRepository.
//
// Persistence for the hosted inbound webhook surface. Read paths:
//   - findActiveBySlug — public receiver lookup. (provider, slug) is
//     uniquely indexed AND excludes revoked rows in the query so the
//     receiver can't fire after revoke without an extra check.
//   - findByIdScoped — operator CRUD read; tenant scope enforced via
//     operator_id predicate.
//   - listByOperator — operator dashboard list.
//
// Write paths:
//   - insert — operator create
//   - revoke — soft delete (CAS on revoked_at IS NULL)
//   - bumpCounters — telemetry from the receiver (total_calls + last_used_at,
//     plus total_blocked + last_block_at on block decisions)

import { and, desc, eq, isNull, sql } from 'drizzle-orm';
import { type Database, inboundWebhooks } from '@stack/shared';

export type InboundWebhookRow = typeof inboundWebhooks.$inferSelect;

export interface InsertInboundWebhookInput {
  id: string;
  operator_id: string;
  provider: string;
  slug: string;
  forward_url: string | null;
  webhook_secret_encrypted: string;
  provider_signing_secret_encrypted?: string | null;
  agent_id: string | null;
  generic_config?: InboundWebhookRow['generic_config'];
}

export class InboundWebhookRepository {
  constructor(private db: Database) {}

  async insert(input: InsertInboundWebhookInput): Promise<InboundWebhookRow> {
    const [row] = await this.db
      .insert(inboundWebhooks)
      .values({
        id: input.id,
        operator_id: input.operator_id,
        provider: input.provider,
        slug: input.slug,
        forward_url: input.forward_url,
        webhook_secret_encrypted: input.webhook_secret_encrypted,
        provider_signing_secret_encrypted: input.provider_signing_secret_encrypted ?? null,
        agent_id: input.agent_id,
        generic_config: input.generic_config ?? null,
      })
      .returning();
    if (!row) throw new Error('inbound_webhooks: insert returned no row');
    return row;
  }

  /**
   * Public receiver lookup. Returns the row only when it's active
   * (revoked_at IS NULL). Returning null on revoked means the receiver
   * surfaces 404 — the slug is treated as if it never existed, so
   * timing-attack surface against revoked-vs-never-existed is minimal.
   */
  async findActiveBySlug(provider: string, slug: string): Promise<InboundWebhookRow | null> {
    const row = await this.db.query.inboundWebhooks.findFirst({
      where: and(
        eq(inboundWebhooks.provider, provider),
        eq(inboundWebhooks.slug, slug),
        isNull(inboundWebhooks.revoked_at),
      ),
    });
    return row ?? null;
  }

  async findByIdScoped(id: string, operatorId: string): Promise<InboundWebhookRow | null> {
    const row = await this.db.query.inboundWebhooks.findFirst({
      where: and(eq(inboundWebhooks.id, id), eq(inboundWebhooks.operator_id, operatorId)),
    });
    return row ?? null;
  }

  async listByOperator(operatorId: string): Promise<InboundWebhookRow[]> {
    return this.db.query.inboundWebhooks.findMany({
      where: eq(inboundWebhooks.operator_id, operatorId),
      orderBy: [desc(inboundWebhooks.created_at)],
    });
  }

  /**
   * Soft-delete via CAS on revoked_at. Returns true on the transition;
   * false when the row was already revoked (idempotent repeat call).
   */
  async revoke(id: string, operatorId: string): Promise<boolean> {
    const updated = await this.db
      .update(inboundWebhooks)
      .set({ revoked_at: new Date() })
      .where(
        and(
          eq(inboundWebhooks.id, id),
          eq(inboundWebhooks.operator_id, operatorId),
          isNull(inboundWebhooks.revoked_at),
        ),
      )
      .returning({ id: inboundWebhooks.id });
    return updated.length > 0;
  }

  /**
   * Receiver-side telemetry: bump total_calls + last_used_at, and on a
   * block decision also bump total_blocked + last_block_at. Single
   * UPDATE so concurrent receivers don't race the counter.
   */
  async bumpCounters(id: string, blocked: boolean): Promise<void> {
    const now = new Date();
    if (blocked) {
      await this.db
        .update(inboundWebhooks)
        .set({
          total_calls: sql`${inboundWebhooks.total_calls} + 1`,
          total_blocked: sql`${inboundWebhooks.total_blocked} + 1`,
          last_used_at: now,
          last_block_at: now,
        })
        .where(eq(inboundWebhooks.id, id));
    } else {
      await this.db
        .update(inboundWebhooks)
        .set({
          total_calls: sql`${inboundWebhooks.total_calls} + 1`,
          last_used_at: now,
        })
        .where(eq(inboundWebhooks.id, id));
    }
  }

  /** Swap in a new downstream secret and keep the one it replaces, as of `rotatedAt`, for the grace period. */
  async rotateDownstreamSecret(
    id: string,
    operatorId: string,
    input: { encrypted: string; previousEncrypted: string; rotatedAt: Date },
  ): Promise<boolean> {
    const rows = await this.db
      .update(inboundWebhooks)
      .set({
        webhook_secret_encrypted: input.encrypted,
        webhook_secret_previous_encrypted: input.previousEncrypted,
        webhook_secret_rotated_at: input.rotatedAt,
      })
      .where(and(eq(inboundWebhooks.id, id), eq(inboundWebhooks.operator_id, operatorId), isNull(inboundWebhooks.revoked_at)))
      .returning({ id: inboundWebhooks.id });
    return rows.length > 0;
  }

  async setProviderSigningSecret(id: string, operatorId: string, encrypted: string, provider: string = 'agentmail', downstreamEncrypted?: string): Promise<boolean> {
    const rows = await this.db.update(inboundWebhooks).set({
      provider_signing_secret_encrypted: encrypted,
      ...(downstreamEncrypted !== undefined
        ? { webhook_secret_encrypted: downstreamEncrypted, webhook_secret_previous_encrypted: null, webhook_secret_rotated_at: null }
        : {}),
    })
      .where(and(eq(inboundWebhooks.id, id), eq(inboundWebhooks.operator_id, operatorId),
        eq(inboundWebhooks.provider, provider), isNull(inboundWebhooks.revoked_at)))
      .returning({ id: inboundWebhooks.id });
    return rows.length > 0;
  }
}
