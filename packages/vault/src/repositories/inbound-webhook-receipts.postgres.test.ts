import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { and, eq, sql } from 'drizzle-orm';
import { inboundWebhookReceipts, inboundWebhooks, operators, createDb, type Database } from '@stack/shared';
import { InboundWebhookReceiptsRepository } from './inbound-webhook-receipts-repo.js';
import { InboundWebhookRepository } from './inbound-webhook-repo.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

// Allow only the isolated local audit store or the CI service database.
const fixtureUrl = process.env['DATABASE_URL'];
const run = isDedicatedVaultTestDatabase(fixtureUrl) ? describe : describe.skip;
run('durable inbound receipts in isolated PostgreSQL', () => {
  let db: Database;
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_iwh_receipts_${suffix}`;
  const webhookId = `iwh_receipts_${suffix}`;
  let repo: InboundWebhookReceiptsRepository;
  beforeAll(async () => {
    db = createDb(fixtureUrl!);
    repo = new InboundWebhookReceiptsRepository(db);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: `inert-fixture-hash-${suffix}`,
    });
    await db
      .insert(inboundWebhooks)
      .values({
        id: webhookId,
        operator_id: operatorId,
        provider: 'generic',
        slug: `fixture_${suffix}`,
        webhook_secret_encrypted: 'inert-fixture-ciphertext',
      });
  });
  beforeEach(async () => {
    await db.delete(inboundWebhookReceipts).where(eq(inboundWebhookReceipts.webhook_id, webhookId));
    await db
      .update(inboundWebhooks)
      .set({ total_calls: 0, total_blocked: 0 })
      .where(eq(inboundWebhooks.id, webhookId));
  });
  afterAll(async () => {
    if (!db) return;
    await db.delete(inboundWebhooks).where(eq(inboundWebhooks.id, webhookId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.$client.end();
  });
  it('allows one concurrent owner, completes once and counts one logical delivery', async () => {
    const claims = await Promise.all(
      Array.from({ length: 12 }, () => repo.claim(webhookId, 'event', 'body-hash')),
    );
    expect(claims.filter((claim) => claim.state === 'acquired')).toHaveLength(1);
    expect(claims.filter((claim) => claim.state === 'busy')).toHaveLength(11);
    const owner = claims.find((claim) => claim.state === 'acquired');
    if (!owner || owner.state !== 'acquired') throw new Error('fixture has no owner');
    expect(await repo.complete(webhookId, 'event', owner.attemptId, true)).toBe(true);
    expect(await repo.complete(webhookId, 'event', owner.attemptId, true)).toBe(false);
    expect(await repo.release(webhookId, 'event', owner.attemptId)).toBe(false);
    expect(await repo.claim(webhookId, 'event', 'body-hash')).toEqual({ state: 'completed' });
    expect(
      await db.query.inboundWebhooks.findFirst({ where: eq(inboundWebhooks.id, webhookId) }),
    ).toMatchObject({ total_calls: 1, total_blocked: 1 });
  });
  it('updates both AgentMail encrypted keys in one scoped write and never crosses provider or owner', async () => {
    const webhooks = new InboundWebhookRepository(db);
    expect(
      await webhooks.setProviderSigningSecret(
        webhookId,
        operatorId,
        'fixture-provider',
        'agentmail',
        'fixture-downstream',
      ),
    ).toBe(false);
    await db
      .update(inboundWebhooks)
      .set({ provider: 'agentmail' })
      .where(eq(inboundWebhooks.id, webhookId));
    try {
      expect(
        await webhooks.setProviderSigningSecret(
          webhookId,
          'op_other',
          'wrong',
          'agentmail',
          'wrong',
        ),
      ).toBe(false);
      expect(
        await webhooks.setProviderSigningSecret(
          webhookId,
          operatorId,
          'fixture-provider',
          'agentmail',
          'fixture-downstream',
        ),
      ).toBe(true);
      expect(await webhooks.findByIdScoped(webhookId, operatorId)).toMatchObject({
        provider_signing_secret_encrypted: 'fixture-provider',
        webhook_secret_encrypted: 'fixture-downstream',
      });
      expect(
        await webhooks.setProviderSigningSecret(webhookId, operatorId, 'wrong', 'generic'),
      ).toBe(false);
      expect(await webhooks.findByIdScoped(webhookId, operatorId)).toMatchObject({
        provider_signing_secret_encrypted: 'fixture-provider',
        webhook_secret_encrypted: 'fixture-downstream',
      });
    } finally {
      await db
        .update(inboundWebhooks)
        .set({ provider: 'generic' })
        .where(eq(inboundWebhooks.id, webhookId));
    }
  });
  it('recovers expired work and fences every mutation from the stale attempt', async () => {
    const first = await repo.claim(webhookId, 'event', 'body-hash');
    if (first.state !== 'acquired') throw new Error('fixture has no owner');
    expect(await repo.markMetered(webhookId, 'event', first.attemptId)).toBe(true);
    expect(await repo.markScanned(webhookId, 'event', first.attemptId, 'clean')).toBe(true);
    await db
      .update(inboundWebhookReceipts)
      .set({ lease_expires_at: sql`now() - interval '1 second'` })
      .where(eq(inboundWebhookReceipts.webhook_id, webhookId));
    const second = await repo.claim(webhookId, 'event', 'body-hash');
    expect(second).toMatchObject({
      state: 'acquired',
      metered: true,
      scanVerdict: 'clean',
      firstSeenAt: first.firstSeenAt,
    });
    if (second.state !== 'acquired') throw new Error('fixture has no retry owner');
    for (const operation of [
      repo.renew(webhookId, 'event', first.attemptId),
      repo.markMetered(webhookId, 'event', first.attemptId),
      repo.markScanned(webhookId, 'event', first.attemptId, 'warning'),
      repo.release(webhookId, 'event', first.attemptId),
      repo.complete(webhookId, 'event', first.attemptId, false),
    ])
      expect(await operation).toBe(false);
    expect(await repo.complete(webhookId, 'event', second.attemptId, false)).toBe(true);
  });
  it('refuses changed content and preserves pending work during retention sweeps', async () => {
    const claim = await repo.claim(webhookId, 'event', 'body-hash');
    if (claim.state !== 'acquired') throw new Error('fixture has no owner');
    expect(await repo.release(webhookId, 'event', claim.attemptId)).toBe(true);
    expect(await repo.claim(webhookId, 'event', 'different')).toEqual({ state: 'conflict' });
    // Sweep is global, so a past cutoff plus test-owned old timestamps avoids unrelated records.
    const cutoff = new Date('2000-01-01T00:00:00Z');
    await db
      .update(inboundWebhookReceipts)
      .set({ seen_at: new Date('1999-01-01T00:00:00Z') })
      .where(
        and(
          eq(inboundWebhookReceipts.webhook_id, webhookId),
          eq(inboundWebhookReceipts.provider_message_id, 'event'),
        ),
      );
    await repo.sweepOlderThan(cutoff);
    expect(await repo.exists(webhookId, 'event')).toBe(true);
  });
});
