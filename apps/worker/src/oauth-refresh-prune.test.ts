import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDb, oauthClients, oauthRefreshTokens, operators } from '@stack/shared';
import { eq } from 'drizzle-orm';
import {
  OAUTH_REFRESH_PRUNE_BATCH,
  OAUTH_REFRESH_RETENTION_MS,
  createOAuthRefreshPruneGate,
  pruneExpiredOAuthRefreshTokens,
} from './oauth-retry-cleanup.js';

// A refresh writes one new row and keeps the old one for reuse detection, so
// the table only ever grows. An old row is useful until its own expiry (a
// replay after that is refused as expired); the sweep removes rows that
// expired more than a week ago, and nothing else.

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describe('OAuth refresh-token retention', () => {
  it('keeps a week after expiry and prunes in bounded batches', () => {
    expect(OAUTH_REFRESH_RETENTION_MS).toBe(7 * 24 * 60 * 60 * 1000);
    expect(OAUTH_REFRESH_PRUNE_BATCH).toBeGreaterThan(0);
    expect(OAUTH_REFRESH_PRUNE_BATCH).toBeLessThanOrEqual(5_000);
  });

  it('runs at most once an hour', async () => {
    let calls = 0;
    const gate = createOAuthRefreshPruneGate(async () => {
      calls += 1;
      return calls;
    });
    await expect(gate(null as never, new Date(0))).resolves.toBe(1);
    await expect(gate(null as never, new Date(3_599_999))).resolves.toBe(0);
    await expect(gate(null as never, new Date(3_600_000))).resolves.toBe(2);
    expect(calls).toBe(2);
  });
});

describeWithDb('OAuth refresh-token pruning', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_oauth_prune_${suffix}`;
  const clientId = `oclient_oauth_prune_${suffix}`;
  const now = new Date('2026-01-15T12:00:00.000Z');
  const day = 24 * 60 * 60 * 1000;
  const hash = (name: string) => `prune_${name}_${suffix}`;

  const row = (name: string, family: string, expiresAt: Date, extra: Partial<typeof oauthRefreshTokens.$inferInsert> = {}) => ({
    token_hash: hash(name),
    token_family_id: `rfam_${family}_${suffix}`,
    client_id: clientId,
    operator_id: operatorId,
    scope: 'agents:read',
    resource: 'https://mcp.getstack.run/mcp',
    expires_at: expiresAt,
    ...extra,
  });

  const remaining = async () => new Set(
    (await db.select({ hash: oauthRefreshTokens.token_hash }).from(oauthRefreshTokens)
      .where(eq(oauthRefreshTokens.operator_id, operatorId))).map((r) => r.hash),
  );

  beforeAll(async () => {
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@oauth-test.invalid`,
      tier: 'business',
      api_key_hash: `hash_${suffix}`,
    } as typeof operators.$inferInsert);
    await db.insert(oauthClients).values({
      id: clientId,
      client_type: 'public',
      client_name: 'OAuth prune test',
      redirect_uris: ['http://127.0.0.1/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      operator_id: operatorId,
    });
    await db.insert(oauthRefreshTokens).values([
      // One family refreshed many times, all expired long ago: every row goes.
      row('old_parent', 'old', new Date(now.getTime() - 40 * day), { replaced_by_hash: hash('old_head') }),
      row('old_head', 'old', new Date(now.getTime() - 10 * day)),
      // A live family: an old rotated parent, expired 8 days ago, and the live head.
      row('live_parent', 'live', new Date(now.getTime() - 8 * day), { replaced_by_hash: hash('live_head') }),
      row('live_head', 'live', new Date(now.getTime() + 20 * day)),
      // Expired inside the retention week: kept, so a replay is still told apart.
      row('recent_expired', 'recent', new Date(now.getTime() - 6 * day)),
      // A family revoked for reuse but still inside its expiry: kept (it holds the revocation).
      row('revoked_live', 'revoked', new Date(now.getTime() + 5 * day), { revoked_at: now, revoked_reason: 'reuse_detected' }),
      // Expired a week and a minute ago, revoked: goes.
      row('revoked_old', 'revokedold', new Date(now.getTime() - 7 * day - 60_000), { revoked_at: new Date(now.getTime() - 20 * day), revoked_reason: 'logout' }),
    ]);
  });

  afterAll(async () => {
    await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
    await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  it('deletes only rows that expired more than a week ago, whatever their state', async () => {
    const pruned = await pruneExpiredOAuthRefreshTokens(db, now);
    expect(pruned).toBeGreaterThanOrEqual(4);
    expect(await remaining()).toEqual(new Set([hash('live_head'), hash('recent_expired'), hash('revoked_live')]));
  });

  it('does nothing the second time, and never touches a row at exactly the retention edge', async () => {
    await db.insert(oauthRefreshTokens).values(row('edge', 'edge', new Date(now.getTime() - 7 * day)));
    await expect(pruneExpiredOAuthRefreshTokens(db, now)).resolves.toBe(0);
    expect((await remaining()).has(hash('edge'))).toBe(true);
    await expect(pruneExpiredOAuthRefreshTokens(db, new Date(now.getTime() + 1_000))).resolves.toBe(1);
  });

  it('works through a backlog larger than one batch within a single run', async () => {
    const many = Array.from({ length: 25 }, (_, i) => row(`bulk_${i}`, `bulk${i}`, new Date(now.getTime() - 30 * day)));
    await db.insert(oauthRefreshTokens).values(many);
    const pruned = await pruneExpiredOAuthRefreshTokens(db, now, { batchSize: 10 });
    expect(pruned).toBe(25);
    const left = await remaining();
    expect([...left].some((h) => h.startsWith('prune_bulk_'))).toBe(false);
  });
});
