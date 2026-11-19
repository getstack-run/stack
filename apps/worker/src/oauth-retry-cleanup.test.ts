import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createDb,
  oauthClients,
  oauthRefreshTokens,
  operators,
} from '@stack/shared';
import { eq } from 'drizzle-orm';
import {
  cleanupExpiredOAuthRetryCiphertexts,
  createOAuthRetryCleanupGate,
} from './oauth-retry-cleanup.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('OAuth retry ciphertext cleanup', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_oauth_cleanup_${suffix}`;
  const clientId = `oclient_oauth_cleanup_${suffix}`;
  const now = new Date('2026-08-09T22:00:00.000Z');
  const hashes = {
    expired: `expired_${suffix}`,
    future: `future_${suffix}`,
    legacy: `legacy_${suffix}`,
  };

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
      client_name: 'OAuth cleanup test',
      redirect_uris: ['http://127.0.0.1/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      operator_id: operatorId,
    });
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: hashes.expired, token_family_id: `rfam_expired_${suffix}`,
        client_id: clientId, operator_id: operatorId, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(now.getTime() + 60_000),
        replacement_token_encrypted: 'kms-expired',
        replacement_retry_expires_at: new Date(now.getTime() - 1),
      },
      {
        token_hash: hashes.future, token_family_id: `rfam_future_${suffix}`,
        client_id: clientId, operator_id: operatorId, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(now.getTime() + 60_000),
        replacement_token_encrypted: 'kms-future',
        replacement_retry_expires_at: new Date(now.getTime() + 1),
      },
      {
        token_hash: hashes.legacy, token_family_id: `rfam_legacy_${suffix}`,
        client_id: clientId, operator_id: operatorId, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(now.getTime() + 60_000),
        replacement_token_encrypted: 'kms-legacy',
        replacement_retry_expires_at: null,
      },
    ]);
  });

  afterAll(async () => {
    await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
    await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  it('clears only ciphertext with an expired non-null retry deadline', async () => {
    await expect(cleanupExpiredOAuthRetryCiphertexts(db, now)).resolves.toBe(1);
    const rows = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.operator_id, operatorId),
    });
    const byHash = new Map(rows.map((row) => [row.token_hash, row]));
    expect(byHash.get(hashes.expired)?.replacement_token_encrypted).toBeNull();
    expect(byHash.get(hashes.expired)?.replacement_retry_expires_at).toEqual(
      new Date(now.getTime() - 1),
    );
    expect(byHash.get(hashes.future)?.replacement_token_encrypted).toBe('kms-future');
    expect(byHash.get(hashes.legacy)?.replacement_token_encrypted).toBe('kms-legacy');
  });

  it('runs cleanup at most once every five minutes', async () => {
    let calls = 0;
    const maybeCleanup = createOAuthRetryCleanupGate(async () => {
      calls += 1;
      return calls;
    });

    await expect(maybeCleanup(db, new Date(0))).resolves.toBe(1);
    await expect(maybeCleanup(db, new Date(299_999))).resolves.toBe(0);
    await expect(maybeCleanup(db, new Date(300_000))).resolves.toBe(2);
    expect(calls).toBe(2);
  });
});
