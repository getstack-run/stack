import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createDb,
  oauthClients,
  oauthRefreshTokens,
  operators,
  OAUTH_FAMILY_REVOKED_KEY,
} from '@stack/shared';
import { eq } from 'drizzle-orm';
import { env } from '../config/env.js';
import { hashToken } from './oauth-helpers.js';
import { registerOAuthRoutes } from './oauth.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('OAuth refresh route failure paths', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_oauth_route_${suffix}`;
  const clientId = `oclient_oauth_route_${suffix}`;
  const auditWrite = vi.fn(async () => {});
  const securityRecord = vi.fn(async () => null);
  const redisSet = vi.fn(async () => { throw new Error('Redis unavailable'); });
  const kmsEncrypt = vi.fn(async () => { throw new Error('KMS unavailable'); });
  const app = Fastify();
  const previousOAuthEnabled = env.OAUTH_ENABLED;

  beforeAll(async () => {
    (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = 'true';
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@oauth-test.invalid`,
      tier: 'business',
      api_key_hash: `hash_${suffix}`,
    } as typeof operators.$inferInsert);
    await db.insert(oauthClients).values({
      id: clientId,
      client_type: 'public',
      client_name: 'OAuth route test',
      redirect_uris: ['http://127.0.0.1/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      operator_id: operatorId,
    });
    registerOAuthRoutes(app, {
      db,
      kms: { encrypt: kmsEncrypt },
      redis: { set: redisSet },
      audit: { write: auditWrite },
      securityEvent: { record: securityRecord },
      analytics: { fireOnce: vi.fn() },
    } as never);
    await app.ready();
  });

  afterAll(async () => {
    (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = previousOAuthEnabled;
    await app.close();
    await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
    await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  it('revokes the full family and still audits when Redis fails', async () => {
    const parent = `rt_${Buffer.from(`route-parent-${suffix}`).toString('base64url')}`;
    const child = `rt_${Buffer.from(`route-child-${suffix}`).toString('base64url')}`;
    const familyId = `rfam_route_revoke_${suffix}`;
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: hashToken(parent), token_family_id: familyId, client_id: clientId,
        operator_id: operatorId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        expires_at: new Date(Date.now() + 60_000), replaced_by_hash: hashToken(child),
        replacement_token_encrypted: 'kms-parent',
        replacement_retry_expires_at: new Date(Date.now() + 60_000),
      },
      {
        token_hash: hashToken(child), token_family_id: familyId, client_id: clientId,
        operator_id: operatorId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        expires_at: new Date(Date.now() + 60_000),
      },
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ token: child }).toString(),
    });

    expect(response.statusCode).toBe(200);
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, familyId),
    });
    expect(family.every((row) => row.revoked_reason === 'logout')).toBe(true);
    expect(redisSet).toHaveBeenCalledWith(OAUTH_FAMILY_REVOKED_KEY(familyId), '1', 'EX', 3600);
    expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({ action: 'oauth.token_revoke' }));
  });

  it('records the critical replay event after the Redis write fails', async () => {
    const parent = `rt_${Buffer.from(`route-replay-parent-${suffix}`).toString('base64url')}`;
    const child = `rt_${Buffer.from(`route-replay-child-${suffix}`).toString('base64url')}`;
    const familyId = `rfam_route_replay_${suffix}`;
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: hashToken(parent), token_family_id: familyId, client_id: clientId,
        operator_id: operatorId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        expires_at: new Date(Date.now() + 60_000), replaced_by_hash: hashToken(child),
        replacement_token_encrypted: 'kms-parent',
        replacement_retry_expires_at: new Date(Date.now() - 1),
        last_used_ip: '127.0.0.1', last_used_ua: 'route-test',
      },
      {
        token_hash: hashToken(child), token_family_id: familyId, client_id: clientId,
        operator_id: operatorId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        expires_at: new Date(Date.now() + 60_000),
      },
    ]);

    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'user-agent': 'route-test',
      },
      payload: new URLSearchParams({
        grant_type: 'refresh_token', refresh_token: parent, client_id: clientId,
      }).toString(),
    });

    expect(response.statusCode).toBe(400);
    expect(securityRecord).toHaveBeenCalledWith(expect.objectContaining({
      operatorId,
      signalType: 'oauth_refresh_reuse',
      severity: 'critical',
      metadata: expect.objectContaining({ token_family_id: familyId, reason: 'stale_replay' }),
    }));
  });

  it('maps KMS encryption failure to OAuth 503 without changing the family', async () => {
    const raw = `rt_${Buffer.from(`route-kms-${suffix}`).toString('base64url')}`;
    const familyId = `rfam_route_kms_${suffix}`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: familyId, client_id: clientId,
      operator_id: operatorId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
      expires_at: new Date(Date.now() + 60_000),
    });

    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'refresh_token', refresh_token: raw, client_id: clientId,
      }).toString(),
    });

    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBe('1');
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, familyId),
    });
    expect(family).toHaveLength(1);
    expect(family[0]?.replaced_by_hash).toBeNull();
    expect(family[0]?.revoked_at).toBeNull();
  });
});
