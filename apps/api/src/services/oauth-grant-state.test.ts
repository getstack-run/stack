import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createDb,
  oauthAuthorizationCodes,
  oauthClients,
  oauthDeviceCodes,
  oauthRefreshTokens,
  operatorErasureJobs,
  operators,
  teamMembers,
} from '@stack/shared';
import { eq, sql } from 'drizzle-orm';
import { createHash } from 'node:crypto';
import { hashToken } from '../routes/oauth-helpers.js';
import { registerOAuthRoutes } from '../routes/oauth.js';
import { env } from '../config/env.js';
import {
  MemberRepository,
  MemberService,
  OperatorRepository,
  OperatorService,
} from '@stack/vault';
import {
  consumeApprovedDeviceCode,
  consumeAuthorizationCode,
  decideDeviceCode,
  issueAuthorizationCode,
  revokeRefreshFamilyByToken,
  rotateRefreshGrant,
} from './oauth-grant-state.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('OAuth grant state', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_oauth_concurrency_${suffix}`;
  const clientId = `oclient_oauth_concurrency_${suffix}`;
  const familyId = `rfam_oauth_concurrency_${suffix}`;
  const original = `rt_${Buffer.from(`original-${suffix}`).toString('base64url')}`;

  const kms = {
    async encrypt(plaintext: string, context?: Record<string, string>) {
      return {
        ciphertext: Buffer.from(JSON.stringify({ plaintext, context })).toString('base64'),
        keyRef: 'test-key',
      };
    },
    async decrypt(ciphertext: string, expectedContext?: Record<string, string>) {
      const decoded = JSON.parse(Buffer.from(ciphertext, 'base64').toString('utf8')) as {
        plaintext: string;
        context?: Record<string, string>;
      };
      expect(decoded.context).toEqual(expectedContext);
      return decoded.plaintext;
    },
  };

  async function holdOperatorLock(targetOperatorId: string) {
    let release!: () => void;
    let held!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const heldPromise = new Promise<void>((resolve) => { held = resolve; });
    const lockPromise = db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${targetOperatorId}, 239))`);
      held();
      await releasePromise;
    });
    await heldPromise;
    return {
      async release() {
        release();
        await lockPromise;
      },
    };
  }

  async function holdFamilyLock(targetFamilyId: string) {
    let release!: () => void;
    let held!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const heldPromise = new Promise<void>((resolve) => { held = resolve; });
    const lockPromise = db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${targetFamilyId}, 240))`);
      held();
      await releasePromise;
    });
    await heldPromise;
    return {
      async release() {
        release();
        await lockPromise;
      },
    };
  }

  async function settledWithin(promise: Promise<unknown>, timeoutMs = 100): Promise<boolean> {
    return Promise.race([
      promise.then(() => true, () => true),
      new Promise<false>((resolve) => setTimeout(() => resolve(false), timeoutMs)),
    ]);
  }

  async function makeRefreshRouteApp(input: {
    kms: unknown;
    signAccessToken: (claims: unknown) => Promise<string>;
  }) {
    const app = Fastify();
    const previousOAuthEnabled = env.OAUTH_ENABLED;
    (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = 'true';
    registerOAuthRoutes(app, {
      db,
      kms: input.kms,
      signer: { signAccessToken: input.signAccessToken },
      redis: { set: vi.fn(async () => 'OK') },
      audit: { write: vi.fn(async () => 'aud_oauth') },
      securityEvent: { record: vi.fn(async () => null) },
      analytics: { fireOnce: vi.fn() },
    } as never);
    await app.ready();
    return {
      app,
      async close() {
        await app.close();
        (env as { OAUTH_ENABLED: string }).OAUTH_ENABLED = previousOAuthEnabled;
      },
    };
  }

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
      client_name: 'OAuth concurrency test',
      redirect_uris: ['http://127.0.0.1/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      operator_id: operatorId,
    });
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(original),
      token_family_id: familyId,
      client_id: clientId,
      operator_id: operatorId,
      member_id: null,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      expires_at: new Date(Date.now() + 60_000),
    });
  });

  afterAll(async () => {
    await db.delete(oauthAuthorizationCodes).where(eq(oauthAuthorizationCodes.operator_id, operatorId));
    await db.delete(oauthDeviceCodes).where(eq(oauthDeviceCodes.client_id, clientId));
    await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
    await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
    await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  it('returns one identical successor for concurrent use of one refresh token', async () => {
    const results = await Promise.all(
      Array.from({ length: 16 }, () =>
        rotateRefreshGrant(
          { db, kms: kms as never },
          {
            refreshToken: original,
            clientId,
            ip: '127.0.0.1',
            userAgent: 'oauth-concurrency-test',
          },
        ),
      ),
    );

    expect(results.every((result) => result.kind === 'success')).toBe(true);
    const successors = new Set(
      results.map((result) => result.kind === 'success' ? result.refreshToken : null),
    );
    expect(successors.size).toBe(1);

    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, familyId),
    });
    expect(family).toHaveLength(2);
    expect(family.filter((row) => !row.revoked_at && !row.replaced_by_hash)).toHaveLength(1);
    expect(family.every((row) => row.revoked_at === null)).toBe(true);
  });

  it('issues no credential after a pending erasure marks the operator deleted', async () => {
    const refresh = `rt_${Buffer.from(`erasure-refresh-${suffix}`).toString('base64url')}`;
    const refreshFamily = `${familyId}_erasure_refresh`;
    const codeHash = hashToken(`code_erasure_${suffix}`);
    const verifier = `verifier_${suffix}`;
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const deviceHash = hashToken(`device_erasure_${suffix}`);
    const now = new Date();
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(refresh), token_family_id: refreshFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(now.getTime() + 60_000),
    });
    await db.insert(oauthAuthorizationCodes).values({
      code_hash: codeHash,
      client_id: clientId,
      operator_id: operatorId,
      member_id: null,
      redirect_uri: 'http://127.0.0.1/callback',
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      expires_at: new Date(now.getTime() + 60_000),
    });
    await db.insert(oauthDeviceCodes).values({
      device_code_hash: deviceHash,
      user_code: `ERASE-${suffix.slice(0, 6)}`,
      client_id: clientId,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      status: 'approved',
      operator_id: operatorId,
      member_id: null,
      approved_at: now,
      expires_at: new Date(now.getTime() + 60_000),
      interval_seconds: 5,
    });
    await db.transaction(async (tx) => {
      await tx.update(operators).set({ status: 'deleted', deleted_at: now })
        .where(eq(operators.id, operatorId));
      await tx.insert(operatorErasureJobs).values({ operator_id: operatorId });
    });

    try {
      const rotated = await rotateRefreshGrant(
        { db, kms: kms as never },
        { refreshToken: refresh, clientId, ip: '127.0.0.1', userAgent: 'test' },
      );
      const code = await consumeAuthorizationCode(db, {
        codeHash,
        clientId,
        redirectUri: 'http://127.0.0.1/callback',
        codeVerifier: verifier,
        refreshToken: `rt_code_erasure_${suffix}`,
        tokenFamilyId: `${familyId}_erasure_code`,
      });
      const device = await consumeApprovedDeviceCode(db, {
        deviceCodeHash: deviceHash,
        clientId,
        refreshToken: `rt_device_erasure_${suffix}`,
        tokenFamilyId: `${familyId}_erasure_device`,
      });

      expect(rotated).toMatchObject({ kind: 'invalid_grant', description: 'operator not active' });
      expect(code).toMatchObject({ kind: 'invalid_grant', description: 'operator not active' });
      expect(device).toMatchObject({ kind: 'invalid_grant', description: 'operator not active' });
      expect(await db.query.oauthAuthorizationCodes.findFirst({
        where: eq(oauthAuthorizationCodes.code_hash, codeHash),
      })).toMatchObject({ consumed_at: null });
      expect(await db.query.oauthDeviceCodes.findFirst({
        where: eq(oauthDeviceCodes.device_code_hash, deviceHash),
      })).toMatchObject({ status: 'approved' });
      const rows = await db.query.oauthRefreshTokens.findMany({
        where: eq(oauthRefreshTokens.operator_id, operatorId),
      });
      expect(rows.some((row) => row.token_family_id === `${familyId}_erasure_code`)).toBe(false);
      expect(rows.some((row) => row.token_family_id === `${familyId}_erasure_device`)).toBe(false);
      expect(rows.filter((row) => row.token_family_id === refreshFamily)).toHaveLength(1);
    } finally {
      await db.delete(operatorErasureJobs).where(eq(operatorErasureJobs.operator_id, operatorId));
      await db.update(operators).set({ status: 'active', deleted_at: null })
        .where(eq(operators.id, operatorId));
    }
  });

  it('failure recovery keeps the family live when KMS decrypt is temporarily unavailable', async () => {
    const raw = `rt_${Buffer.from(`kms-${suffix}`).toString('base64url')}`;
    const kmsFamily = `${familyId}_kms`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw),
      token_family_id: kmsFamily,
      client_id: clientId,
      operator_id: operatorId,
      member_id: null,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      expires_at: new Date(Date.now() + 60_000),
    });
    const first = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: null },
    );
    expect(first.kind).toBe('success');
    const unavailable = await rotateRefreshGrant(
      {
        db,
        kms: {
          ...kms,
          async decrypt() { throw new Error('KMS timeout'); },
        } as never,
      },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: null },
    );
    expect(unavailable).toEqual({ kind: 'temporarily_unavailable' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, kmsFamily),
    });
    expect(family.every((row) => row.revoked_at === null)).toBe(true);
    expect(family.filter((row) => !row.replaced_by_hash)).toHaveLength(1);
  });

  it('failure recovery maps a KMS decrypt outage to OAuth 503', async () => {
    const raw = `rt_${Buffer.from(`kms-route-${suffix}`).toString('base64url')}`;
    const kmsFamily = `${familyId}_kms_route`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: kmsFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const first = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: 'failure-recovery' },
    );
    expect(first.kind).toBe('success');

    const route = await makeRefreshRouteApp({
      kms: {
        ...kms,
        async decrypt() { throw new Error('KMS timeout'); },
      },
      signAccessToken: vi.fn(async () => 'must-not-sign'),
    });
    try {
      const response = await route.app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'user-agent': 'failure-recovery',
        },
        payload: new URLSearchParams({
          grant_type: 'refresh_token', refresh_token: raw, client_id: clientId,
        }).toString(),
      });
      expect(response.statusCode).toBe(503);
      expect(response.headers['retry-after']).toBe('1');
      expect(response.json()).toMatchObject({ error: 'temporarily_unavailable' });
    } finally {
      await route.close();
    }
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, kmsFamily),
    });
    expect(family.every((row) => row.revoked_at === null)).toBe(true);
  });

  it('failure recovery returns the stored successor after access-token signing fails', async () => {
    const raw = `rt_${Buffer.from(`sign-route-${suffix}`).toString('base64url')}`;
    const signingFamily = `${familyId}_signing_route`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: signingFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const signAccessToken = vi.fn()
      .mockRejectedValueOnce(new Error('signer unavailable'))
      .mockResolvedValueOnce('signed-access-token');
    const route = await makeRefreshRouteApp({ kms, signAccessToken });
    try {
      const request = {
        method: 'POST' as const,
        url: '/oauth/token',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'user-agent': 'signing-recovery',
        },
        payload: new URLSearchParams({
          grant_type: 'refresh_token', refresh_token: raw, client_id: clientId,
        }).toString(),
      };
      const first = await route.app.inject(request);
      const second = await route.app.inject(request);

      expect(first.statusCode).toBe(500);
      expect(second.statusCode).toBe(200);
      const recovered = second.json() as { access_token: string; refresh_token: string };
      expect(recovered.access_token).toBe('signed-access-token');
      expect(signAccessToken).toHaveBeenCalledTimes(2);
      const family = await db.query.oauthRefreshTokens.findMany({
        where: eq(oauthRefreshTokens.token_family_id, signingFamily),
      });
      expect(family).toHaveLength(2);
      expect(family.find((row) => !row.replaced_by_hash)?.token_hash)
        .toBe(hashToken(recovered.refresh_token));
      expect(family.every((row) => row.revoked_at === null)).toBe(true);
    } finally {
      await route.close();
    }
  });

  it('retry identity returns the successor only to the same IP and user agent', async () => {
    const raw = `rt_${Buffer.from(`binding-${suffix}`).toString('base64url')}`;
    const bindingFamily = `${familyId}_binding`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: bindingFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const first = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '10.0.0.1', userAgent: 'codex/a' },
    );
    if (first.kind !== 'success') throw new Error(`first rotation failed: ${first.kind}`);
    const sameIdentity = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '10.0.0.1', userAgent: 'codex/a' },
    );
    expect(sameIdentity).toMatchObject({
      kind: 'success',
      refreshToken: first.refreshToken,
      retry: true,
    });
    const result = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '10.0.0.2', userAgent: 'codex/b' },
    );
    expect(result).toMatchObject({ kind: 'reuse', reason: 'stale_replay' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, bindingFamily),
    });
    expect(family.every((row) => row.revoked_reason === 'reuse_detected')).toBe(true);
    expect(family.filter((row) => !row.replaced_by_hash)).toHaveLength(1);
  });

  it('legacy transition rejects rows without retry fields and keeps the family live', async () => {
    const parent = `rt_${Buffer.from(`legacy-parent-${suffix}`).toString('base64url')}`;
    const child = `rt_${Buffer.from(`legacy-child-${suffix}`).toString('base64url')}`;
    const legacyFamily = `${familyId}_legacy`;
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: hashToken(parent), token_family_id: legacyFamily, client_id: clientId,
        operator_id: operatorId, member_id: null, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
        replaced_by_hash: hashToken(child), last_used_at: new Date(),
        last_used_ip: '127.0.0.1', last_used_ua: 'codex/a',
      },
      {
        token_hash: hashToken(child), token_family_id: legacyFamily, client_id: clientId,
        operator_id: operatorId, member_id: null, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
      },
    ]);
    const result = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: parent, clientId, ip: '127.0.0.1', userAgent: 'codex/a' },
    );
    expect(result).toMatchObject({ kind: 'invalid_grant' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, legacyFamily),
    });
    expect(family.every((row) => row.revoked_at === null)).toBe(true);
  });

  it('failure recovery rolls back when KMS encrypt fails', async () => {
    const raw = `rt_${Buffer.from(`encrypt-fail-${suffix}`).toString('base64url')}`;
    const encryptFamily = `${familyId}_encrypt_fail`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: encryptFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const result = await rotateRefreshGrant(
      {
        db,
        kms: { ...kms, async encrypt() { throw new Error('KMS unavailable'); } } as never,
      },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: 'codex/a' },
    );
    expect(result).toEqual({ kind: 'temporarily_unavailable' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, encryptFamily),
    });
    expect(family).toHaveLength(1);
    expect(family[0]?.replaced_by_hash).toBeNull();
  });

  it('revokes the family when the fixed retry window has expired', async () => {
    const raw = `rt_${Buffer.from(`stale-${suffix}`).toString('base64url')}`;
    const staleFamily = `${familyId}_stale`;
    const start = new Date('2026-08-09T20:00:00.000Z');
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw),
      token_family_id: staleFamily,
      client_id: clientId,
      operator_id: operatorId,
      member_id: null,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      issued_at: start,
      expires_at: new Date(start.getTime() + 120_000),
    });
    await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: null, now: start },
    );
    const replay = await rotateRefreshGrant(
      { db, kms: kms as never },
      {
        refreshToken: raw,
        clientId,
        ip: '127.0.0.1',
        userAgent: null,
        now: new Date(start.getTime() + 61_000),
      },
    );
    expect(replay).toMatchObject({ kind: 'reuse', reason: 'stale_replay' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, staleFamily),
    });
    expect(family.every((row) => row.revoked_at !== null)).toBe(true);
  });

  it('revokes a stale replay after the worker cleared its expired ciphertext', async () => {
    const parent = `rt_${Buffer.from(`cleanup-parent-${suffix}`).toString('base64url')}`;
    const child = `rt_${Buffer.from(`cleanup-child-${suffix}`).toString('base64url')}`;
    const cleanupFamily = `${familyId}_cleanup_replay`;
    const deadline = new Date(Date.now() - 1_000);
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: hashToken(parent), token_family_id: cleanupFamily, client_id: clientId,
        operator_id: operatorId, member_id: null, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
        replaced_by_hash: hashToken(child), replacement_token_encrypted: null,
        replacement_retry_expires_at: deadline, last_used_ip: '127.0.0.1',
        last_used_ua: 'codex/a',
      },
      {
        token_hash: hashToken(child), token_family_id: cleanupFamily, client_id: clientId,
        operator_id: operatorId, member_id: null, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
      },
    ]);

    const result = await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: parent, clientId, ip: '127.0.0.1', userAgent: 'codex/a' },
    );

    expect(result).toMatchObject({ kind: 'reuse', reason: 'stale_replay' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, cleanupFamily),
    });
    expect(family.every((row) => row.revoked_reason === 'reuse_detected')).toBe(true);
  });

  it('revokes replay of a parent after its child rotates inside the old retry window', async () => {
    const parent = `rt_${Buffer.from(`advance-parent-${suffix}`).toString('base64url')}`;
    const advanceFamily = `${familyId}_advance_replay`;
    const start = new Date('2026-08-09T21:00:00.000Z');
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(parent), token_family_id: advanceFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', issued_at: start,
      expires_at: new Date(start.getTime() + 120_000),
    });
    const first = await rotateRefreshGrant(
      { db, kms: kms as never },
      {
        refreshToken: parent, clientId, ip: '127.0.0.1', userAgent: 'codex/a', now: start,
      },
    );
    if (first.kind !== 'success') throw new Error(`first rotation failed: ${first.kind}`);
    const second = await rotateRefreshGrant(
      { db, kms: kms as never },
      {
        refreshToken: first.refreshToken, clientId, ip: '127.0.0.1',
        userAgent: 'codex/a', now: new Date(start.getTime() + 1_000),
      },
    );
    expect(second.kind).toBe('success');

    const replay = await rotateRefreshGrant(
      { db, kms: kms as never },
      {
        refreshToken: parent, clientId, ip: '127.0.0.1', userAgent: 'codex/a',
        now: new Date(start.getTime() + 2_000),
      },
    );

    expect(replay).toMatchObject({ kind: 'reuse', reason: 'stale_replay' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, advanceFamily),
    });
    expect(family.every((row) => row.revoked_reason === 'reuse_detected')).toBe(true);
  });

  it('failure recovery revokes the family when KMS returns an integrity mismatch', async () => {
    const raw = `rt_${Buffer.from(`integrity-${suffix}`).toString('base64url')}`;
    const integrityFamily = `${familyId}_integrity`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw),
      token_family_id: integrityFamily,
      client_id: clientId,
      operator_id: operatorId,
      member_id: null,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      expires_at: new Date(Date.now() + 60_000),
    });
    await rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: null },
    );
    const integrity = await rotateRefreshGrant(
      {
        db,
        kms: {
          ...kms,
          async decrypt() { return 'wrong-successor'; },
        } as never,
      },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: null },
    );
    expect(integrity).toMatchObject({ kind: 'reuse', reason: 'integrity_failure' });
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, integrityFamily),
    });
    expect(family.every((row) => row.revoked_reason === 'refresh_integrity_failure')).toBe(true);
  });

  it('family revocation revokes every row and clears retry ciphertext', async () => {
    const parent = `rt_${Buffer.from(`revoke-parent-${suffix}`).toString('base64url')}`;
    const child = `rt_${Buffer.from(`revoke-child-${suffix}`).toString('base64url')}`;
    const revokeFamilyId = `${familyId}_revoke`;
    await db.insert(oauthRefreshTokens).values([
      {
        token_hash: hashToken(parent), token_family_id: revokeFamilyId, client_id: clientId,
        operator_id: operatorId, member_id: null, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
        replaced_by_hash: hashToken(child), replacement_token_encrypted: 'kms-ciphertext',
        replacement_retry_expires_at: new Date(Date.now() + 60_000),
        revoked_at: new Date(Date.now() - 1_000), revoked_reason: 'prior_revoke',
      },
      {
        token_hash: hashToken(child), token_family_id: revokeFamilyId, client_id: clientId,
        operator_id: operatorId, member_id: null, scope: 'agents:read',
        resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
      },
    ]);

    const revoked = await revokeRefreshFamilyByToken(db, {
      refreshToken: child,
      reason: 'logout',
    });

    expect(revoked?.token_family_id).toBe(revokeFamilyId);
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, revokeFamilyId),
    });
    expect(family).toHaveLength(2);
    expect(family.every((row) => row.revoked_at !== null)).toBe(true);
    expect(new Set(family.map((row) => row.revoked_reason))).toEqual(
      new Set(['prior_revoke', 'logout']),
    );
    expect(family.every((row) => row.replacement_token_encrypted === null)).toBe(true);
    expect(family.every((row) => row.replacement_retry_expires_at === null)).toBe(true);
  });

  it('family revocation serializes logout with refresh rotation', async () => {
    const raw = `rt_${Buffer.from(`revoke-rotation-${suffix}`).toString('base64url')}`;
    const raceFamily = `${familyId}_revoke_rotation`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: raceFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const lock = await holdFamilyLock(raceFamily);
    const rotation = rotateRefreshGrant(
      { db, kms: kms as never },
      { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: 'family-revocation' },
    );
    const logout = revokeRefreshFamilyByToken(db, { refreshToken: raw, reason: 'logout' });
    const [rotationSettled, logoutSettled] = await Promise.all([
      settledWithin(rotation),
      settledWithin(logout),
    ]);
    await lock.release();
    await Promise.all([rotation, logout]);

    expect(rotationSettled).toBe(false);
    expect(logoutSettled).toBe(false);
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, raceFamily),
    });
    expect(family.length).toBeGreaterThan(0);
    expect(family.every((row) => row.revoked_at !== null)).toBe(true);
    expect(family.every((row) => row.replacement_token_encrypted === null)).toBe(true);
  });

  it('family revocation serializes operator session revocation', async () => {
    const raw = `rt_${Buffer.from(`session-revoke-${suffix}`).toString('base64url')}`;
    const sessionFamily = `${familyId}_session_revoke`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: sessionFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const service = new OperatorService(new OperatorRepository(db));
    service.setDb(db);
    const lock = await holdFamilyLock(sessionFamily);
    const revocation = service.revokeMcpSession(operatorId, undefined, sessionFamily);
    const settled = await settledWithin(revocation);
    await lock.release();
    await revocation;

    expect(settled).toBe(false);
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, sessionFamily),
    });
    expect(family.every((row) => row.revoked_reason === 'operator_revoked')).toBe(true);
  });

  it('family revocation serializes member revocation', async () => {
    const memberId = `mem_family_revoke_${suffix}`;
    const raw = `rt_${Buffer.from(`member-revoke-${suffix}`).toString('base64url')}`;
    const memberFamily = `${familyId}_member_revoke`;
    await db.insert(teamMembers).values({
      id: memberId,
      operator_id: operatorId,
      email: `${memberId}@oauth-test.invalid`,
      name: 'Family revocation member',
      status: 'active',
    });
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: memberFamily, client_id: clientId,
      operator_id: operatorId, member_id: memberId, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    const service = new MemberService(new MemberRepository(db));
    service.setDb(db);
    const lock = await holdFamilyLock(memberFamily);
    const revocation = service.revoke(memberId, operatorId);
    const settled = await settledWithin(revocation);
    await lock.release();
    await revocation;

    expect(settled).toBe(false);
    const family = await db.query.oauthRefreshTokens.findMany({
      where: eq(oauthRefreshTokens.token_family_id, memberFamily),
    });
    expect(family.every((row) => row.revoked_reason === 'member_revoked')).toBe(true);
  });

  it('device decision allows only one final decision for one pending code', async () => {
    const deviceCode = `device_decision_${suffix}`;
    const userCode = `D-${suffix.slice(0, 8)}`;
    await db.insert(oauthDeviceCodes).values({
      device_code_hash: hashToken(deviceCode),
      user_code: userCode,
      client_id: clientId,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      status: 'pending',
      expires_at: new Date(Date.now() + 60_000),
    });

    const decisions = await Promise.all([
      decideDeviceCode(db, {
        userCode, decision: 'approve', operatorId, memberId: null,
      }),
      decideDeviceCode(db, {
        userCode, decision: 'deny', operatorId, memberId: null,
      }),
    ]);

    expect(decisions.filter((result) => result.kind === 'success')).toHaveLength(1);
    expect(decisions.filter((result) => result.kind === 'already_decided')).toHaveLength(1);
    const row = await db.query.oauthDeviceCodes.findFirst({
      where: eq(oauthDeviceCodes.device_code_hash, hashToken(deviceCode)),
    });
    expect(['approved', 'denied']).toContain(row?.status);
  });

  it('device decision cannot restore expired, denied, or consumed codes', async () => {
    const expiredDeviceCode = `device_expired_${suffix}`;
    const deniedDeviceCode = `device_denied_${suffix}`;
    const consumedDeviceCode = `device_consumed_${suffix}`;
    const expiredUserCode = `E-${suffix.slice(0, 8)}`;
    const deniedUserCode = `N-${suffix.slice(0, 8)}`;
    const consumedUserCode = `C-${suffix.slice(0, 8)}`;
    const now = new Date();
    await db.insert(oauthDeviceCodes).values([
      {
        device_code_hash: hashToken(expiredDeviceCode), user_code: expiredUserCode,
        client_id: clientId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        status: 'pending', expires_at: new Date(now.getTime() - 1_000),
      },
      {
        device_code_hash: hashToken(deniedDeviceCode), user_code: deniedUserCode,
        client_id: clientId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        status: 'pending', expires_at: new Date(now.getTime() + 60_000),
      },
      {
        device_code_hash: hashToken(consumedDeviceCode), user_code: consumedUserCode,
        client_id: clientId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        status: 'pending', expires_at: new Date(now.getTime() + 60_000),
      },
    ]);

    expect(await decideDeviceCode(db, {
      userCode: deniedUserCode, decision: 'deny', operatorId, memberId: null, now,
    })).toMatchObject({ kind: 'success' });
    expect(await decideDeviceCode(db, {
      userCode: consumedUserCode, decision: 'approve', operatorId, memberId: null, now,
    })).toMatchObject({ kind: 'success' });
    expect(await consumeApprovedDeviceCode(db, {
      deviceCodeHash: hashToken(consumedDeviceCode), clientId,
      refreshToken: `rt_device_consumed_${suffix}`,
      tokenFamilyId: `${familyId}_device_consumed`,
      now,
    })).toMatchObject({ kind: 'success' });

    const lateApprovals = await Promise.all([
      decideDeviceCode(db, {
        userCode: expiredUserCode, decision: 'approve', operatorId, memberId: null, now,
      }),
      decideDeviceCode(db, {
        userCode: deniedUserCode, decision: 'approve', operatorId, memberId: null, now,
      }),
      decideDeviceCode(db, {
        userCode: consumedUserCode, decision: 'approve', operatorId, memberId: null, now,
      }),
    ]);
    expect(lateApprovals.map((result) => result.kind)).toEqual([
      'expired',
      'already_decided',
      'expired',
    ]);

    const rows = await db.query.oauthDeviceCodes.findMany({
      where: sql`${oauthDeviceCodes.device_code_hash} in (
        ${hashToken(expiredDeviceCode)},
        ${hashToken(deniedDeviceCode)},
        ${hashToken(consumedDeviceCode)}
      )`,
    });
    const byHash = new Map(rows.map((row) => [row.device_code_hash, row]));
    expect(byHash.get(hashToken(expiredDeviceCode))).toMatchObject({
      status: 'pending', operator_id: null, approved_at: null,
    });
    expect(byHash.get(hashToken(deniedDeviceCode))).toMatchObject({
      status: 'denied', approved_at: null,
    });
    expect(byHash.get(hashToken(consumedDeviceCode))).toMatchObject({
      status: 'expired', approved_at: now,
    });
  });

  it('blocks every grant mutation while operator deletion owns the operator lock', async () => {
    const raw = `rt_${Buffer.from(`operator-lock-${suffix}`).toString('base64url')}`;
    const lockFamily = `${familyId}_operator_lock`;
    const code = `ocode_lock_${suffix}`;
    const verifier = `verifier-lock-${suffix}`;
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const deviceCode = `device_lock_${suffix}`;
    const decisionDeviceCode = `device_decision_lock_${suffix}`;
    const decisionUserCode = `L-${suffix.slice(0, 8)}`;
    await db.insert(oauthRefreshTokens).values({
      token_hash: hashToken(raw), token_family_id: lockFamily, client_id: clientId,
      operator_id: operatorId, member_id: null, scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', expires_at: new Date(Date.now() + 60_000),
    });
    await db.insert(oauthAuthorizationCodes).values({
      code_hash: hashToken(code), client_id: clientId, operator_id: operatorId,
      member_id: null, redirect_uri: 'http://127.0.0.1/callback', scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp', code_challenge: challenge,
      code_challenge_method: 'S256', expires_at: new Date(Date.now() + 60_000),
    });
    await db.insert(oauthDeviceCodes).values([
      {
        device_code_hash: hashToken(deviceCode), user_code: `P-${suffix.slice(0, 8)}`,
        client_id: clientId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        status: 'approved', operator_id: operatorId, expires_at: new Date(Date.now() + 60_000),
      },
      {
        device_code_hash: hashToken(decisionDeviceCode), user_code: decisionUserCode,
        client_id: clientId, scope: 'agents:read', resource: 'https://mcp.getstack.run/mcp',
        status: 'pending', expires_at: new Date(Date.now() + 60_000),
      },
    ]);

    const lock = await holdOperatorLock(operatorId);
    const operations = [
      rotateRefreshGrant(
        { db, kms: kms as never },
        { refreshToken: raw, clientId, ip: '127.0.0.1', userAgent: 'lock-test' },
      ),
      consumeAuthorizationCode(db, {
        codeHash: hashToken(code), clientId, redirectUri: 'http://127.0.0.1/callback',
        codeVerifier: verifier, refreshToken: `rt_auth_lock_${suffix}`,
        tokenFamilyId: `rfam_auth_lock_${suffix}`,
      }),
      consumeApprovedDeviceCode(db, {
        deviceCodeHash: hashToken(deviceCode), clientId,
        refreshToken: `rt_device_lock_${suffix}`,
        tokenFamilyId: `rfam_device_lock_${suffix}`,
      }),
      decideDeviceCode(db, {
        userCode: decisionUserCode, decision: 'approve', operatorId, memberId: null,
      }),
    ];
    const state = await Promise.race([
      Promise.all(operations).then(() => 'settled'),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
    ]);
    await lock.release();
    const results = await Promise.all(operations);

    expect(state).toBe('blocked');
    expect(results.every((result) => result.kind === 'success')).toBe(true);
  });

  it('refuses code issuance when member revocation wins the operator lock', async () => {
    const memberId = `mem_code_issue_race_${suffix}`;
    await db.insert(teamMembers).values({
      id: memberId,
      operator_id: operatorId,
      email: `${memberId}@oauth-test.invalid`,
      name: 'Code issuance race member',
      status: 'active',
    });
    let release!: () => void;
    let held!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const heldPromise = new Promise<void>((resolve) => { held = resolve; });
    const revocation = db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${operatorId}, 239))`);
      await tx.update(teamMembers)
        .set({ status: 'revoked' })
        .where(eq(teamMembers.id, memberId));
      held();
      await releasePromise;
    });
    await heldPromise;

    const issuance = issueAuthorizationCode(db, {
      operatorId,
      clientId,
      memberId,
      redirectUri: 'http://127.0.0.1/callback',
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      codeChallenge: 'member-revoke-race-challenge',
      codeChallengeMethod: 'S256',
    });
    const state = await Promise.race([
      issuance.then(() => 'settled' as const),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 100)),
    ]);
    release();
    await revocation;
    const result = await issuance;

    expect(state).toBe('blocked');
    expect(result).toEqual({ kind: 'member_inactive' });
    const rows = await db.query.oauthAuthorizationCodes.findMany({
      where: eq(oauthAuthorizationCodes.member_id, memberId),
    });
    expect(rows).toHaveLength(0);
  });

  it('consumes one authorization code and inserts one family atomically', async () => {
    const code = `ocode_${suffix}`;
    const verifier = `verifier-${suffix}`;
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    await db.insert(oauthAuthorizationCodes).values({
      code_hash: hashToken(code),
      client_id: clientId,
      operator_id: operatorId,
      member_id: null,
      redirect_uri: 'http://127.0.0.1/callback',
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      expires_at: new Date(Date.now() + 60_000),
    });
    const attempts = await Promise.all(
      [1, 2].map((n) => consumeAuthorizationCode(db, {
        codeHash: hashToken(code),
        clientId,
        redirectUri: 'http://127.0.0.1/callback',
        codeVerifier: verifier,
        refreshToken: `rt_auth_${suffix}_${n}`,
        tokenFamilyId: `rfam_auth_${suffix}_${n}`,
      })),
    );
    expect(attempts.filter((result) => result.kind === 'success')).toHaveLength(1);
    const inserted = await Promise.all(
      [1, 2].map((n) => db.query.oauthRefreshTokens.findFirst({
        where: eq(oauthRefreshTokens.token_hash, hashToken(`rt_auth_${suffix}_${n}`)),
      })),
    );
    expect(inserted.filter(Boolean)).toHaveLength(1);
  });

  it('burns one approved device code with the one inserted family', async () => {
    const deviceCode = `device_${suffix}`;
    await db.insert(oauthDeviceCodes).values({
      device_code_hash: hashToken(deviceCode),
      user_code: `T-${suffix.slice(0, 8)}`,
      client_id: clientId,
      scope: 'agents:read',
      resource: 'https://mcp.getstack.run/mcp',
      status: 'approved',
      operator_id: operatorId,
      expires_at: new Date(Date.now() + 60_000),
    });
    const attempts = await Promise.all(
      [1, 2].map((n) => consumeApprovedDeviceCode(db, {
        deviceCodeHash: hashToken(deviceCode),
        clientId,
        refreshToken: `rt_device_${suffix}_${n}`,
        tokenFamilyId: `rfam_device_${suffix}_${n}`,
      })),
    );
    expect(attempts.filter((result) => result.kind === 'success')).toHaveLength(1);
    const inserted = await Promise.all(
      [1, 2].map((n) => db.query.oauthRefreshTokens.findFirst({
        where: eq(oauthRefreshTokens.token_hash, hashToken(`rt_device_${suffix}_${n}`)),
      })),
    );
    expect(inserted.filter(Boolean)).toHaveLength(1);
  });
});
