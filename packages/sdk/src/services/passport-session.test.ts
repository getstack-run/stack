import { describe, it, expect, vi } from 'vitest';
import { PassportSession, missionRefusal } from './passport-session.js';
import { MissionNotLiveError, StackError } from '../errors.js';
import type { HttpClient } from '../client.js';

/**
 * PassportSession invariants:
 *
 *   S1 — getToken returns current token when fresh (past grace window)
 *   S2 — getToken auto-refreshes within grace window + updates state
 *   S3 — expiresAt Date reflects current exp
 *   S4 — token property does NOT trigger refresh
 *   S5 — refresh failure propagates (caller surfaces "expired + can't refresh")
 */

function buildToken(expSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ exp: expSeconds })).toString('base64url');
  return `${header}.${payload}.sig`;
}

describe('PassportSession', () => {
  it('S1 returns current token when fresh (exp > now + grace)', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const token = buildToken(futureExp);
    const client = { post: vi.fn() } as unknown as HttpClient;
    const session = new PassportSession(
      client,
      { token, jti: 'pas_x', expires_at: '2026-12-31T00:00:00Z' } as never,
      { agent_id: 'agt_x' } as never,
    );
    const got = await session.getToken(60);
    expect(got).toBe(token);
    expect(client.post).not.toHaveBeenCalled();
  });

  it('S2 auto-refreshes within grace window + updates state', async () => {
    // Token expires in 30 seconds; grace is 60s — should refresh.
    const expiringExp = Math.floor(Date.now() / 1000) + 30;
    const expiringToken = buildToken(expiringExp);

    const refreshedExp = Math.floor(Date.now() / 1000) + 3600;
    const refreshedToken = buildToken(refreshedExp);

    const client = {
      post: vi.fn(async () => ({
        token: refreshedToken,
        jti: 'pas_x',
        expires_at: new Date(refreshedExp * 1000).toISOString(),
      })),
    } as unknown as HttpClient;

    const session = new PassportSession(
      client,
      { token: expiringToken, jti: 'pas_x', expires_at: '2026-05-23T00:01:00Z' } as never,
      { agent_id: 'agt_x', ttl_seconds: 900 } as never,
    );

    const got = await session.getToken(60);
    expect(got).toBe(refreshedToken);
    expect(client.post).toHaveBeenCalledWith(
      '/v1/passports/refresh',
      expect.objectContaining({ token: expiringToken, ttl_seconds: 900 }),
    );
    // Session state updated.
    expect(session.token).toBe(refreshedToken);
  });

  it('S3 expiresAt reflects the current exp', () => {
    const exp = Math.floor(Date.now() / 1000) + 1000;
    const token = buildToken(exp);
    const client = { post: vi.fn() } as unknown as HttpClient;
    const session = new PassportSession(
      client,
      { token, jti: 'pas_x', expires_at: '2026-05-23T00:00:00Z' } as never,
      { agent_id: 'agt_x' } as never,
    );
    expect(session.expiresAt.getTime()).toBe(exp * 1000);
  });

  it('S4 token getter does NOT trigger refresh', () => {
    const exp = Math.floor(Date.now() / 1000) + 30; // within grace
    const token = buildToken(exp);
    const client = { post: vi.fn() } as unknown as HttpClient;
    const session = new PassportSession(
      client,
      { token, jti: 'pas_x', expires_at: '2026-05-23T00:00:00Z' } as never,
      { agent_id: 'agt_x' } as never,
    );
    // Reading .token bypasses the grace check.
    expect(session.token).toBe(token);
    expect(client.post).not.toHaveBeenCalled();
  });

  it('S5 refresh failure propagates', async () => {
    const exp = Math.floor(Date.now() / 1000) + 30; // within grace
    const token = buildToken(exp);
    const client = {
      post: vi.fn(async () => {
        throw new Error('refresh denied');
      }),
    } as unknown as HttpClient;
    const session = new PassportSession(
      client,
      { token, jti: 'pas_x', expires_at: '2026-05-23T00:00:00Z' } as never,
      { agent_id: 'agt_x' } as never,
    );
    await expect(session.getToken(60)).rejects.toThrow('refresh denied');
  });

  it.each([
    ['Mission ms_a is completed', 403, 'completed'],
    ['Mission ms_a is revoked', 403, 'revoked'],
    ['Mission ms_a has expired', 403, 'expired'],
    ['Mission ms_a not found', 404, 'not_found'],
  ] as const)('S6 a Mission refusal (%s) becomes MissionNotLiveError', async (message, status, state) => {
    const token = buildToken(Math.floor(Date.now() / 1000) + 30);
    const refusal = new StackError(message, status === 404 ? 'NOT_FOUND' : 'FORBIDDEN', status);
    const client = { post: vi.fn(async () => { throw refusal; }) } as unknown as HttpClient;
    const session = new PassportSession(
      client,
      { token, jti: 'pas_x', expires_at: '2026-05-23T00:00:00Z' } as never,
      { agent_id: 'agt_x', mission_ids: ['ms_a'] },
    );
    const err = await session.getToken(60).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MissionNotLiveError);
    expect(err).toMatchObject({ missionId: 'ms_a', state, status, code: 'MISSION_NOT_LIVE', refusal });
    expect((err as Error).message).toMatch(/Open a new Mission/);
  });

  it('S7 a passport without exactly one Mission refuses with state unbound', async () => {
    const err = missionRefusal(new StackError('A Passport must be bound to exactly one Mission', 'FORBIDDEN', 403));
    expect(err).toMatchObject({ missionId: null, state: 'unbound' });
  });

  it('S8 other refusals pass through unchanged', async () => {
    expect(missionRefusal(new StackError('Passport has been revoked', 'PASSPORT_REVOKED', 401))).toBeNull();
    expect(missionRefusal(new StackError('Mission ms_a is revoked', 'X', 500))).toBeNull();
    expect(missionRefusal(new Error('Mission ms_a is revoked'))).toBeNull();
  });
});
