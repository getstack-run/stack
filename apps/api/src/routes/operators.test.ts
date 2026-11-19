import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerOperatorRoutes } from './operators.js';
import { fakeEntitlements } from '../test/entitlements.js';

const apps: ReturnType<typeof Fastify>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp(input?: { redisFails?: boolean; erasureStatus?: 'completed' | 'pending' }) {
  const auditWrite = vi.fn(async () => undefined);
  const deleteAccount = vi.fn(async () => ({ status: input?.erasureStatus ?? 'completed' }));
  const revokeMcpSession = vi.fn(async () => ({ revoked: 2 }));
  const listMcpSessions = vi.fn(async () => ([
    {
      token_family_id: 'rfam_route_test',
      member_id: 'mem_route_test',
      member_name: 'Ada Member',
      member_email: 'ada@example.test',
      client_name: 'Codex',
    },
  ]));
  const redisSet = vi.fn(async () => {
    if (input?.redisFails) throw new Error('Redis unavailable');
    return 'OK';
  });
  const operator = {
    id: 'op_route_test',
    email: 'route@test.invalid',
    tier: 'business',
    status: 'active',
    is_admin: true,
    is_platform_staff: false,
    is_partner: false,
    stripe_customer_id: null,
  };
  const services = {
    audit: { write: auditWrite },
    entitlements: fakeEntitlements(), operator: {
      authenticateByApiKey: vi.fn(async () => operator),
      getById: vi.fn(async () => ({ ...operator, identity_claim_ttl: '90d', identity_claim_inheritance: 'auto', identity_auto_revoke: false, created_at: new Date('2026-07-10T00:00:00Z') })),
      deleteAccount,
      revokeMcpSession,
      listMcpSessions,
    },
    redis: { set: redisSet },
  };
  const app = Fastify();
  apps.push(app);
  registerOperatorRoutes(app, services as never);
  await app.ready();
  return { app, auditWrite, deleteAccount, revokeMcpSession, listMcpSessions, redisSet };
}

describe('GET /v1/operators/me', () => {
  it('names the plan the account is on and not the legacy tier', async () => {
    const { app } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/operators/me',
      headers: { authorization: 'Bearer sk_live_route_test' },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ id: 'op_route_test', plan: 'contract' });
    expect(response.json()).not.toHaveProperty('tier');
  });
});

describe('operator destructive routes', () => {
  it('gives the account owner the complete account client list', async () => {
    const { app, listMcpSessions } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/operators/me/mcp-sessions',
      headers: { authorization: 'Bearer sk_live_route_test' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ sessions: expect.arrayContaining([
      expect.objectContaining({ member_id: 'mem_route_test', member_name: 'Ada Member' }),
    ]) });
    expect(listMcpSessions).toHaveBeenCalledWith('op_route_test', undefined);
  });

  it('does not write orphan audit data after hard account deletion', async () => {
    const { app, auditWrite, deleteAccount } = await makeApp();
    const response = await app.inject({
      method: 'DELETE',
      url: '/v1/operators/me',
      headers: { authorization: 'Bearer sk_live_route_test' },
      payload: { confirm_email: 'route@test.invalid' },
    });

    expect(response.statusCode).toBe(204);
    expect(deleteAccount).toHaveBeenCalledWith('op_route_test', 'route@test.invalid');
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it('returns 202 when durable account erasure is queued', async () => {
    const { app, auditWrite } = await makeApp({ erasureStatus: 'pending' });
    const response = await app.inject({
      method: 'DELETE',
      url: '/v1/operators/me',
      headers: { authorization: 'Bearer sk_live_route_test' },
      payload: { confirm_email: 'route@test.invalid' },
    });

    expect(response.statusCode).toBe(202);
    expect(auditWrite).not.toHaveBeenCalled();
  });

  it('returns success and audits after Redis fails during MCP session revoke', async () => {
    const { app, auditWrite, revokeMcpSession, redisSet } = await makeApp({ redisFails: true });
    const response = await app.inject({
      method: 'DELETE',
      url: '/v1/operators/me/mcp-sessions/rfam_route_test',
      headers: { authorization: 'Bearer sk_live_route_test' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ revoked: 2 });
    expect(revokeMcpSession).toHaveBeenCalledWith(
      'op_route_test',
      undefined,
      'rfam_route_test',
    );
    expect(redisSet).toHaveBeenCalledOnce();
    expect(auditWrite).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp_session.revoke',
      outcome: 'success',
    }));
  });
});
