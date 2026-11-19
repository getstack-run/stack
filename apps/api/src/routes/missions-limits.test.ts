import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { errorHandler } from '../middleware/error-handler.js';

// The owner's side of a Mission's limits: the review of a Mission a cap paused, and the pre-approval of its making
// orders. Both are the owner's or an admin's; an agent never decides its own pause or pre-approves its own spending.

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['operatorId'] = 'op_owner';
    request['operatorTier'] = 'enterprise';
    request['isAdmin'] = false;
    request['isPlatformStaff'] = false;
    request['isPartner'] = false;
    if (token.startsWith('member')) {
      request['memberId'] = 'mem_one';
      request['memberRole'] = token.slice('member-'.length);
    }
    if (token === 'agent') request['agentId'] = 'agt_owner';
  },
}));

vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => {}) }));

import { registerMissionsRoutes } from './missions.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const view = {
  mission_id: 'ms_one', operator_id: 'op_owner', claim_id: 'pc_one', passport_jti: null, intent_summary: 'work',
  intent_services: [], expected_counterparties: [], max_actions: 4, max_dropoff_bytes: null, coverage_cap_cents: null,
  max_duration_seconds: null, max_concurrent_intents: null, max_actions_per_service: {}, cap_behavior: {},
  coverage_cap_period: 'mission', cap_time_zone: 'UTC', paused_at: null, paused_cap: null, paused_service: null,
  making_orders_up_to_cents: 2_000, baseline_profile: null, expected_output_shape: null,
  started_at: new Date('2026-11-02T10:00:00Z'), expires_at: new Date('2026-11-03T10:00:00Z'),
  completed_at: null, revoked_at: null, revoked_reason: null, terminal_state: null,
};

async function makeApp() {
  const rateLimits: string[] = [];
  const services = {
    entitlements: { controlsEnabled: vi.fn(async () => true) },
    mission: {
      review: vi.fn(async (_id: string, input: { decision: string }) => ({ mission_id: 'ms_one', decision: input.decision, result: 'raised', mission: view })),
      setMakingAllowance: vi.fn(async () => view),
      open: vi.fn(async () => ({ mission_id: 'ms_new', claim_id: 'pc_new', expires_at: new Date('2026-11-03T10:00:00Z') })),
    },
    agent: { getById: vi.fn(async () => ({ id: 'agt_owner' })) },
    fleet: { assertUnboundIssue: vi.fn(async () => {}) },
    passport: { findByJti: vi.fn(async () => null) },
    registries: { messageSenders: { list: () => [] } },
    audit: { write: vi.fn(async () => {}) },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  // A route's own rate limit is a `rateLimit` in its config: the owner's routes carry none.
  app.addHook('onRoute', (route) => {
    if ((route.config as { rateLimit?: unknown } | undefined)?.rateLimit) rateLimits.push(`${String(route.method)} ${route.url}`);
  });
  registerMissionsRoutes(app, services as never);
  await app.ready();
  return { app, services, rateLimits };
}

describe('POST /v1/missions/:id/review', () => {
  it('passes the owner\'s decision to the Mission and answers the result with the Mission', async () => {
    const { app, services } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/missions/ms_one/review', headers: { authorization: 'Bearer key' }, payload: { decision: 'raise', limit: 10 } });
    expect(response.statusCode).toBe(200);
    expect(services.mission.review).toHaveBeenCalledWith('ms_one', { operatorId: 'op_owner', decision: 'raise', limit: 10 });
    expect(response.json()).toMatchObject({ mission_id: 'ms_one', decision: 'raise', result: 'raised', mission: { max_actions: 4, paused_at: null } });
    expect(services.audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'mission.review.raise' }));
  });

  it('refuses an agent, a read-only member and a raise without its limit', async () => {
    const { app, services } = await makeApp();
    for (const token of ['agent', 'member-readonly']) {
      const response = await app.inject({ method: 'POST', url: '/v1/missions/ms_one/review', headers: { authorization: `Bearer ${token}` }, payload: { decision: 'continue' } });
      expect(response.statusCode).toBe(403);
    }
    const bad = await app.inject({ method: 'POST', url: '/v1/missions/ms_one/review', headers: { authorization: 'Bearer key' }, payload: { decision: 'raise' } });
    expect(bad.statusCode).toBe(400);
    expect(services.mission.review).not.toHaveBeenCalled();
  });

  it('lets a standard member decide', async () => {
    const { app } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/missions/ms_one/review', headers: { authorization: 'Bearer member-standard' }, payload: { decision: 'continue' } });
    expect(response.statusCode).toBe(200);
  });
});

describe('the owner routes for the limits of a Mission', () => {
  it('carry no rate limit of their own', async () => {
    const { rateLimits } = await makeApp();
    expect(rateLimits).toEqual([]);
  });

  it('take a making allowance of any size', async () => {
    const { app, services } = await makeApp();
    const response = await app.inject({ method: 'PUT', url: '/v1/missions/ms_one/making-allowance', headers: { authorization: 'Bearer key' }, payload: { making_orders_up_to_cents: 250_000_000 } });
    expect(response.statusCode).toBe(200);
    expect(services.mission.setMakingAllowance).toHaveBeenCalledWith('ms_one', 'op_owner', 250_000_000);
  });
});

describe('PUT /v1/missions/:id/making-allowance', () => {
  it('sets what the owner pre-approves of the Mission\'s making orders', async () => {
    const { app, services } = await makeApp();
    const response = await app.inject({ method: 'PUT', url: '/v1/missions/ms_one/making-allowance', headers: { authorization: 'Bearer key' }, payload: { making_orders_up_to_cents: 2_000 } });
    expect(response.statusCode).toBe(200);
    expect(services.mission.setMakingAllowance).toHaveBeenCalledWith('ms_one', 'op_owner', 2_000);
    expect(response.json()).toMatchObject({ making_orders_up_to_cents: 2_000 });
  });

  it('refuses an agent and a member who is not an admin', async () => {
    const { app, services } = await makeApp();
    for (const token of ['agent', 'member-standard']) {
      const response = await app.inject({ method: 'PUT', url: '/v1/missions/ms_one/making-allowance', headers: { authorization: `Bearer ${token}` }, payload: { making_orders_up_to_cents: 1 } });
      expect(response.statusCode).toBe(403);
    }
    expect(services.mission.setMakingAllowance).not.toHaveBeenCalled();
  });
});

describe('POST /v1/missions with limits', () => {
  it('opens with the cap behaviours, a cap of one day in a time zone, and the owner\'s making allowance', async () => {
    const { app, services } = await makeApp();
    const response = await app.inject({
      method: 'POST', url: '/v1/missions', headers: { authorization: 'Bearer key' },
      payload: {
        intent_summary: 'work', coverage_cap_cents: 500, coverage_cap_period: 'day', cap_time_zone: 'Europe/Stockholm',
        cap_behavior: { coverage_cap_cents: 'end_mission', max_actions: 'refuse_action' }, making_orders_up_to_cents: 3_000,
      },
    });
    expect(response.statusCode).toBe(201);
    expect(services.mission.open).toHaveBeenCalledWith(expect.objectContaining({
      coverage_cap_period: 'day', cap_time_zone: 'Europe/Stockholm', making_orders_up_to_cents: 3_000,
      cap_behavior: { coverage_cap_cents: 'end_mission', max_actions: 'refuse_action' },
    }));
  });

  it('refuses the earlier behaviours and an agent that pre-approves its own making orders', async () => {
    const { app, services } = await makeApp();
    const old = await app.inject({ method: 'POST', url: '/v1/missions', headers: { authorization: 'Bearer key' }, payload: { intent_summary: 'work', cap_behavior: { max_actions: 'auto_revoke' } } });
    expect(old.statusCode).toBe(400);
    const self = await app.inject({ method: 'POST', url: '/v1/missions', headers: { authorization: 'Bearer agent' }, payload: { intent_summary: 'work', making_orders_up_to_cents: 100 } });
    expect(self.statusCode).toBe(403);
    const plain = await app.inject({ method: 'POST', url: '/v1/missions', headers: { authorization: 'Bearer agent' }, payload: { intent_summary: 'work', max_actions: 5 } });
    expect(plain.statusCode).toBe(201);
    expect(services.mission.open).toHaveBeenCalledTimes(1);
  });
});
