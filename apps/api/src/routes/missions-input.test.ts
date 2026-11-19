import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';

/**
 * POST /v1/missions picks between a fleet-mission start and an ordinary open
 * from the keys in the body. Neither shape may be read from an unvalidated
 * cast: a malformed body is a 400 with the standard validation envelope, and
 * a valid one still reaches the service.
 */

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['operatorId'] = 'op_owner';
    if (token === 'agent') request['agentId'] = 'agt_self';
  },
}));
vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => {}) }));

const { registerMissionsRoutes } = await import('./missions.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const open = vi.fn(async () => ({
    mission_id: 'ms_new',
    claim_id: 'pc_open',
    expires_at: new Date(Date.now() + 900_000),
  }));
  const fleetStart = vi.fn();
  const assertUnboundIssue = vi.fn(async () => {});
  const services = {
    entitlements: { controlsEnabled: vi.fn(async () => true) },
    mission: { open },
    fleet: { start: fleetStart, assertUnboundIssue },
    audit: { write: vi.fn(async () => {}) },
  } as unknown as Services;
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerMissionsRoutes(app, services);
  await app.ready();
  return { app, open, fleetStart };
}

function post(app: ReturnType<typeof Fastify>, payload: unknown, token = 'operator') {
  return app.inject({
    method: 'POST',
    url: '/v1/missions',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });
}

describe('POST /v1/missions body handling', () => {
  it.each([
    ['an array', []],
    ['a string', 'open a mission'],
    ['an object missing intent_summary', { max_actions: 5 }],
    ['an intent_summary of the wrong type', { intent_summary: 42 }],
  ])('rejects %s with the validation envelope', async (_label, payload) => {
    const { app, open } = await makeApp();
    const res = await post(app, payload);
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('VALIDATION_ERROR');
    expect(open).not.toHaveBeenCalled();
  });

  it.each([
    ['max_actions', { max_actions: 2_147_483_648 }],
    ['max_duration_seconds', { max_duration_seconds: 2_147_483_648 }],
    ['max_concurrent_intents', { max_concurrent_intents: 2_147_483_648 }],
    ['a per-service action limit', { max_actions_per_service: { stripe: 2_147_483_648 } }],
  ])('refuses %s above what its column holds with a 400, never a 500', async (_label, limit) => {
    const { app, open } = await makeApp();
    const res = await post(app, { intent_summary: 'a limit too large to store', ...limit });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('VALIDATION_ERROR');
    expect(open).not.toHaveBeenCalled();
  });

  it('takes the largest value its column holds', async () => {
    const { app, open } = await makeApp();
    const res = await post(app, { intent_summary: 'the largest limits', max_actions: 2_147_483_647, max_duration_seconds: 2_147_483_647, max_concurrent_intents: 2_147_483_647 });
    expect(res.statusCode).toBe(201);
    expect(open).toHaveBeenCalledTimes(1);
  });

  it('rejects an empty body with the validation envelope', async () => {
    const { app, open } = await makeApp();
    const res = await app.inject({ method: 'POST', url: '/v1/missions', headers: { authorization: 'Bearer operator' } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('VALIDATION_ERROR');
    expect(open).not.toHaveBeenCalled();
  });

  it('opens a mission for a valid ordinary body', async () => {
    const { app, open } = await makeApp();
    const res = await post(app, { intent_summary: 'Send the weekly digest', max_actions: 20 });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ mission_id: 'ms_new', claim_id: 'pc_open' });
    expect(open).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_owner',
      intent_summary: 'Send the weekly digest',
      max_actions: 20,
    }));
  });

  it('treats a body with a fleet key as a fleet start, which needs an agent caller', async () => {
    const { app, open, fleetStart } = await makeApp();
    const res = await post(app, { fleet_policy_id: 'flp_1' });
    expect(res.statusCode).toBe(403);
    expect(open).not.toHaveBeenCalled();
    expect(fleetStart).not.toHaveBeenCalled();
  });

  it('validates a fleet start body with the fleet schema', async () => {
    const { app, fleetStart } = await makeApp();
    const res = await post(app, { fleet_policy_id: 42 }, 'agent');
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('VALIDATION_ERROR');
    expect(fleetStart).not.toHaveBeenCalled();
  });
});
