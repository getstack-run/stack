import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import { registerPassportRoutes } from './passports.js';

// The authentication middleware has its own real-credential suites. These
// HTTP checks exercise the route's handling of the authenticated principal.
const context = vi.hoisted(() => ({ actor: {} as Record<string, unknown> }));
const meter = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => Object.assign(request, context.actor),
}));
vi.mock('../middleware/meter.js', () => ({ meterAction: meter, meterPassportUpkeep: meter }));

describe('Passport continuation HTTP authorization', () => {
  const apps: ReturnType<typeof Fastify>[] = [];
  beforeEach(() => {
    context.actor = { operatorId: 'op_one', agentId: 'agt_self', operatorTier: 'developer' };
    meter.mockClear();
  });
  afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

  function fixture(owner = 'agt_self') {
    const app = Fastify();
    apps.push(app);
    app.setErrorHandler(createErrorHandler());
    const issued = { token: 'synthetic-local-token', jti: 'pas_new', expires_at: new Date(Date.now() + 60_000) };
    const issue = vi.fn(async () => issued);
    const refresh = vi.fn(async () => issued);
    const delegate = vi.fn(async () => issued);
    const getById = vi.fn(async (id: string) => ({ id }));
    registerPassportRoutes(app, {
      signer: { verify: vi.fn(async () => ({ stk: { operator_id: 'op_one', agent_id: owner } })) },
      passport: { issue, refresh, delegate }, agent: { getById },
      fleet: { issueFromMission: vi.fn(async () => null) },
      audit: { write: vi.fn(async () => undefined) },
      analytics: { fireOnce: vi.fn() },
    } as never);
    return { app, issue, refresh, delegate };
  }

  it('refuses root issuance by an inbound Passport before metering or signing', async () => {
    context.actor.passportContext = { jti: 'pas_restricted' };
    const { app, issue } = fixture();
    const response = await app.inject({ method: 'POST', url: '/v1/passports/issue', payload: { agent_id: 'agt_self', mission_ids: ['ms_self'] } });
    expect(response.statusCode).toBe(403);
    expect(issue).not.toHaveBeenCalled();
    expect(meter).not.toHaveBeenCalled();
  });

  it('allows an agent identity to issue its own preassigned authority', async () => {
    const { app, issue } = fixture();
    const response = await app.inject({ method: 'POST', url: '/v1/passports/issue', payload: { agent_id: 'agt_self', mission_ids: ['ms_self'] } });
    expect(response.statusCode).toBe(201);
    expect(issue).toHaveBeenCalledOnce();
  });

  for (const operation of ['refresh', 'delegate'] as const) {
    it(`refuses ${operation} of another agent's Passport before metering`, async () => {
      const { app, refresh, delegate } = fixture('agt_other');
      const payload = operation === 'refresh' ? { token: 'synthetic' }
        : { parent_passport_token: 'synthetic', child_agent_id: 'agt_child', scopes: [] };
      const response = await app.inject({ method: 'POST', url: `/v1/passports/${operation}`, payload });
      expect(response.statusCode).toBe(403);
      expect(refresh).not.toHaveBeenCalled();
      expect(delegate).not.toHaveBeenCalled();
      expect(meter).not.toHaveBeenCalled();
    });

    it(`allows ${operation} of the authenticated agent's own Passport`, async () => {
      const { app, refresh, delegate } = fixture();
      const payload = operation === 'refresh' ? { token: 'synthetic' }
        : { parent_passport_token: 'synthetic', child_agent_id: 'agt_child', scopes: [] };
      const response = await app.inject({ method: 'POST', url: `/v1/passports/${operation}`, payload });
      expect(response.statusCode).toBe(201);
      expect(operation === 'refresh' ? refresh : delegate).toHaveBeenCalledOnce();
    });
  }

});
