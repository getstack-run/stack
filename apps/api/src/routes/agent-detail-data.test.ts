import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NotFoundError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request['operatorId'] = 'op_owner';
    const headers = request['headers'] as Record<string, string>;
    if (headers['authorization'] === 'Bearer agent') request['agentId'] = 'agt_owner';
  },
}));
vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn() }));
import { registerMissionsRoutes } from './missions.js';
import { registerIntentsRoutes } from './intents.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });
const now = new Date();
const row = { id: 'ia_one', operator_id: 'op_owner', agent_id: 'agt_owner', passport_jti: 'pas_one',
  intent_claim_id: 'pc_one', simulated_claim_id: null, status: 'pending', requested_at: now,
  expires_at: now, decided_at: null, decided_by_member_id: null, notes: null, block_future: false };
const body = { type: 'intent_claim', intent_type: 'http_call', agent_id: 'agt_owner',
  named_intent: 'github:issues:create', target: 'github', action: 'POST /issues', reason: 'Report a bug',
  parameters: { authorization: 'PRIVATE_SECRET' }, user_subject: 'PRIVATE_IDENTITY',
  submitted_at: 1780000000000,
  estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: null }, requires: [], mission_ref: null };

async function setup(claimOverride = {}) {
  const services = {
    agent: { getById: vi.fn(async (id: string, op: string) => {
      if (id !== 'agt_owner' || op !== 'op_owner') throw new NotFoundError('Agent', id);
      return { id, operator_id: op };
    }) },
    mission: {
      listByOperator: vi.fn(async () => ({ items: [], total: 65, page: 2, limit: 50, has_more: false })),
      findById: vi.fn(async (_id: string, scope?: { agentId?: string }) => scope?.agentId ? null : ({ operator_id: 'op_owner' })),
      listPassports: vi.fn(async () => ({ items: [], total: 0, page: 1, limit: 20, has_more: false })),
    },
    intentApproval: {
      listPending: vi.fn(async () => ({ items: [], total: 65, page: 2, limit: 50, has_more: false })),
      findById: vi.fn(async () => row), approve: vi.fn(), reject: vi.fn(),
    },
    authority: { listPassportAuthorityRefsForPassports: vi.fn(async () => new Map()) },
    passportClaimsRepo: { findByClaimId: vi.fn(async () => ({ operator_id: 'op_owner', passport_id: 'pas_one', type: 'intent_claim', body_json: body, ...claimOverride })) },
    // Controls on: the record these routes read is a controls feature.
    entitlements: { controlsEnabled: async () => true },
  };
  const app = Fastify(); apps.push(app);
  app.setErrorHandler(errorHandler);
  registerMissionsRoutes(app, services as never);
  registerIntentsRoutes(app, services as never);
  await app.ready();
  return { app, services };
}

describe('agent detail read contracts', () => {
  it.each(['/v1/missions', '/v1/intents/pending'])('passes agent filter before page retrieval: %s', async (path) => {
    const { app, services } = await setup();
    const result = await app.inject(`${path}?agent_id=agt_owner&page=2&limit=50`);
    expect(result.statusCode).toBe(200);
    const reader = path.includes('pending') ? services.intentApproval.listPending : services.mission.listByOperator;
    expect(reader).toHaveBeenCalledWith('op_owner', { agentId: 'agt_owner', page: 2, limit: 50 });
    expect(result.json()).toMatchObject({ total: 65, has_more: false });
  });
  it.each(['/v1/missions', '/v1/intents/pending'])('hides foreign and unknown agents: %s', async (path) => {
    const { app, services } = await setup();
    expect((await app.inject(`${path}?agent_id=agt_foreign`)).statusCode).toBe(404);
    expect(services.mission.listByOperator).not.toHaveBeenCalled();
    expect(services.intentApproval.listPending).not.toHaveBeenCalled();
  });
  it.each(['', '/replay', '/dossiers'])('rejects a mission not belonging to the selected agent: %s', async (suffix) => {
    const { app, services } = await setup();
    expect((await app.inject(`/v1/missions/ms_one${suffix}?agent_id=agt_owner`)).statusCode).toBe(404);
    expect(services.mission.findById).toHaveBeenCalledWith('ms_one', { operatorId: 'op_owner', agentId: 'agt_owner' });
  });
  it('projects review details without request parameters or identity', async () => {
    const { app } = await setup();
    const result = await app.inject('/v1/intents/ia_one?review=1');
    expect(result.statusCode).toBe(200);
    expect(result.json().intent).toMatchObject({ target: 'github', action: 'POST /issues' });
    expect(result.body).not.toContain('PRIVATE_');
    expect((await app.inject('/v1/intents/ia_one')).json()).not.toHaveProperty('intent');
  });
  it.each([{ operator_id: 'op_foreign' }, { passport_id: 'pas_wrong' }, { body_json: { ...body, agent_id: 'agt_other' } }])('fails closed on mismatched review proof %j', async (overrides) => {
    const { app } = await setup(overrides);
    expect((await app.inject('/v1/intents/ia_one?review=1')).statusCode).toBe(404);
  });
  it.each(['agent'])('rejects %s context from expanded reads and decisions', async (principal) => {
    const { app, services } = await setup();
    const headers = { authorization: `Bearer ${principal}` };
    expect((await app.inject({ url: '/v1/intents/ia_one?review=1', headers })).statusCode).toBe(403);
    expect((await app.inject({ url: '/v1/missions/ms_one/passports', headers })).statusCode).toBe(403);
    for (const action of ['approve', 'reject']) {
      expect((await app.inject({ method: 'POST', url: `/v1/intents/ia_one/${action}`, headers, payload: {} })).statusCode).toBe(403);
    }
    expect(services.intentApproval.approve).not.toHaveBeenCalled();
    expect(services.intentApproval.reject).not.toHaveBeenCalled();
  });
});
