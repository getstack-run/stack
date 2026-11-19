import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NotFoundError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['operatorId'] = token === 'foreign' ? 'op_other' : 'op_owner';
    request['operatorTier'] = 'enterprise';
    if (token === 'owner' || token === 'sibling') request['agentId'] = `agt_${token}`;
  },
}));
vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => {}) }));

import { registerMissionsRoutes } from './missions.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map(app => app.close())); });

async function makeApp() {
  const findById = vi.fn(async (_id: string, scope?: unknown) => scope ? null : ({ operator_id: 'op_owner' }));
  const listByOperator = vi.fn(async () => ({ items: [], total: 0 }));
  const complete = vi.fn(async (_id: string, input: { actor: { operatorId: string; agentId?: string } }) => {
    if (input.actor.agentId && input.actor.agentId !== 'agt_owner') throw new NotFoundError('mission', 'ms_work');
    return { mission_id: 'ms_work', claim_id: 'pc_done', terminal_state: 'completed_successful', completed_at: new Date(), transitioned: true };
  });
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerMissionsRoutes(app, {
    mission: { findById, listByOperator, complete },
    agent: { getById: async () => ({}) },
    audit: { write: async () => {} },
    entitlements: { controlsEnabled: async () => true },
  } as never);
  await app.ready();
  return { app, complete, findById, listByOperator };
}

describe('Mission reads bind to the authenticated worker', () => {
  it.each(['', '/replay', '/dossiers'])('restricts %s to the authenticated agent', async suffix => {
    const { app, findById } = await makeApp();
    const response = await app.inject({ method: 'GET', url: `/v1/missions/ms_work${suffix}`,
      headers: { authorization: 'Bearer sibling' } });
    expect(response.statusCode).toBe(404);
    expect(findById).toHaveBeenCalledWith('ms_work', { operatorId: 'op_owner', agentId: 'agt_sibling' });
  });

  it.each(['', '/replay', '/dossiers'])('rejects query impersonation on %s', async suffix => {
    const { app, findById } = await makeApp();
    const response = await app.inject({ method: 'GET', url: `/v1/missions/ms_work${suffix}?agent_id=agt_owner`,
      headers: { authorization: 'Bearer sibling' } });
    expect(response.statusCode).toBe(403);
    expect(findById).not.toHaveBeenCalled();
  });

  it('filters the list to the worker and denies an alternate agent filter', async () => {
    const { app, listByOperator } = await makeApp();
    expect((await app.inject({ method: 'GET', url: '/v1/missions', headers: { authorization: 'Bearer sibling' } })).statusCode).toBe(200);
    expect(listByOperator).toHaveBeenCalledWith('op_owner', { agentId: 'agt_sibling' });
    expect((await app.inject({ method: 'GET', url: '/v1/missions?agent_id=agt_owner', headers: { authorization: 'Bearer sibling' } })).statusCode).toBe(403);
  });
});

describe('Mission completion authenticated actor propagation', () => {
  it('does not accept a body-supplied completion identity', async () => {
    const { app, complete } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/missions/ms_work/complete',
      headers: { authorization: 'Bearer sibling' },
      payload: { actor: { operatorId: 'op_owner', agentId: 'agt_owner' } },
    });
    expect(response.statusCode).toBe(404);
    expect(complete).toHaveBeenCalledWith('ms_work', { actor: { operatorId: 'op_owner', agentId: 'agt_sibling' } });
  });

  it.each(['owner', 'operator'])('passes authenticated %s scope to the lifecycle service', async token => {
    const { app, complete } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/missions/ms_work/complete', headers: { authorization: `Bearer ${token}` }, payload: {} });
    expect(response.statusCode).toBe(200);
    expect(complete).toHaveBeenCalledWith('ms_work', { actor: { operatorId: 'op_owner', ...(token === 'owner' ? { agentId: 'agt_owner' } : {}) } });
  });

  it('hides other operators missions before completion', async () => {
    const { app, complete } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/missions/ms_work/complete', headers: { authorization: 'Bearer foreign' }, payload: {} });
    expect(response.statusCode).toBe(404);
    expect(complete).not.toHaveBeenCalled();
  });
});
