import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { registerAuthorityRoutes } from './authority.js';
import { fakeEntitlements } from '../test/entitlements.js';

describe('agent authority list HTTP contract', () => {
  async function setup() {
    const listAgentBindings = vi.fn(async () => ({ items: [], principals: [], receivers: [], proofs: [], page: 2, limit: 10, has_more: false }));
    const listBindings = vi.fn(async () => []);
    const listAgentAuthorityUses = vi.fn(async () => ({ items: [], presentations: [], page: 2, limit: 10, has_more: false }));
    const getById = vi.fn(async (id: string) => {
      if (id === 'agt_foreign') throw Object.assign(new Error('Agent not found'), { statusCode: 404 });
      return { id, operator_id: 'op_owned' };
    });
    const app = Fastify();
    registerAuthorityRoutes(app, {
      entitlements: fakeEntitlements(), operator: { authenticateByApiKey: vi.fn(async () => ({
        id: 'op_owned', tier: 'pro', status: 'active', is_admin: true,
        is_platform_staff: false, is_partner: false, stripe_customer_id: null,
      })) },
      agent: { getById },
      authority: { listAgentBindings, listBindings, listAgentAuthorityUses },
    } as never);
    return { app, listAgentBindings, listBindings, listAgentAuthorityUses, getById };
  }

  it('passes only the authenticated operator and bounded agent/page to the read model', async () => {
    const { app, listAgentBindings, listBindings } = await setup();
    try {
      const response = await app.inject({ method: 'GET',
        url: '/v1/authority/bindings?agent_id=agt_other&page=2&limit=10&operator_id=op_attacker',
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(response.statusCode).toBe(200);
      expect(listAgentBindings).toHaveBeenCalledWith('op_owned', 'agt_other', 2, 10, undefined);
      expect(listBindings).not.toHaveBeenCalled();
      expect(response.json()).toMatchObject({ items: [], page: 2, limit: 10, has_more: false });
    } finally { await app.close(); }
  });

  it('preserves the account-wide inspector contract without an agent filter', async () => {
    const { app, listAgentBindings, listBindings } = await setup();
    try {
      const response = await app.inject({ method: 'GET', url: '/v1/authority/bindings',
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ bindings: [] });
      expect(listBindings).toHaveBeenCalledWith('op_owned');
      expect(listAgentBindings).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });

  it('opens an exact binding version without dropping the agent scope and rejects partial links', async () => {
    const { app, listAgentBindings, getById } = await setup();
    try {
      const response = await app.inject({ method: 'GET',
        url: '/v1/authority/bindings?agent_id=agt_one&binding_id=abn_old&binding_version=7',
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(response.statusCode).toBe(200);
      expect(getById).toHaveBeenCalledWith('agt_one', 'op_owned');
      expect(listAgentBindings).toHaveBeenCalledWith('op_owned', 'agt_one', 1, 20, { id: 'abn_old', version: 7 });
      listAgentBindings.mockClear();
      for (const query of ['agent_id=agt_one&binding_id=abn_old', 'agent_id=agt_one&binding_version=7',
        'binding_id=abn_old&binding_version=7', 'agent_id=agt_one&binding_id=abn_old&binding_version=0']) {
        const invalid = await app.inject({ method: 'GET', url: `/v1/authority/bindings?${query}`,
          headers: { authorization: 'Bearer sk_live_test' } });
        expect(invalid.statusCode).toBeGreaterThanOrEqual(400);
      }
      expect(listAgentBindings).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });

  it('returns 404 for a foreign agent without querying authority or use records', async () => {
    const { app, listAgentBindings, listAgentAuthorityUses, getById } = await setup();
    try {
      for (const resource of ['bindings', 'uses']) {
        const response = await app.inject({ method: 'GET', url: `/v1/authority/${resource}?agent_id=agt_foreign`,
          headers: { authorization: 'Bearer sk_live_test' } });
        expect(response.statusCode).toBe(404);
      }
      expect(getById).toHaveBeenCalledWith('agt_foreign', 'op_owned');
      expect(listAgentBindings).not.toHaveBeenCalled();
      expect(listAgentAuthorityUses).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });

  it('pages uses for the exact binding version and rejects partial binding filters', async () => {
    const { app, listAgentAuthorityUses } = await setup();
    try {
      const response = await app.inject({ method: 'GET',
        url: '/v1/authority/uses?agent_id=agt_one&binding_id=abn_one&binding_version=2&page=2&limit=10',
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(response.statusCode).toBe(200);
      expect(listAgentAuthorityUses).toHaveBeenCalledWith('op_owned', 'agt_one', 2, 10, { id: 'abn_one', version: 2 });
      listAgentAuthorityUses.mockClear();
      for (const query of ['agent_id=agt_one&binding_id=abn_one', 'binding_id=abn_one&binding_version=2']) {
        const invalid = await app.inject({ method: 'GET', url: `/v1/authority/uses?${query}`,
          headers: { authorization: 'Bearer sk_live_test' } });
        expect(invalid.statusCode).toBeGreaterThanOrEqual(400);
      }
      expect(listAgentAuthorityUses).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });

  it('rejects invalid pagination without reading authority records', async () => {
    const { app, listAgentBindings } = await setup();
    try {
      for (const query of ['limit=51', 'page=0', 'page=1.5', 'agent_id=invalid']) {
        const response = await app.inject({ method: 'GET', url: `/v1/authority/bindings?agent_id=agt_one&${query}`,
          headers: { authorization: 'Bearer sk_live_test' } });
        expect(response.statusCode).toBeGreaterThanOrEqual(400);
      }
      expect(listAgentBindings).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });
});
