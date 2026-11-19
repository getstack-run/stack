import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { registerAuthorityRoutes } from './authority.js';
import { fakeEntitlements } from '../test/entitlements.js';

describe('account authority list HTTP contract', () => {
  function setup() {
    const listAccountRecords = vi.fn(async () => ({ principals: [], page: 1, limit: 20, has_more: false }));
    const listPrincipals = vi.fn(async () => []);
    const listProofs = vi.fn(async () => []);
    const listReceivers = vi.fn(async () => []);
    const app = Fastify();
    registerAuthorityRoutes(app, {
      entitlements: fakeEntitlements(), operator: { authenticateByApiKey: vi.fn(async () => ({ id: 'op_owned', tier: 'pro', status: 'active',
        is_admin: true, is_platform_staff: false, is_partner: false, stripe_customer_id: null })) },
      authority: { listAccountRecords, listPrincipals, listProofs, listReceivers },
    } as never);
    return { app, listAccountRecords, listPrincipals, listProofs, listReceivers };
  }

  it.each(['principals', 'proofs', 'receivers'])('preserves no-query %s and bounds explicit pages', async (kind) => {
    const { app, listAccountRecords } = setup();
    try {
      const legacy = await app.inject({ method: 'GET', url: `/v1/authority/${kind}`,
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(legacy.statusCode).toBe(200);
      expect(legacy.json()).toEqual({ [kind]: [] });
      expect(listAccountRecords).not.toHaveBeenCalled();
      const paged = await app.inject({ method: 'GET', url: `/v1/authority/${kind}?page=2&limit=10&operator_id=op_foreign`,
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(paged.statusCode).toBe(200);
      expect(listAccountRecords).toHaveBeenCalledWith('op_owned', kind, 2, 10, undefined);
    } finally { await app.close(); }
  });

  it('passes the exact selected proof version and rejects incomplete or invalid pages', async () => {
    const { app, listAccountRecords } = setup();
    try {
      const response = await app.inject({ method: 'GET',
        url: '/v1/authority/proofs?related=bindings&record_id=apf_one&version=3',
        headers: { authorization: 'Bearer sk_live_test' } });
      expect(response.statusCode).toBe(200);
      expect(listAccountRecords).toHaveBeenCalledWith('op_owned', 'proofs', 1, 20, { id: 'apf_one', version: 3 });
      listAccountRecords.mockClear();
      for (const query of ['page=0', 'limit=51', 'related=bindings&record_id=apf_one',
        'record_id=apf_one&version=3', 'related=bindings&version=3', 'related=other']) {
        const invalid = await app.inject({ method: 'GET', url: `/v1/authority/proofs?${query}`,
          headers: { authorization: 'Bearer sk_live_test' } });
        expect(invalid.statusCode).toBeGreaterThanOrEqual(400);
      }
      expect(listAccountRecords).not.toHaveBeenCalled();
    } finally { await app.close(); }
  });
});
