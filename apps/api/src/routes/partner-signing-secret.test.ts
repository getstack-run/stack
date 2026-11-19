import { describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { NotFoundError } from '@stack/shared';
import { registerPartnerRoutes } from './partner.js';
import { requirePartner } from '../middleware/require-platform.js';
import { errorHandler } from '../middleware/error-handler.js';

describe('partner account human signing setup', () => {
  it.each([
    ['owner', {}, 'tenant_owned', 'wh_owned', 200],
    ['downstream', {}, 'tenant_owned', 'wh_owned', 200],
    ['invalid body', {}, 'tenant_owned', 'wh_owned', 400],
    ['admin', { memberId: 'mem_fixture', memberRole: 'admin' }, 'tenant_owned', 'wh_owned', 200],
    ['standard', { memberId: 'mem_fixture', memberRole: 'standard' }, 'tenant_owned', 'wh_owned', 403],
    ['agent', { agentId: 'agt_fixture' }, 'tenant_owned', 'wh_owned', 403],
    ['OAuth', { oauthScope: 'partner:write' }, 'tenant_owned', 'wh_owned', 403],
    ['foreign tenant', {}, 'tenant_foreign', 'wh_owned', 404],
    ['foreign endpoint', {}, 'tenant_owned', 'wh_foreign', 404],
    ['not partner', { isPartner: false }, 'tenant_owned', 'wh_owned', 403],
  ] as const)('enforces %s ownership and authority', async (_name, context, tenant, webhook, status) => {
    const app = Fastify();
    app.setErrorHandler(errorHandler);
    app.addHook('preHandler', async request => { Object.assign(request, { operatorId: 'partner_fixture', isPartner: true }, context); });
    app.addHook('preHandler', requirePartner);
    const owned = vi.fn(async (id: string, partnerId: string) => {
      if (id !== 'tenant_owned' || partnerId !== 'partner_fixture') throw new NotFoundError('account', id);
    });
    const setter = vi.fn(async (id: string, ownerId: string, _secret: string) => {
      if (id !== 'wh_owned' || ownerId !== 'tenant_owned') throw new NotFoundError('webhook', id);
      return { configured: true };
    });
    const audit = vi.fn();
    registerPartnerRoutes(app, { partnerTenants: { assertTenantOwnership: owned }, inboundWebhooks: { setProviderSigningSecret: setter }, audit: { write: audit } } as never);
    const secret = 'synthetic-fixture-only-01234567890123456789';
    const downstream = _name === 'downstream' ? 'synthetic-downstream-only-01234567890123' : undefined;
    const response = await app.inject({ method: 'PUT', url: `/v1/partner/accounts/${tenant}/inbound-webhooks/${webhook}/provider-signing-secret`, payload: _name === 'invalid body' ? {} : { signing_secret: secret, ...(downstream ? { downstream_signing_secret: downstream } : {}) } });
    await app.close();
    expect(response.statusCode).toBe(status);
    expect(response.body).not.toContain(secret);
    expect(JSON.stringify(audit.mock.calls)).not.toContain(secret);
    if (status === 200) {
      expect(response.json()).toEqual({ configured: true });
      expect(setter).toHaveBeenCalledWith('wh_owned', 'tenant_owned', secret, downstream);
    } else if (webhook !== 'wh_foreign') expect(setter).not.toHaveBeenCalled();
  });
});
