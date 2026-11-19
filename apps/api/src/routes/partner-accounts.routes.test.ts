import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { TenantTierNotAllowedError } from '@stack/vault';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';
import { fakeEntitlements } from '../test/entitlements.js';
import { registerPartnerRoutes } from './partner.js';

/**
 * Partner-managed account routes: opening is idempotent on the partner's reference and refuses a plan, closing
 * cascades to the account's webhooks and passports and is safe to retry, a lost key is replaced, and inviting the
 * customer stores the address only as an invited read-only member. That an account passport issued by the partner is
 * metered on the pool is the hosted meter's, covered by the deployment's own tests.
 */

function buildServices(options: { mail?: boolean } = {}) {
  const webhooks = new Map([
    ['iwh_1', { id: 'iwh_1', revoked: false }],
    ['iwh_2', { id: 'iwh_2', revoked: false }],
  ]);
  let accountActive = true;
  const billingAccounts = { ...fakeEntitlements(), evict: vi.fn() };
  const sent: Array<{ to: string; text: string }> = [];
  const services = {
    partnerTenants: {
      createTenant: vi.fn(async (_partner: string, input: Record<string, unknown>) => {
        if ('tier' in input) throw new TenantTierNotAllowedError();
        return { account_id: 'op_account', external_ref: input['external_ref'], billing: 'partner', status: 'active', created: true, created_at: 'now', api_key: 'sk_live_x' };
      }),
      listTenants: vi.fn(async () => []),
      rotateKey: vi.fn(async (id: string) => ({ account_id: id, api_key: 'sk_live_new' })),
      revokeTenant: vi.fn(async () => {
        const transitioned = accountActive;
        accountActive = false;
        return { transitioned };
      }),
      assertTenantOwnership: vi.fn(async () => ({ id: 'op_account' })),
    },
    inboundWebhooks: {
      list: vi.fn(async () => [...webhooks.values()].map((w) => ({ id: w.id }))),
      revoke: vi.fn(async (id: string) => {
        const hook = webhooks.get(id)!;
        const transitioned = !hook.revoked;
        hook.revoked = true;
        return { transitioned };
      }),
    },
    passport: {
      revokeAllForOperator: vi.fn()
        .mockResolvedValueOnce([{ jti: 'p1' }, { jti: 'p2' }, { jti: 'p3' }])
        .mockResolvedValue([]),
      issue: vi.fn(async () => ({ jti: 'pas_new' })),
    },
    member: {
      invite: vi.fn(async (_op: string, input: { email: string; role: string }) => ({
        member: { id: 'mem_1', email: input.email, invite_expires_at: new Date('2026-11-01T00:00:00Z') },
        inviteToken: 'inv_' + 'a'.repeat(32),
      })),
      revoke: vi.fn(async () => undefined),
    },
    operator: { getById: vi.fn(async () => ({ id: 'op_partner', email: 'ops@partner.example' })) },
    features: { require: vi.fn() },
    authEmail: options.mail === false ? null : {
      sendEmail: vi.fn(async (to: string, _subject: string, text: string) => { sent.push({ to, text }); }),
    },
    billingAccounts,
    entitlements: billingAccounts,
    audit: { write: vi.fn(async () => {}) },
    // The account action meter counts in one Lua step: [count, cents due, accrual taken, units].
    redis: { incr: vi.fn(async () => 1), expire: vi.fn(), decr: vi.fn(), eval: vi.fn(async () => [1, 0, 0, 0]) },
    wallet: {},
    claimRegistry: {},
  };
  return { services, sent };
}

async function buildApp(services: ReturnType<typeof buildServices>['services']) {
  const app = Fastify({ logger: false });
  app.setErrorHandler(createErrorHandler());
  app.addHook('onRequest', async (request) => {
    Object.assign(request, { operatorId: 'op_partner', operatorTier: 'enterprise', isPartner: true });
  });
  registerPartnerRoutes(app, services as unknown as Services);
  await app.ready();
  return app;
}

describe('partner-managed account routes', () => {
  it('passes the choice to open the account with its controls on, and refuses a value that is not a boolean', async () => {
    const { services } = buildServices();
    const app = await buildApp(services);
    try {
      const on = await app.inject({ method: 'POST', url: '/v1/partner/accounts', payload: { external_ref: 'cust_c', controls: true } });
      expect(on.statusCode).toBe(201);
      expect(services.partnerTenants.createTenant).toHaveBeenLastCalledWith(expect.any(String), { external_ref: 'cust_c', controls: true });
      const off = await app.inject({ method: 'POST', url: '/v1/partner/accounts', payload: { external_ref: 'cust_d' } });
      expect(off.statusCode).toBe(201);
      expect(services.partnerTenants.createTenant).toHaveBeenLastCalledWith(expect.any(String), { external_ref: 'cust_d' });
      const bad = await app.inject({ method: 'POST', url: '/v1/partner/accounts', payload: { external_ref: 'cust_e', controls: 'yes' } });
      expect(bad.statusCode).toBe(400);
    } finally {
      await app.close();
    }
  });

  it('opens an account under the partner reference and shows its key once, with no store', async () => {
    const { services } = buildServices();
    const app = await buildApp(services);
    try {
      const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts', payload: { external_ref: 'cust_1' } });
      expect(response.statusCode).toBe(201);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.json()).toMatchObject({ account_id: 'op_account', external_ref: 'cust_1', created: true, api_key: 'sk_live_x' });
      expect(services.audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'partner.account.create' }));
    } finally {
      await app.close();
    }
  });

  it('answers a repeat of the same reference with 200 and no key, and writes no second audit row', async () => {
    const { services } = buildServices();
    services.partnerTenants.createTenant.mockResolvedValueOnce({
      account_id: 'op_account', external_ref: 'cust_1', billing: 'partner', status: 'active', created: false, created_at: 'now',
    } as never);
    const app = await buildApp(services);
    try {
      const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts', payload: { external_ref: 'cust_1' } });
      expect(response.statusCode).toBe(200);
      expect(response.json()).not.toHaveProperty('api_key');
      expect(services.audit.write).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it('refuses a tier on create by name', async () => {
    const { services } = buildServices();
    const app = await buildApp(services);
    try {
      const response = await app.inject({
        method: 'POST', url: '/v1/partner/accounts', payload: { external_ref: 'c1', tier: 'enterprise' },
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ error: { code: 'TENANT_TIER_NOT_ALLOWED' } });
    } finally {
      await app.close();
    }
  });

  it('needs the reference, and rejects unknown create fields rather than ignoring them', async () => {
    const { services } = buildServices();
    const app = await buildApp(services);
    try {
      for (const payload of [{}, { plan: 'enterprise', external_ref: 'c' }, { external_ref: '' }, { external_ref: 'x'.repeat(257) }]) {
        const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts', payload });
        expect(response.statusCode).toBe(400);
      }
      expect(services.partnerTenants.createTenant).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it('closing cascades to webhooks and passports and a retry finishes cleanly', async () => {
    const { services } = buildServices();
    const app = await buildApp(services);
    try {
      const first = await app.inject({ method: 'DELETE', url: '/v1/partner/accounts/op_account' });
      expect(first.statusCode).toBe(200);
      expect(first.json()).toEqual({ transitioned: true, webhooks_revoked: 2, passports_revoked: 3 });
      expect(services.billingAccounts.evict).toHaveBeenCalledWith('op_account');

      const retry = await app.inject({ method: 'DELETE', url: '/v1/partner/accounts/op_account' });
      expect(retry.statusCode).toBe(200);
      expect(retry.json()).toEqual({ transitioned: false, webhooks_revoked: 0, passports_revoked: 0 });
      // The cascade still ran on the retry: every webhook was asked again.
      expect(services.inboundWebhooks.revoke).toHaveBeenCalledTimes(4);
    } finally {
      await app.close();
    }
  });

  it('replaces a lost key for an administrator of the partner account, never for OAuth', async () => {
    const { services } = buildServices();
    const app = await buildApp(services);
    try {
      const ok = await app.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/rotate-key' });
      expect(ok.statusCode).toBe(200);
      expect(ok.headers['cache-control']).toBe('no-store');
      expect(ok.json()).toEqual({ account_id: 'op_account', api_key: 'sk_live_new' });
    } finally {
      await app.close();
    }
    const oauth = Fastify({ logger: false });
    oauth.setErrorHandler(createErrorHandler());
    oauth.addHook('onRequest', async (request) => {
      Object.assign(request, { operatorId: 'op_partner', operatorTier: 'enterprise', isPartner: true, oauthScope: 'partner:write' });
    });
    registerPartnerRoutes(oauth, services as unknown as Services);
    await oauth.ready();
    try {
      const refused = await oauth.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/rotate-key' });
      expect(refused.statusCode).toBe(403);
      expect(services.partnerTenants.rotateKey).toHaveBeenCalledTimes(1);
    } finally {
      await oauth.close();
    }
  });

  describe('inviting the customer', () => {
    it('invites a read-only member, mails the address given, and returns no token or address', async () => {
      const { services, sent } = buildServices();
      const app = await buildApp(services);
      try {
        const response = await app.inject({
          method: 'POST', url: '/v1/partner/accounts/op_account/invite', payload: { email: 'Customer@Example.com' },
        });
        expect(response.statusCode).toBe(201);
        expect(response.json()).toEqual({ status: 'invited', expires_at: '2026-11-01T00:00:00.000Z' });
        expect(services.member.invite).toHaveBeenCalledWith(
          'op_account', expect.objectContaining({ email: 'customer@example.com', role: 'readonly' }),
        );
        expect(sent).toHaveLength(1);
        expect(sent[0]!.to).toBe('customer@example.com');
        expect(sent[0]!.text).toContain('/team/invite#token=');
        expect(JSON.stringify(response.json())).not.toContain('inv_');
      } finally {
        await app.close();
      }
    });

    it('refuses the partner\'s own address and the reserved placeholder domain, and mails nothing', async () => {
      const { services, sent } = buildServices();
      const app = await buildApp(services);
      try {
        for (const email of ['ops@partner.example', 'tenant-x@partner.stack-tenant.local']) {
          const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/invite', payload: { email } });
          expect(response.statusCode).toBe(403);
        }
        expect(services.member.invite).not.toHaveBeenCalled();
        expect(sent).toHaveLength(0);
      } finally {
        await app.close();
      }
    });

    it('takes the invitation back when the mail cannot be sent, so no one is left invited unseen', async () => {
      const { services } = buildServices();
      (services.authEmail as { sendEmail: ReturnType<typeof vi.fn> }).sendEmail.mockRejectedValueOnce(new Error('down'));
      const app = await buildApp(services);
      try {
        const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/invite', payload: { email: 'c@example.com' } });
        expect(response.statusCode).toBe(502);
        expect(services.member.revoke).toHaveBeenCalledWith('mem_1', 'op_account');
      } finally {
        await app.close();
      }
    });

    it('answers 503 where no mail can be sent, before storing anything', async () => {
      const { services } = buildServices({ mail: false });
      const app = await buildApp(services);
      try {
        const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/invite', payload: { email: 'c@example.com' } });
        expect(response.statusCode).toBe(503);
        expect(services.member.invite).not.toHaveBeenCalled();
      } finally {
        await app.close();
      }
    });

    it('is limited per partner per hour', async () => {
      const { services } = buildServices();
      services.redis.incr.mockResolvedValue(61);
      const app = await buildApp(services);
      try {
        const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/invite', payload: { email: 'c@example.com' } });
        expect(response.statusCode).toBe(429);
        expect(response.json()).toMatchObject({ error: { code: 'RATE_LIMITED' } });
        expect(services.member.invite).not.toHaveBeenCalled();
      } finally {
        await app.close();
      }
    });

    it('needs a valid address and nothing else', async () => {
      const { services } = buildServices();
      const app = await buildApp(services);
      try {
        for (const payload of [{}, { email: 'not-an-address' }, { email: 'a@b.com', role: 'admin' }]) {
          const response = await app.inject({ method: 'POST', url: '/v1/partner/accounts/op_account/invite', payload });
          expect(response.statusCode).toBe(400);
        }
      } finally {
        await app.close();
      }
    });
  });
});
