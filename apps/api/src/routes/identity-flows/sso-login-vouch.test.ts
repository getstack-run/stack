import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { hostedFeatureGate } from '../../config/licence-service.js';
import type { Services } from '../../config/services.js';
import { createErrorHandler } from '../../middleware/error-handler.js';
import { handleOidcCallback } from './sso-login.js';

/**
 * What the sign-in asks of the account when the provider did not verify the address (spec/sso-login/SPEC.md 9.5): the
 * issuer's own claim, or a domain the account verified, and only for a token with no email_verified claim at all. The
 * member lookup is faked so the test sees exactly what the route hands it.
 */

const STATE = 'oidc_state_value';
const BINDING = 'b'.repeat(64);
const OPERATOR = 'op_acme';

type Identity = {
  email: string;
  email_verified: boolean;
  email_verified_absent: boolean;
  issuer_vouches_email_domain: boolean;
};

function build(identity: Identity, options: { domainVerified?: boolean; linked?: boolean; vouchedBy?: string } = {}) {
  const isVerifiedFor = vi.fn(async () => options.domainVerified ?? false);
  let vouched: unknown = 'not asked';
  const findOrProvisionForSso = vi.fn(async (input: { vouchForEmail?: () => Promise<unknown> }) => {
    vouched = input.vouchForEmail ? await input.vouchForEmail() : 'no hook';
    return { member: { id: 'mem_1', email: identity.email, role: 'standard' }, provisioned: false, linked: options.linked ?? false, ...(options.vouchedBy ? { vouchedBy: options.vouchedBy } : {}) };
  });
  const audit = vi.fn(async () => undefined);
  const tx = {
    execute: vi.fn(async () => []),
    select: () => ({ from: () => ({ where: () => ({ for: async () => [{ status: 'active' }] }) }) }),
  };
  const provider = {
    acceptCallback: vi.fn(async () => ({})),
    completeForLogin: vi.fn(async () => ({
      operator_id: OPERATOR, config_id: 'cfg_1', default_member_role: 'standard', name: null, sub: 'sub-1', iss: 'https://idp.example', ...identity,
    })),
  };
  const services = {
    identity: { getProvider: () => provider },
    redis: { get: vi.fn(async () => JSON.stringify({ config_id: 'cfg_1', browser_binding_hash: BINDING })), del: vi.fn(async () => 1), set: vi.fn(async () => 'OK') },
    features: { ...hostedFeatureGate, has: () => true },
    member: { findOrProvisionForSso },
    ssoDomains: { isVerifiedFor },
    audit: { write: audit },
    db: { transaction: async (fn: (t: unknown) => unknown) => fn(tx) },
  } as unknown as Services;
  const app = Fastify();
  app.setErrorHandler(createErrorHandler());
  app.get('/callback', (request, reply) => handleOidcCallback(request, reply, services));
  const call = () => app.inject({ method: 'GET', url: `/callback?code=abc&state=${STATE}`, headers: { cookie: `stack_sso_state=${STATE}` } });
  return { app, call, isVerifiedFor, findOrProvisionForSso, audit, vouched: () => vouched };
}

const apps: Array<ReturnType<typeof Fastify>> = [];
afterEach(async () => {
  while (apps.length) await apps.pop()!.close();
});

const base = { email: 'jane@corp.example.com', email_verified: false, email_verified_absent: true, issuer_vouches_email_domain: false };

describe('SSO sign-in: vouching for an address the provider did not verify', () => {
  it('takes the issuer\'s own claim that the domain is verified, without looking anything up', async () => {
    const t = build({ ...base, issuer_vouches_email_domain: true });
    apps.push(t.app);
    expect((await t.call()).statusCode).toBe(302);
    expect(t.vouched()).toBe('issuer_domain_claim');
    expect(t.isVerifiedFor).not.toHaveBeenCalled();
  });

  it('takes a domain the account verified, asking for the address\'s own domain, in canonical form', async () => {
    const t = build({ ...base, email: 'jane@corp.example.com' }, { domainVerified: true });
    apps.push(t.app);
    await t.call();
    expect(t.vouched()).toBe('verified_domain');
    expect(t.isVerifiedFor).toHaveBeenCalledWith(OPERATOR, 'corp.example.com');
  });

  it('vouches for nothing when the domain is not verified for the account', async () => {
    const t = build(base, { domainVerified: false });
    apps.push(t.app);
    await t.call();
    expect(t.vouched()).toBeUndefined();
  });

  it('does not ask, whatever the domain, when the provider said something about the address: false, or anything but true', async () => {
    const t = build({ ...base, email_verified_absent: false, issuer_vouches_email_domain: true }, { domainVerified: true });
    apps.push(t.app);
    await t.call();
    expect(t.vouched()).toBeUndefined();
    expect(t.isVerifiedFor).not.toHaveBeenCalled();
  });

  it('does not ask when the provider verified the address', async () => {
    const t = build({ ...base, email_verified: true, email_verified_absent: false }, { domainVerified: true });
    apps.push(t.app);
    await t.call();
    expect(t.vouched()).toBeUndefined();
    expect(t.isVerifiedFor).not.toHaveBeenCalled();
  });

  it('finds no domain in an address that has none', async () => {
    const t = build({ ...base, email: 'jane' }, { domainVerified: true });
    apps.push(t.app);
    await t.call();
    expect(t.vouched()).toBeUndefined();
    expect(t.isVerifiedFor).not.toHaveBeenCalled();
  });

  it('writes down on what a first sign-in was linked, beside the sign-in itself, and only then', async () => {
    const linkedByDomain = build(base, { domainVerified: true, linked: true, vouchedBy: 'verified_domain' });
    apps.push(linkedByDomain.app);
    await linkedByDomain.call();
    const actions = linkedByDomain.audit.mock.calls.map((call) => (call as unknown as [{ action: string }])[0].action);
    expect(actions).toEqual(['sso.login', 'sso.login.link.verified_domain']);

    const byIssuer = build({ ...base, issuer_vouches_email_domain: true }, { linked: true, vouchedBy: 'issuer_domain_claim' });
    apps.push(byIssuer.app);
    await byIssuer.call();
    expect(byIssuer.audit.mock.calls.map((call) => (call as unknown as [{ action: string }])[0].action)).toEqual(['sso.login', 'sso.login.link.issuer_domain_claim']);

    const byProvider = build({ ...base, email_verified: true, email_verified_absent: false }, { linked: true });
    apps.push(byProvider.app);
    await byProvider.call();
    expect(byProvider.audit.mock.calls.map((call) => (call as unknown as [{ action: string }])[0].action)).toEqual(['sso.login']);
  });
});
