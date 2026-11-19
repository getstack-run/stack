import { describe, expect, it, vi } from 'vitest';
import type { FastifyRequest } from 'fastify';
import type { Services } from '../../config/services.js';

// The approval methods an install offers are the ones it has registered. These tests run the two handlers that
// choose a method, with the services they read replaced, for a deployment with a verification provider and one
// without.

// A request that is already completed is only read; a pending one is the one a method is started for.
const record = vi.hoisted(() => ({ status: 'completed' as 'completed' | 'pending', terms: {} as Record<string, unknown> }));

vi.mock('./dashboard-author.js', () => ({
  resolveDashboardAuthorityAuthor: async () => ({
    operatorId: 'op_1',
    author: { kind: 'operator_owner', operator_id: 'op_1' },
    browserSession: {},
  }),
  requireAuthorityAdmin: () => undefined,
}));

vi.mock('./setup-requests.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./setup-requests.js')>();
  return {
    ...actual,
    loadAuthorityRequest: async () => ({
      request_id: 'aor_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      operator_id: 'op_1',
      request_hash: 'h',
      request: record.terms,
      display: { agent_name: 'agent', mission_summary: null, system_name: 'system' },
      status: record.status,
      created_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2026-01-02T00:00:00.000Z',
    }),
    assertAuthorityRequestPending: () => undefined,
  };
});

vi.mock('@stack/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@stack/shared')>();
  return { ...actual, CreateEnterpriseOidcAuthoritySetupInput: { parse: (value: unknown) => value } };
});

const { reviewEnterpriseOidcRequest, startEnterpriseOidcApproval } = await import('./enterprise-oidc-approval.js');

const VERIFICATION = {
  provider_key: 'stripe_identity',
  name: 'Document check',
  supported_layers: ['identity'],
  price_cents: 150,
};

function services(providers: Array<Record<string, unknown>>, connectionName?: string) {
  const initiate = vi.fn(async () => ({ expires_at: new Date() }));
  const bundle = {
    // The name is given only while the account holds several connections of the service; with one the call answers null.
    serviceConnection: { connectionNameWhenSeveral: vi.fn(async () => connectionName ?? null) },
    oidcIdpConfigRepo: { findActiveByOperator: vi.fn(async () => null) },
    operator: { getById: vi.fn(async () => ({ id: 'op_1', tier: 'enterprise' })) },
    identity: { listProviders: vi.fn(async () => providers), initiate },
  };
  return { services: bundle as unknown as Services, initiate };
}

function request(body: unknown) {
  return { params: { requestId: 'aor_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }, body, headers: {} } as unknown as FastifyRequest<{ Params: { requestId: string } }>;
}

const BROWSER_BINDING = 'a'.repeat(43);

describe('the approval methods of an Authority request', () => {
  it('offers the verification method only when its provider is registered', async () => {
    record.status = 'completed';
    const without = services([]);
    expect((await reviewEnterpriseOidcRequest(without.services, request({}))).approval_methods).toEqual([]);

    const withProvider = services([VERIFICATION]);
    const review = await reviewEnterpriseOidcRequest(withProvider.services, request({}));
    expect(review.approval_methods).toEqual([
      { method: 'stripe_identity', name: 'Document check', price_cents: 150, role_source: 'customer_assertion' },
    ]);
  });

  it('names the connection the request is about as its owner names it now, read live, when the account has several of the service; the stored request is untouched', async () => {
    record.status = 'completed';
    record.terms = { service_connection_id: 'scon_a', provider: 'custom_grocer' };
    try {
      const named = services([], 'Work');
      const review = await reviewEnterpriseOidcRequest(named.services, request({}));
      expect(review.display).toEqual({ agent_name: 'agent', mission_summary: null, system_name: 'system', connection_name: 'Work' });
      expect(review.request).toEqual({ service_connection_id: 'scon_a', provider: 'custom_grocer' });
      expect(named.services.serviceConnection.connectionNameWhenSeveral).toHaveBeenCalledWith('scon_a', 'op_1');

      // One connection of the service, or one that cannot be read, adds no name: the page shows the id as it always did.
      const unnamed = services([]);
      expect((await reviewEnterpriseOidcRequest(unnamed.services, request({}))).display).toEqual({ agent_name: 'agent', mission_summary: null, system_name: 'system' });
    } finally {
      record.terms = {};
    }
  });

  it('refuses to start verification on an install with no provider, in words that name no vendor', async () => {
    record.status = 'pending';
    const { services: bundle, initiate } = services([]);
    const error = await startEnterpriseOidcApproval(bundle, request({ browser_binding: BROWSER_BINDING, method: 'stripe_identity' })).catch((e: unknown) => e as Error);
    expect(error).toMatchObject({ code: 'CONFLICT', statusCode: 409 });
    expect((error as Error).message).toBe('No identity verification provider is registered on this installation; approve this request with company sign-in');
    expect((error as Error).message).not.toMatch(/stripe/i);
    expect(initiate).not.toHaveBeenCalled();
  });

  it('starts verification with the registered provider', async () => {
    record.status = 'pending';
    const { services: bundle, initiate } = services([VERIFICATION]);
    // The fake provider starts no session, so the handler stops right after the call it is shown to make.
    await expect(startEnterpriseOidcApproval(bundle, request({ browser_binding: BROWSER_BINDING, method: 'stripe_identity' }))).rejects.toMatchObject({ statusCode: 503 });
    expect(initiate).toHaveBeenCalledWith('op_1', 'stripe_identity', ['verified_identity'], expect.stringContaining('stripe_return=1'), { kind: 'authority', request_id: 'aor_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' });
  });
});
