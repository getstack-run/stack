import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { GovernanceApprovalRequiredError, GovernanceApprovalStateError, PlatformSubscriptionRequiredError, StackError } from '../errors.js';

interface Sent {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      calls.push({
        method: init.method ?? 'GET',
        path: new URL(url).pathname,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const billing = () => new Stack({ apiKey: 'sk_live_billing_test', baseUrl: 'http://api.fixture' }).billing;

const CHECKOUT = { checkout_url: 'https://checkout.stripe.test/c/pay/cs_1', session_id: 'cs_1', trial: true };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('BillingService', () => {
  it('reads the subscription status', async () => {
    const status = {
      platform: { status: 'trialing', active: true, contract: false, trial_ends_at: '2026-11-24T10:00:00.000Z' },
      controls: { status: 'off', trial_ends_at: null },
      this_month: { account_actions: 12, control_checks: 0 },
    };
    const calls = stubFetch({ status: 200, body: status });
    await expect(billing().subscriptions()).resolves.toEqual(status);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/billing/subscriptions', body: undefined });
  });

  it('starts the platform and controls checkouts with no body and returns the Checkout URL', async () => {
    const calls = stubFetch({ status: 200, body: CHECKOUT });
    const service = billing();
    const platform = await service.subscribePlatform();
    const controls = await service.subscribeControls();
    expect(platform).toEqual(CHECKOUT);
    expect(controls.checkout_url).toBe(CHECKOUT.checkout_url);
    expect(calls.map((c) => [c.method, c.path, c.body, c.headers['X-Governance-Approval']])).toEqual([
      ['POST', '/v1/billing/platform/subscribe', undefined, undefined],
      ['POST', '/v1/billing/controls/subscribe', undefined, undefined],
    ]);
  });

  it('sends the governance approval on the retry, and nothing on the first try', async () => {
    const calls = stubFetch({ status: 200, body: CHECKOUT });
    const service = billing();
    await service.subscribePlatform();
    await service.subscribePlatform({ governanceApprovalId: 'gvr_1' });
    await service.subscribeControls({ governanceApprovalId: 'gvr_2' });
    expect(calls.map((c) => [c.path, c.headers['X-Governance-Approval']])).toEqual([
      ['/v1/billing/platform/subscribe', undefined],
      ['/v1/billing/platform/subscribe', 'gvr_1'],
      ['/v1/billing/controls/subscribe', 'gvr_2'],
    ]);
  });

  it('throws GovernanceApprovalRequiredError carrying the approval link', async () => {
    stubFetch({
      status: 403,
      body: {
        error: {
          code: 'GOVERNANCE_APPROVAL_REQUIRED',
          message: 'Approval required',
          details: { approval_id: 'gvr_9', approval_url: 'https://getstack.run/governance/approvals/gvr_9' },
        },
      },
    });
    const error = await billing().subscribePlatform().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GovernanceApprovalRequiredError);
    expect(error).toMatchObject({ approvalId: 'gvr_9', approvalUrl: 'https://getstack.run/governance/approvals/gvr_9' });
  });

  it.each(['pending', 'rejected', 'expired'] as const)('throws GovernanceApprovalStateError for a retry whose approval is %s', async (state) => {
    const code = `GOVERNANCE_APPROVAL_${state.toUpperCase()}`;
    stubFetch({ status: 403, body: { error: { code, message: 'refused', details: { approval_id: 'gvr_9', status: state } } } });
    const error = await billing().subscribePlatform({ governanceApprovalId: 'gvr_9' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GovernanceApprovalStateError);
    expect(error).toMatchObject({ code, status: 403, approvalId: 'gvr_9', approvalStatus: state });
  });

  it.each([
    ['SUBSCRIPTION_CONFLICT', 409],
    ['BILLING_NOT_CONFIGURED', 503],
    ['CONFLICT', 409],
  ] as const)('keeps %s as a plain StackError with its status', async (code, status) => {
    stubFetch({ status, body: { error: { code, message: 'refused' } } });
    const error = await billing().subscribeControls().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect(error).not.toBeInstanceOf(GovernanceApprovalRequiredError);
    expect(error).toMatchObject({ code, status });
  });

  it('maps PLATFORM_SUBSCRIPTION_REQUIRED on a controls checkout to its typed error', async () => {
    stubFetch({ status: 402, body: { error: { code: 'PLATFORM_SUBSCRIPTION_REQUIRED', message: 'refused', details: { status: 'none' } } } });
    const error = await billing().subscribeControls().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PlatformSubscriptionRequiredError);
    expect(error).toMatchObject({ subscriptionStatus: 'none' });
  });
});
