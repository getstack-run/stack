import { afterEach, describe, expect, it, vi } from 'vitest';
import { PaymentConnectionRequiredError, StackError, Stack, StripeRequestFailedError } from '../index.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET',
        path: parsed.pathname,
        search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      if (reply.status === 204) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_payments_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const AGENT = { passportToken: 'agent.passport.jwt' };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the Stripe connection', () => {
  it('starts it with an empty body and returns the connection with its connect address', async () => {
    const calls = stubFetch({ status: 201, body: { id: 'pcn_1', state: 'awaiting_key', connect_url: 'https://getstack.run/connect/x' } });
    const connection = await stack().payments.startStripe(ACCOUNT);
    expect(connection.connect_url).toBe('https://getstack.run/connect/x');
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/accounts/${ACCOUNT}/payments/stripe`, body: {} });
    expect(calls[0]!.headers['X-Passport-Token']).toBeUndefined();
  });

  it('sends the Passport only when the agent asks', async () => {
    const calls = stubFetch();
    await stack().payments.startStripe(ACCOUNT, AGENT);
    await stack().payments.getStripe(ACCOUNT, AGENT);
    expect(calls[0]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
    expect(calls[1]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });

  it('reads the connection, which may be none, and disconnects with no body', async () => {
    const calls = stubFetch({ status: 200, body: { connection: null } });
    expect(await stack().payments.getStripe(ACCOUNT)).toEqual({ connection: null });
    stubFetch({ status: 204 });
    const more = stubFetch({ status: 204 });
    await stack().payments.disconnectStripe(ACCOUNT);
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/accounts/${ACCOUNT}/payments/stripe` });
    expect(more[0]).toMatchObject({ method: 'DELETE', path: `/v1/accounts/${ACCOUNT}/payments/stripe` });
  });
});

describe('asking to be paid', () => {
  it('creates a link and a checkout session under the agent Passport', async () => {
    const calls = stubFetch({ status: 201, body: { id: 'pl_1', url: 'https://buy.stripe.com/x' } });
    const link = await stack().payments.createLink(ACCOUNT, { name: 'Report', amount_minor: 1200 }, AGENT);
    await stack().payments.createCheckoutSession(ACCOUNT, { name: 'Report', amount_minor: 1200, success_url: 'https://acme.sites.example/ok' }, AGENT);
    expect(link.url).toBe('https://buy.stripe.com/x');
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['POST', `/v1/accounts/${ACCOUNT}/payments/links`],
      ['POST', `/v1/accounts/${ACCOUNT}/payments/checkout-sessions`],
    ]);
    expect(calls[0]!.headers['X-Passport-Token']).toBe('agent.passport.jwt');
  });

  it('refuses without a Passport before sending anything', async () => {
    const calls = stubFetch();
    await expect(stack().payments.createLink(ACCOUNT, { name: 'R', amount_minor: 100 }, {})).rejects.toThrow(TypeError);
    await expect(stack().payments.deactivateLink(ACCOUNT, 'pl_1', {})).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });

  it('lists links with the limit and deactivates one', async () => {
    const calls = stubFetch({ status: 200, body: { links: [], id: 'pl_1', state: 'deactivated' } });
    await stack().payments.listLinks(ACCOUNT, { limit: 10 });
    await stack().payments.deactivateLink(ACCOUNT, 'pl 1', AGENT);
    expect(calls[0]).toMatchObject({ method: 'GET', path: `/v1/accounts/${ACCOUNT}/payments/links`, search: '?limit=10' });
    expect(calls[1]).toMatchObject({ method: 'POST', path: `/v1/accounts/${ACCOUNT}/payments/links/pl%201/deactivate` });
  });

  it('throws typed errors for a missing connection and a Stripe failure', async () => {
    stubFetch({ status: 409, body: { error: { code: 'PAYMENT_CONNECTION_REQUIRED', message: 'no connection', details: null } } });
    const missing = await stack().payments.createLink(ACCOUNT, { name: 'R', amount_minor: 100 }, AGENT).catch((e: unknown) => e);
    expect(missing).toBeInstanceOf(PaymentConnectionRequiredError);

    stubFetch({ status: 502, body: { error: { code: 'STRIPE_REQUEST_FAILED', message: 'unavailable', details: { provider_status: 503, kind: 'unavailable' } } } });
    const failed = await stack().payments.createLink(ACCOUNT, { name: 'R', amount_minor: 100 }, AGENT).catch((e: unknown) => e);
    expect(failed).toBeInstanceOf(StripeRequestFailedError);
    expect(failed).toMatchObject({ kind: 'unavailable', providerStatus: 503, status: 502 });

    stubFetch({ status: 500, body: { error: { code: 'SOMETHING_ELSE', message: 'x', details: null } } });
    const other = await stack().payments.createLink(ACCOUNT, { name: 'R', amount_minor: 100 }, AGENT).catch((e: unknown) => e);
    expect(other).toBeInstanceOf(StackError);
    expect(other).not.toBeInstanceOf(StripeRequestFailedError);
  });
});

describe('payments received', () => {
  it('lists both rails with the filter, the limit and the cursor, and reads one', async () => {
    const calls = stubFetch({ status: 200, body: { payments: [], next_cursor: null, id: 'pay_1' } });
    await stack().payments.listPayments(ACCOUNT, { rail: 'x402', limit: 5, cursor: 'c1' });
    await stack().payments.listPayments(ACCOUNT);
    await stack().payments.getPayment(ACCOUNT, 'pay_1');
    expect(calls[0]).toMatchObject({ path: `/v1/accounts/${ACCOUNT}/payments` });
    const search = new URLSearchParams(calls[0]!.search);
    expect(Object.fromEntries(search)).toEqual({ rail: 'x402', limit: '5', cursor: 'c1' });
    expect(calls[1]!.search).toBe('');
    expect(calls[2]).toMatchObject({ path: `/v1/accounts/${ACCOUNT}/payments/pay_1` });
  });
});
