import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { GovernanceApprovalRequiredError, MakingUnavailableError } from '../errors.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }, headers: Record<string, string> = {}): Sent[] {
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
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status, headers: { 'content-type': 'application/json', ...headers } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_making_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const options = { passportToken: 'pas.jwt.token' };
const base = `/v1/accounts/${ACCOUNT}/making`;

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('MakingService', () => {
  it('uploads, quotes and orders under the Passport, with the bodies the API takes', async () => {
    const calls = stubFetch({ status: 201, body: {} });
    const { making } = stack().accounts;
    await making.uploadDesign(ACCOUNT, { file_name: 'bracket.stl', content_base64: 'c29saWQ=' }, options);
    await making.quote(ACCOUNT, {
      design_id: 'mkd_abcdefgh12345678',
      recipient: { name: 'Pat Doe', email: 'pat@example.test', phone: '+14155550123', address1: '1 Main St', city: 'Austin', state: 'TX', postal_code: '78701', country: 'US' },
    }, options);
    await making.order(ACCOUNT, 'mkq_abcdefgh12345678', options);
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['POST', `${base}/designs`],
      ['POST', `${base}/quotes`],
      ['POST', `${base}/orders`],
    ]);
    expect(calls[2]!.body).toEqual({ quote_id: 'mkq_abcdefgh12345678' });
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', 'pas.jwt.token', 'pas.jwt.token']);
  });

  it('reads designs, quotes and orders, with the Passport only when the agent asks', async () => {
    const calls = stubFetch({ status: 200, body: { designs: [], orders: [] } });
    const { making } = stack().accounts;
    await making.listDesigns(ACCOUNT, { limit: 5 }, options);
    await making.getDesign(ACCOUNT, 'mkd_1');
    await making.getQuote(ACCOUNT, 'mkq_1');
    await making.listOrders(ACCOUNT);
    await making.getOrder(ACCOUNT, 'mko_1', options);
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      `GET ${base}/designs?limit=5`,
      `GET ${base}/designs/mkd_1`,
      `GET ${base}/quotes/mkq_1`,
      `GET ${base}/orders`,
      `GET ${base}/orders/mko_1`,
    ]);
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', undefined, undefined, undefined, 'pas.jwt.token']);
  });

  it('cancels with no body and carries the approval on a retry of approve', async () => {
    const calls = stubFetch({ status: 200, body: {} });
    const { making } = stack().accounts;
    await making.cancelOrder(ACCOUNT, 'mko_1', options);
    await making.approveOrder(ACCOUNT, 'mko_1', { governanceApprovalId: 'gvr_1' });
    await making.rejectOrder(ACCOUNT, 'mko_2');
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `${base}/orders/mko_1/cancel`, undefined],
      ['POST', `${base}/orders/mko_1/approve`, undefined],
      ['POST', `${base}/orders/mko_2/reject`, undefined],
    ]);
    expect(calls[1]!.headers['X-Governance-Approval']).toBe('gvr_1');
    expect(calls[0]!.headers['X-Governance-Approval']).toBeUndefined();
  });

  it('throws the approval requirement when approve needs a person, and a plain error for a refusal', async () => {
    stubFetch({
      status: 403,
      body: { error: { code: 'GOVERNANCE_APPROVAL_REQUIRED', message: 'Approve it', details: { approval_id: 'gvr_9', approval_url: 'https://getstack.run/app/approve/gvr_9' } } },
    });
    await expect(stack().accounts.making.approveOrder(ACCOUNT, 'mko_1')).rejects.toBeInstanceOf(GovernanceApprovalRequiredError);

    stubFetch({ status: 503, body: { error: { code: 'MAKING_UNAVAILABLE', message: 'Later', details: { reason: 'no_supplier_available' } } } });
    const unavailable = await stack().accounts.making.quote(ACCOUNT, { design_id: 'mkd_abcdefgh12345678', recipient: { name: 'Pat Doe', email: 'pat@example.test', phone: '+14155550123', address1: '1 Main St', city: 'Austin', state: 'TX', postal_code: '78701', country: 'US' } }, options).catch((e: unknown) => e);
    expect(unavailable).toBeInstanceOf(MakingUnavailableError);
    expect(unavailable).toMatchObject({ code: 'MAKING_UNAVAILABLE', status: 503, reason: 'no_supplier_available' });
  });

  it('connects, lists and removes the customer\'s own supplier account without reading a key back', async () => {
    const calls = stubFetch({ status: 200, body: { supplier: 'gelato', payment: 'customer_account', available: true, connected: true } });
    const { making } = stack().accounts;
    const connected = await making.connectSupplier('gelato', { api_key: 'fixture-key-value' });
    await making.listSuppliers();
    expect(connected).not.toHaveProperty('api_key');
    expect(calls.map((c) => [c.method, c.path])).toEqual([
      ['PUT', '/v1/accounts/making/suppliers/gelato'],
      ['GET', '/v1/accounts/making/suppliers'],
    ]);
    const printful = stubFetch({ status: 201, body: { authorize_url: 'https://www.printful.com/oauth/authorize?client_id=c&state=s', expires_in_seconds: 900 } });
    await expect(making.connectPrintful()).resolves.toMatchObject({ authorize_url: expect.stringContaining('printful.com/oauth/authorize') });
    expect(printful.map((c) => [c.method, c.path])).toEqual([['POST', '/v1/accounts/making/suppliers/printful/connect']]);
    stubFetch({ status: 204 });
    await expect(making.disconnectSupplier('gelato')).resolves.toBeUndefined();
  });
});
