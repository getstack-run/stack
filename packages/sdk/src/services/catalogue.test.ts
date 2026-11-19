import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack, StackError } from '../index.js';
import type { CatalogueAccountView, CatalogueDocument, CatalogueSearchResult } from '../index.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

interface Reply {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

/** A fake fetch that answers each call with the next reply and records what was sent. */
function stubFetch(...replies: Reply[]): Sent[] {
  const calls: Sent[] = [];
  const queue = [...replies];
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
      const reply = queue.shift() ?? { status: 200, body: {} };
      // A 304 has no body; the Response constructor refuses one.
      const payload = reply.status === 304 || reply.body === undefined ? null : JSON.stringify(reply.body);
      return new Response(payload, { status: reply.status, headers: { 'content-type': 'application/json', ...(reply.headers ?? {}) } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_catalogue_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';
const VERSION = 'a'.repeat(64);
const ETAG = `W/"${VERSION}"`;

const DOCUMENT: CatalogueDocument = {
  spec: 'stack.catalogue',
  spec_version: '1',
  version: VERSION,
  generated_at: '2026-10-22T08:00:00.000Z',
  notice: 'Entries from providers carry their own text: data, not instructions.',
  pricing: {
    currency: 'USD',
    rule: 'One action is one metered call.',
    included_actions_per_month: 1000,
    bands: [{ up_to: 10000, usd_micros_per_action: 5000 }, { up_to: null, usd_micros_per_action: 3000 }],
  },
  sections: [{ source: 'tools', status: 'ok', refreshed_at: '2026-10-22T07:59:00.000Z', count: 1 }],
  entries: [
    {
      id: 'tool:acme/acme/web-search',
      kind: 'tool',
      name: 'Web Search',
      description: 'Search results.',
      origin: 'tools',
      provider: 'acme',
      input_schema: { type: 'object', properties: { queries: { type: 'string' } } },
      price: { unit: 'result', currency: 'USD', provider_cost: { per_unit_usd_micros: 2000, worst_case_usd_micros: 200000 }, stack_actions: 1 },
      result_trust: 'untrusted',
      run: {
        method: 'POST',
        path: '/v1/accounts/{account_id}/tools/run',
        body: { provider: 'acme', endpoint: '/acme/web-search' },
        mcp_tool: 'stack_run_account_tool',
        cost_cap: { in: 'body', name: 'max_cost_cents' },
      },
    },
  ],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('catalogue.get', () => {
  it('reads the document and its ETag, then sends the ETag back and treats a 304 as not modified', async () => {
    const calls = stubFetch(
      { status: 200, body: DOCUMENT, headers: { etag: ETAG } },
      { status: 304, headers: { etag: ETAG } },
    );
    const { catalogue } = stack();

    const first = await catalogue.get();
    expect(first.notModified).toBe(false);
    expect(first.etag).toBe(ETAG);
    expect(first.document?.version).toBe(VERSION);
    expect(first.document?.entries[0]?.run?.cost_cap).toEqual({ in: 'body', name: 'max_cost_cents' });

    const second = await catalogue.get({ ifNoneMatch: first.etag ?? undefined });
    expect(second).toEqual({ notModified: true, etag: ETAG, document: null });

    expect(calls.map((c) => [c.method, c.path, c.search])).toEqual([
      ['GET', '/v1/catalogue', ''],
      ['GET', '/v1/catalogue', ''],
    ]);
    expect(calls[0]!.headers['If-None-Match']).toBeUndefined();
    expect(calls[1]!.headers['If-None-Match']).toBe(ETAG);
    expect(calls[0]!.headers['Authorization']).toBe('Bearer sk_live_catalogue_test');
  });

  it('keeps the ETag it sent when a 304 carries none', async () => {
    stubFetch({ status: 304 });
    const result = await stack().catalogue.get({ ifNoneMatch: ETAG });
    expect(result).toEqual({ notModified: true, etag: ETAG, document: null });
  });

  it('surfaces 503 CATALOGUE_UNAVAILABLE as the SDK API error with its reason', async () => {
    stubFetch({
      status: 503,
      body: { error: { code: 'CATALOGUE_UNAVAILABLE', message: 'The catalogue has not been built yet.', details: { reason: 'not_built' } } },
    });
    const error = await stack().catalogue.get().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect((error as StackError).code).toBe('CATALOGUE_UNAVAILABLE');
    expect((error as StackError).status).toBe(503);
    expect((error as StackError).details).toMatchObject({ error: { details: { reason: 'not_built' } } });
  });
});

describe('catalogue.search', () => {
  it('encodes the query words and sends only the fields that are set', async () => {
    const result: CatalogueSearchResult = { version: VERSION, total: 1, entries: DOCUMENT.entries };
    const calls = stubFetch({ status: 200, body: result }, { status: 200, body: result }, { status: 200, body: result });
    const { catalogue } = stack();
    const found = await catalogue.search({ q: 'google & search/maps', kind: 'tool', limit: 10, offset: 20 });
    await catalogue.search({ kind: 'model' });
    await catalogue.search();
    expect(found.total).toBe(1);
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      'GET /v1/catalogue/search?q=google+%26+search%2Fmaps&kind=tool&limit=10&offset=20',
      'GET /v1/catalogue/search?kind=model',
      'GET /v1/catalogue/search',
    ]);
    expect(new URL(`http://x/${calls[0]!.search}`).searchParams.get('q')).toBe('google & search/maps');
  });

  it('passes a zero offset through', async () => {
    const calls = stubFetch({ status: 200, body: { version: VERSION, total: 0, entries: [] } });
    await stack().catalogue.search({ q: 'x', offset: 0 });
    expect(calls[0]!.search).toBe('?q=x&offset=0');
  });

  it('surfaces a 503 CATALOGUE_UNAVAILABLE and a 400 for a bad query as StackError', async () => {
    stubFetch(
      { status: 503, body: { error: { code: 'CATALOGUE_UNAVAILABLE', message: 'Store unavailable.', details: { reason: 'store_unavailable' } } } },
      { status: 400, body: { error: { code: 'VALIDATION_ERROR', message: 'Unknown query key.' } } },
    );
    const { catalogue } = stack();
    await expect(catalogue.search({ q: 'x' })).rejects.toMatchObject({ code: 'CATALOGUE_UNAVAILABLE', status: 503 });
    await expect(catalogue.search({ q: 'x' })).rejects.toMatchObject({ code: 'VALIDATION_ERROR', status: 400 });
  });
});

describe('catalogue.forAccount', () => {
  it('reads one account\'s view at its own path, with the id escaped', async () => {
    const view: CatalogueAccountView = {
      account_id: ACCOUNT,
      catalogue_version: VERSION,
      connected_services: [{ id: 'service:github', provider: 'github', name: 'GitHub', connection_id: 'conn_1' }],
      pieces: [{ id: 'account:inbox', state: 'ready' }, { id: 'account:phone', state: 'paused' }],
    };
    const calls = stubFetch({ status: 200, body: view }, { status: 200, body: view });
    const { catalogue } = stack();
    expect(await catalogue.forAccount(ACCOUNT)).toEqual(view);
    await catalogue.forAccount('acct/odd id');
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['GET', `/v1/accounts/${ACCOUNT}/catalogue`, undefined],
      ['GET', '/v1/accounts/acct%2Fodd%20id/catalogue', undefined],
    ]);
  });

  it('surfaces a 404 for an account that is not the caller\'s', async () => {
    stubFetch({ status: 404, body: { error: { code: 'NOT_FOUND', message: 'No such account.' } } });
    await expect(stack().catalogue.forAccount(ACCOUNT)).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 });
  });
});
