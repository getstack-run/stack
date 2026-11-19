import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

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
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_brain_test', baseUrl: 'http://api.fixture' });
const FILE = 'drv_abcdefgh1234';
const TOKEN = 'jwt.passport.token';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('BrainService', () => {
  it('adds a file as given, with the Passport only on an agent call, and returns the estimate', async () => {
    const reply = { files: [{ file_id: FILE, name: 'invoice.pdf', status: 'reading', reason: null, estimated_pages: 3, estimated_free_pages: 3, estimated_cost_cents: 0 }], estimated_pages: 3, estimated_free_pages: 3, estimated_cost_cents: 0, free_pages_left: 197 };
    const calls = stubFetch({ status: 201, body: reply });
    const added = await stack().brain.add({ file_id: FILE });
    await stack().brain.add({ name_prefix: 'contracts/' }, { passportToken: TOKEN });
    expect(added).toEqual(reply);
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/brain/files', body: { file_id: FILE } });
    expect(calls[0]!.headers['X-Passport-Token']).toBeUndefined();
    expect(calls[1]).toMatchObject({ body: { name_prefix: 'contracts/' } });
    expect(calls[1]!.headers['X-Passport-Token']).toBe(TOKEN);
    expect(JSON.stringify(calls[1]!.body)).not.toContain(TOKEN);
  });

  it('removes files and returns what was in the brain', async () => {
    const calls = stubFetch({ status: 200, body: { removed: [FILE], not_in_brain: [] } });
    const removed = await stack().brain.remove({ file_ids: [FILE] });
    expect(removed).toEqual({ removed: [FILE], not_in_brain: [] });
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/brain/remove', body: { file_ids: [FILE] } });
  });

  it('searches and returns untrusted passages with the pending count', async () => {
    const reply = { results: [{ file_id: FILE, name: 'invoice.pdf', page: 2, passage: 'Total due: 1200', score: 0.9, flag: null, withheld: false, trust: 'untrusted' }], pending: 1, trust: 'untrusted' };
    const calls = stubFetch({ status: 200, body: reply });
    const found = await stack().brain.search({ query: 'what is the total?' }, { passportToken: TOKEN });
    expect(found).toEqual(reply);
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/brain/search', body: { query: 'what is the total?' } });
    expect(calls[0]!.headers['X-Passport-Token']).toBe(TOKEN);
  });

  it('lists with the query serialized and no body', async () => {
    const calls = stubFetch({ status: 200, body: { files: [], next_cursor: null, usage: { month: '2026-11', pages_read: 3, free_pages: 200, free_pages_left: 197, cost_cents: 0 } } });
    await stack().brain.list({ status: 'searchable', limit: 25 });
    expect(calls[0]!.method).toBe('GET');
    expect(calls[0]!.path).toBe('/v1/brain/files');
    expect(calls[0]!.search).toContain('status=searchable');
    expect(calls[0]!.search).toContain('limit=25');
    expect(calls[0]!.body).toBeUndefined();
  });
});
