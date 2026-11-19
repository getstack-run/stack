import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(body: unknown = {}): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET', path: parsed.pathname, search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined, headers: init.headers ?? {},
      });
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_accounts_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('signing keys', () => {
  it('lists and rotates', async () => {
    const calls = stubFetch({ keys: [] });
    const { signingKeys } = stack().accounts;
    await signingKeys.list(ACCOUNT);
    await signingKeys.rotate(ACCOUNT);
    const base = `/v1/accounts/${ACCOUNT}/signing-keys`;
    expect(calls.map((c) => [c.method, c.path, c.search])).toEqual([
      ['GET', base, ''],
      ['POST', `${base}/rotate`, ''],
    ]);
  });
});

describe('what the public answer shows', () => {
  it('reads the two switches and changes them, and nothing else', async () => {
    const calls = stubFetch({ account_id: ACCOUNT, agent_id: 'agt_x', enabled: true, show_name: false, urls: { lookup: 'l', agent_card: 'a', mcp_server_card: 'm', key_directory: 'k' } });
    const { identity } = stack().accounts;
    await identity.get(ACCOUNT);
    await identity.update(ACCOUNT, { show_name: true });
    await identity.update(ACCOUNT, { enabled: false });
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['GET', `/v1/accounts/${ACCOUNT}/identity`, undefined],
      ['PUT', `/v1/accounts/${ACCOUNT}/identity`, { show_name: true }],
      ['PUT', `/v1/accounts/${ACCOUNT}/identity`, { enabled: false }],
    ]);
  });
});

describe('no AI disclosure setting', () => {
  it('has no disclosure service: STACK adds no line to what an agent sends', () => {
    expect(Object.keys(stack().accounts)).not.toContain('disclosure');
  });
});
