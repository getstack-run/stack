import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

const SETTING = { agent_id: null, trust: 'trust_agents', effective: 'trust_agents', source: 'account' };

const approvals: Array<string | null> = [];

function stubFetch(): Array<{ method: string; path: string; body: unknown }> {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  approvals.length = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      calls.push({ method: init.method ?? 'GET', path: new URL(url).pathname, body: init.body ? JSON.parse(init.body) : undefined });
      approvals.push(new Headers(init.headers).get('x-governance-approval'));
      return new Response(JSON.stringify(SETTING), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const trust = () => new Stack({ apiKey: 'sk_live_trust_test', baseUrl: 'http://api.fixture' }).trust;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('TrustService', () => {
  it('reads and sets the account value and one agent value', async () => {
    const calls = stubFetch();
    await trust().get();
    await trust().set('ask_first');
    await trust().get('agt_one');
    await trust().set('trust_agents', 'agt_one');
    await trust().clear('agt_one');
    expect(calls).toEqual([
      { method: 'GET', path: '/v1/trust', body: undefined },
      { method: 'PUT', path: '/v1/trust', body: { trust: 'ask_first' } },
      { method: 'GET', path: '/v1/agents/agt_one/trust', body: undefined },
      { method: 'PUT', path: '/v1/agents/agt_one/trust', body: { trust: 'trust_agents' } },
      { method: 'PUT', path: '/v1/agents/agt_one/trust', body: { trust: null } },
    ]);
    expect(approvals.every((approval) => approval === null)).toBe(true);
  });

  it("sends a person's approval only as the governance header on the retry", async () => {
    stubFetch();
    await trust().set('trust_agents', undefined, { governanceApprovalId: 'gvr_one' });
    await trust().clear('agt_one', { governanceApprovalId: 'gvr_two' });
    expect(approvals).toEqual(['gvr_one', 'gvr_two']);
  });
});
