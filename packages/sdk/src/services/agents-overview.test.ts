import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

const PAGE = {
  agents: [
    {
      agent_id: 'agt_one',
      name: 'one',
      status: 'active',
      trust: { value: 'trust_agents', source: 'account' },
      account: null,
      pieces: [],
      held: 0,
      wakes: { queued: 0, running: 0 },
      last_passport_at: null,
      handoffs_this_month: { sent: [], received: [] },
      spend_this_month_cents: null,
    },
  ],
  next_cursor: 'abc',
};

function stubFetch(): Array<{ method: string; path: string; query: Record<string, string> }> {
  const calls: Array<{ method: string; path: string; query: Record<string, string> }> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string }) => {
      const parsed = new URL(url);
      calls.push({ method: init.method ?? 'GET', path: parsed.pathname, query: Object.fromEntries(parsed.searchParams) });
      return new Response(JSON.stringify(PAGE), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('AgentService.overview', () => {
  it('reads the overview page, with the limit and cursor only when given', async () => {
    const calls = stubFetch();
    const agents = new Stack({ apiKey: 'sk_live_overview_test', baseUrl: 'http://api.fixture' }).agents;
    const first = await agents.overview();
    const next = await agents.overview({ limit: 50, cursor: first.next_cursor ?? undefined });
    expect(first.agents[0]?.agent_id).toBe('agt_one');
    expect(next.next_cursor).toBe('abc');
    expect(calls).toEqual([
      { method: 'GET', path: '/v1/agents/overview', query: {} },
      { method: 'GET', path: '/v1/agents/overview', query: { limit: '50', cursor: 'abc' } },
    ]);
  });
});
