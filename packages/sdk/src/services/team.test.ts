import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

interface Sent {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(body: unknown): Sent[] {
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
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_team_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('TeamService.clearSsoBindings', () => {
  it('clears one member, or every member of one issuer, and sends the approval on the retry', async () => {
    const calls = stubFetch({ cleared: [] });
    await stack().team.clearSsoBindings({ member_id: 'mem_1' });
    await stack().team.clearSsoBindings({ issuer: 'https://old-idp.example' }, { governanceApprovalId: 'gvr_1' });
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', '/v1/team/sso-bindings/clear', { member_id: 'mem_1' }],
      ['POST', '/v1/team/sso-bindings/clear', { issuer: 'https://old-idp.example' }],
    ]);
    expect(calls[0]!.headers['X-Governance-Approval']).toBeUndefined();
    expect(calls[1]!.headers['X-Governance-Approval']).toBe('gvr_1');
  });
});
