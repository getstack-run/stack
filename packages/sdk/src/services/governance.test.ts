import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';

interface Sent {
  method: string;
  path: string;
  body: unknown;
}

function stubFetch(reply: { status: number; body?: unknown }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string }) => {
      calls.push({
        method: init.method ?? 'GET',
        path: new URL(url).pathname,
        body: init.body ? JSON.parse(init.body) : undefined,
      });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const governance = () => new Stack({ apiKey: ['sk', 'live', 'governance', 'test'].join('_'), baseUrl: 'http://api.fixture' }).governance;

const DETAIL = {
  approval: {
    id: 'gvr_abc',
    action: 'billing_mutate',
    resource_id: 'platform',
    summary: 'Start the platform subscription',
    requested_via: 'operator_key',
    status: 'pending',
    expires_at: '2026-10-21T12:00:00.000Z',
    created_at: '2026-10-20T12:00:00.000Z',
    decided_at: null,
  },
  payload_hash: 'a'.repeat(64),
  approval_url: 'https://getstack.run/app/approve/gvr_abc',
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('governance.listApprovals', () => {
  it('reads the account\'s approvals with one GET and no body', async () => {
    const calls = stubFetch({ status: 200, body: { approvals: [DETAIL.approval] } });
    const { approvals } = await governance().listApprovals();
    expect(calls).toEqual([{ method: 'GET', path: '/v1/governance/approvals', body: undefined }]);
    expect(approvals.map((approval) => approval.id)).toEqual(['gvr_abc']);
  });

  it('answers an agent as forbidden', async () => {
    stubFetch({ status: 403, body: { error: { code: 'FORBIDDEN', message: 'agents cannot list approvals' } } });
    await expect(governance().listApprovals()).rejects.toMatchObject({ code: 'FORBIDDEN', status: 403 });
  });
});

describe('governance.getApproval', () => {
  it('reads one approval with its payload hash and its own link, and sends no body', async () => {
    const calls = stubFetch({ status: 200, body: DETAIL });
    const detail = await governance().getApproval('gvr_abc');
    expect(calls).toEqual([{ method: 'GET', path: '/v1/governance/approvals/gvr_abc', body: undefined }]);
    expect(detail.approval.status).toBe('pending');
    expect(detail.payload_hash).toBe('a'.repeat(64));
    expect(detail.approval_url).toBe('https://getstack.run/app/approve/gvr_abc');
  });

  it('escapes the id', async () => {
    const calls = stubFetch({ status: 200, body: DETAIL });
    await governance().getApproval('gvr_a/b?c');
    expect(calls[0]!.path).toBe('/v1/governance/approvals/gvr_a%2Fb%3Fc');
  });

  it('answers an approval of another account as not found and an agent as forbidden', async () => {
    stubFetch({ status: 404, body: { error: { code: 'NOT_FOUND', message: 'governance approval not found: gvr_x' } } });
    await expect(governance().getApproval('gvr_x')).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 });
    stubFetch({ status: 403, body: { error: { code: 'FORBIDDEN', message: 'An agent cannot read approvals.' } } });
    await expect(governance().getApproval('gvr_x')).rejects.toMatchObject({ status: 403 });
  });
});
