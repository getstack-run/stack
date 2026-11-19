import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { GovernanceApprovalRequiredError } from '../errors.js';

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

const socket = () => new Stack({ apiKey: 'sk_live_control_socket_test', baseUrl: 'http://api.fixture' }).controlSocket;

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('controlSocket.get', () => {
  it('reads the socket', async () => {
    const calls = stubFetch({ status: 200, body: { socket_id: 'csk_1', effective_mode: 'none' } });
    const view = await socket().get();
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-socket' });
    expect(view).toMatchObject({ socket_id: 'csk_1', effective_mode: 'none' });
  });
});

describe('controlSocket addresses', () => {
  it('sets the decision address, sending the timeout only when given, and returns the secret once', async () => {
    const calls = stubFetch({ status: 201, body: { socket: { socket_id: 'csk_1' }, secret: 'whsec_AAAA' } });
    const change = await socket().setDecisionAddress({ url: 'https://control.example.com/decide' });
    await socket().setDecisionAddress({ url: 'https://control.example.com/decide', timeout_ms: 800 });
    expect(calls.map((call) => [call.method, call.path, call.body])).toEqual([
      ['PUT', '/v1/control-socket/decision', { url: 'https://control.example.com/decide' }],
      ['PUT', '/v1/control-socket/decision', { url: 'https://control.example.com/decide', timeout_ms: 800 }],
    ]);
    expect(change.secret).toBe('whsec_AAAA');
  });

  it('sets the events address', async () => {
    const calls = stubFetch({ status: 200, body: { socket: {}, secret: null } });
    const change = await socket().setEventsAddress({ url: 'https://events.example.com/in' });
    expect(calls[0]).toMatchObject({ method: 'PUT', path: '/v1/control-socket/events', body: { url: 'https://events.example.com/in' } });
    expect(change.secret).toBeNull();
  });

  it('clears an address with a DELETE and no body', async () => {
    const calls = stubFetch({ status: 200, body: {} });
    await socket().clear('events');
    expect(calls[0]).toMatchObject({ method: 'DELETE', path: '/v1/control-socket/events', body: undefined });
    expect(calls[0]!.headers['Content-Type']).toBeUndefined();
  });

  it('runs the setup check and the test exchange on the named address', async () => {
    const calls = stubFetch({ status: 200, body: { target: 'decision', ok: true, activated: true } });
    await socket().verify('decision');
    await socket().test('events');
    expect(calls.map((call) => [call.method, call.path, call.body])).toEqual([
      ['POST', '/v1/control-socket/decision/verify', undefined],
      ['POST', '/v1/control-socket/events/test', undefined],
    ]);
  });

  it('rotates a signing secret and returns the new one', async () => {
    const calls = stubFetch({ status: 201, body: { target: 'decision', secret: 'whsec_BBBB', previous_valid_until: '2026-10-22T00:00:00.000Z' } });
    const rotated = await socket().rotateSecret('decision');
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/control-socket/decision/secret/rotate' });
    expect(rotated).toMatchObject({ secret: 'whsec_BBBB', previous_valid_until: '2026-10-22T00:00:00.000Z' });
  });
});

describe('controlSocket mode and checked types', () => {
  it('sets the mode', async () => {
    const calls = stubFetch();
    await socket().setMode('hosted');
    expect(calls[0]).toMatchObject({ method: 'PUT', path: '/v1/control-socket/mode', body: { mode: 'hosted' } });
  });

  it('sets what happens when the decision server does not answer', async () => {
    const calls = stubFetch();
    await socket().setOnUnavailable('refuse');
    await socket().setOnUnavailable('allow');
    expect(calls.map((call) => call.body)).toEqual([{ on_unavailable: 'refuse' }, { on_unavailable: 'allow' }]);
    expect(calls.every((call) => call.method === 'PUT' && call.path === '/v1/control-socket/on-unavailable')).toBe(true);
  });

  it('sets a list of checked types, and null for every kind', async () => {
    const calls = stubFetch();
    await socket().setCheckedTypes(['email.send', 'card.checkout']);
    await socket().setCheckedTypes(null);
    expect(calls.map((call) => call.body)).toEqual([{ types: ['email.send', 'card.checkout'] }, { types: null }]);
    expect(calls.every((call) => call.method === 'PUT' && call.path === '/v1/control-socket/checked-types')).toBe(true);
  });
});

describe('controlSocket approvals', () => {
  type Approval = { governanceApprovalId: string } | undefined;
  const cases: Array<[string, (approval: Approval) => Promise<unknown>, string, string]> = [
    ['setDecisionAddress', (a) => socket().setDecisionAddress({ url: 'https://control.example.com/decide' }, a), 'PUT', '/v1/control-socket/decision'],
    ['setEventsAddress', (a) => socket().setEventsAddress({ url: 'https://events.example.com/in' }, a), 'PUT', '/v1/control-socket/events'],
    ['clear', (a) => socket().clear('decision', a), 'DELETE', '/v1/control-socket/decision'],
    ['verify', (a) => socket().verify('decision', a), 'POST', '/v1/control-socket/decision/verify'],
    ['rotateSecret', (a) => socket().rotateSecret('events', a), 'POST', '/v1/control-socket/events/secret/rotate'],
    ['setMode', (a) => socket().setMode('none', a), 'PUT', '/v1/control-socket/mode'],
    ['setCheckedTypes', (a) => socket().setCheckedTypes(['email.send'], a), 'PUT', '/v1/control-socket/checked-types'],
    ['setOnUnavailable', (a) => socket().setOnUnavailable('allow', a), 'PUT', '/v1/control-socket/on-unavailable'],
  ];

  it.each(cases)('%s sends X-Governance-Approval only when given', async (_name, call, method, path) => {
    const calls = stubFetch();
    await call(undefined);
    await call({ governanceApprovalId: 'gvr_approved' });
    expect(calls.map((sent) => [sent.method, sent.path])).toEqual([[method, path], [method, path]]);
    expect(calls[0]!.headers['X-Governance-Approval']).toBeUndefined();
    expect(calls[1]!.headers['X-Governance-Approval']).toBe('gvr_approved');
  });

  it('throws GovernanceApprovalRequiredError with the approval link on the first call', async () => {
    stubFetch({
      status: 403,
      body: {
        error: {
          code: 'GOVERNANCE_APPROVAL_REQUIRED',
          message: 'A person must approve this',
          details: { approval_id: 'gvr_1', approval_url: 'https://getstack.run/app/approvals/gvr_1' },
        },
      },
    });
    const error = await socket().setDecisionAddress({ url: 'https://control.example.com/decide' }).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(GovernanceApprovalRequiredError);
    expect(error).toMatchObject({ approvalId: 'gvr_1', approvalUrl: 'https://getstack.run/app/approvals/gvr_1' });
  });
});

describe('controlSocket.decisions', () => {
  it('lists with only the filters given', async () => {
    const calls = stubFetch({ status: 200, body: { decisions: [] } });
    await socket().decisions.list();
    await socket().decisions.list({ limit: 10, account_id: 'acct_1', verdict: 'deny', before: '2026-10-21T00:00:00.000Z' });
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-decisions', search: '' });
    const query = new URLSearchParams(calls[1]!.search);
    expect(Object.fromEntries(query)).toEqual({ limit: '10', account_id: 'acct_1', verdict: 'deny', before: '2026-10-21T00:00:00.000Z' });
  });

  it('reads one decision by id', async () => {
    const calls = stubFetch({ status: 200, body: { id: 'dec_abcdefghijklmnop' } });
    const decision = await socket().decisions.get('dec_abcdefghijklmnop');
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/control-decisions/dec_abcdefghijklmnop' });
    expect(decision.id).toBe('dec_abcdefghijklmnop');
  });
});
