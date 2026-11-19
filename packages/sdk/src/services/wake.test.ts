import { createHmac } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { verifyWakeWebhook } from '../wake-webhook.js';

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
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_wake_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('wakes: the agent\'s queue', () => {
  it('lists the open wakes with the query, under the agent\'s Passport', async () => {
    const calls = stubFetch({ status: 200, body: { wakes: [], next_cursor: null, rate: {} } });
    await stack().wakes.list('agt_1', { status: 'open', limit: 5, cursor: 'abc' }, { passportToken: 'ppt_token' });
    expect(calls[0]).toMatchObject({ method: 'GET', path: '/v1/agents/agt_1/wakes', search: '?status=open&limit=5&cursor=abc' });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('ppt_token');
  });

  it('reads one and acknowledges it', async () => {
    const calls = stubFetch();
    await stack().wakes.get('agt_1', 'wke_1');
    await stack().wakes.acknowledge('agt_1', 'wke_1', { passportToken: 'ppt_token' });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /v1/agents/agt_1/wakes/wke_1', 'POST /v1/agents/agt_1/wakes/wke_1/acknowledge']);
    expect(calls[1]!.headers['X-Passport-Token']).toBe('ppt_token');
  });

  it('writes an id into a path safely', async () => {
    const calls = stubFetch();
    await stack().wakes.get('agt_1/../x', 'wke 1');
    expect(calls[0]!.path).toBe('/v1/agents/agt_1%2F..%2Fx/wakes/wke%201');
  });
});

describe('wakes: configuration', () => {
  it('addresses the customer\'s default without an agent, and one agent with its id', async () => {
    const calls = stubFetch();
    const wakes = stack().wakes;
    await wakes.getSettings();
    await wakes.getSettings('agt_1');
    await wakes.setSettings({ enabled: false });
    await wakes.setSettings({ time_zone: null }, 'agt_1');
    await wakes.listRules();
    await wakes.listRules('agt_1');
    await wakes.createRule({ name: 'a', source: 'email' });
    await wakes.createRule({ name: 'a', source: 'email' }, 'agt_1');
    await wakes.updateRule('wkr_1', { name: 'a', source: 'sms' });
    await wakes.rotateWebhookSecret('agt_1');
    await wakes.testWebhook('agt_1');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /v1/wake/settings', 'GET /v1/agents/agt_1/wake/settings', 'PUT /v1/wake/settings', 'PUT /v1/agents/agt_1/wake/settings',
      'GET /v1/wake/rules', 'GET /v1/agents/agt_1/wake/rules', 'POST /v1/wake/rules', 'POST /v1/agents/agt_1/wake/rules',
      'PUT /v1/wake/rules/wkr_1', 'POST /v1/agents/agt_1/wake/webhook/rotate-secret', 'POST /v1/agents/agt_1/wake/webhook/test',
    ]);
    expect(calls[3]!.body).toEqual({ time_zone: null });
  });

  it('manages schedules and deletes without a body', async () => {
    const calls = stubFetch({ status: 204 });
    const wakes = stack().wakes;
    await wakes.deleteRule('wkr_1');
    await wakes.deleteSchedule('agt_1', 'wsc_1');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['DELETE /v1/wake/rules/wkr_1', 'DELETE /v1/agents/agt_1/wake/schedules/wsc_1']);
  });

  it('turns a refusal into a StackError with the API\'s code', async () => {
    stubFetch({ status: 409, body: { error: { code: 'WAKE_RULE_NOT_FOUND', message: 'gone', details: {} } } });
    await expect(stack().wakes.createRule({ name: 'a', source: 'email' })).rejects.toMatchObject({ code: 'WAKE_RULE_NOT_FOUND', status: 409 });
  });
});

describe('verifyWakeWebhook', () => {
  const secret = `whsec_${Buffer.from('0123456789abcdef0123456789abcdef').toString('base64')}`;
  const wake = { type: 'stack.wake', version: '2', wake_id: 'wke_abc', account_id: 'acct_1', agent_id: 'agt_1', mission_id: 'ms_1', source: 'email', task: 'Read it.', occurred_at: '2026-10-21T10:00:00Z', event: {} };
  const sign = (body: string, id = 'wke_abc', timestamp = 1_790_000_000, key = secret) => ({
    'webhook-id': id,
    'webhook-timestamp': String(timestamp),
    'webhook-signature': `v1,${createHmac('sha256', Buffer.from(key.slice(6), 'base64')).update(`${id}.${timestamp}.${body}`).digest('base64')}`,
  });

  it('accepts what STACK signs, and returns the wake', () => {
    const body = JSON.stringify(wake);
    const result = verifyWakeWebhook({ headers: sign(body), body, secret, now: 1_790_000_010 });
    expect(result).toEqual({ ok: true, wake });
  });

  it('returns the wake of a ringing call: its call id, when the ring runs out and its checks, never the number calling', () => {
    const ringing = {
      ...wake,
      source: 'incoming_call',
      task: 'Incoming call.',
      event: { call_id: 'acall_1', answer_by: '2026-10-21T10:00:30Z' },
      sender_tags: ['new_sender'],
    };
    const body = JSON.stringify(ringing);
    const result = verifyWakeWebhook({ headers: sign(body), body, secret, now: 1_790_000_010 });
    expect(result).toEqual({ ok: true, wake: ringing });
    if (result.ok) {
      expect(result.wake.source).toBe('incoming_call');
      expect(result.wake.event.call_id).toBe('acall_1');
      expect(result.wake.sender_tags).toEqual(['new_sender']);
    }
  });

  it('returns a decision wake of an agent with no account: the item, which one and how it ended', () => {
    const decided = {
      ...wake,
      account_id: null,
      mission_id: null,
      source: 'decision',
      task: 'Intent approval: approved.',
      event: { item_kind: 'intent_approval', item_id: 'iap_1', result: 'approved' },
    };
    const body = JSON.stringify(decided);
    const result = verifyWakeWebhook({ headers: sign(body), body, secret, now: 1_790_000_010 });
    expect(result).toEqual({ ok: true, wake: decided });
    if (result.ok) {
      expect(result.wake.account_id).toBeNull();
      expect(result.wake.event.item_kind).toBe('intent_approval');
      expect(result.wake.event.result).toBe('approved');
    }
  });

  it('accepts either secret during a rotation, from node headers or Headers', () => {
    const body = JSON.stringify(wake);
    const older = `whsec_${Buffer.from('fedcba9876543210fedcba9876543210').toString('base64')}`;
    expect(verifyWakeWebhook({ headers: new Headers(sign(body, 'wke_abc', 1_790_000_000, older)), body: Buffer.from(body), secret: [secret, older], now: 1_790_000_000 }).ok).toBe(true);
  });

  it('refuses a tampered body, a stale message, another wake\'s id, missing headers, and a wrong secret', () => {
    const body = JSON.stringify(wake);
    const headers = sign(body);
    expect(verifyWakeWebhook({ headers, body: body.replace('Read it.', 'Wire it.'), secret, now: 1_790_000_000 })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(verifyWakeWebhook({ headers, body, secret, now: 1_790_000_000 + 600 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyWakeWebhook({ headers: sign(body, 'wke_other'), body, secret, now: 1_790_000_000 })).toEqual({ ok: false, reason: 'id_mismatch' });
    expect(verifyWakeWebhook({ headers: {}, body, secret })).toEqual({ ok: false, reason: 'missing_headers' });
    expect(verifyWakeWebhook({ headers: { ...headers, 'webhook-timestamp': 'soon' }, body, secret })).toEqual({ ok: false, reason: 'bad_timestamp' });
    const other = `whsec_${Buffer.from('ffffffffffffffffffffffffffffffff').toString('base64')}`;
    expect(verifyWakeWebhook({ headers, body, secret: other, now: 1_790_000_000 })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('refuses a signed body that is not a wake, and a malformed signature without throwing', () => {
    const body = '{"hello":"world"}';
    expect(verifyWakeWebhook({ headers: sign(body, 'x'), body, secret, now: 1_790_000_000 })).toEqual({ ok: false, reason: 'bad_body' });
    // A body of the version before the untrusted object was removed is not this version's wake.
    const older = JSON.stringify({ ...wake, version: '1' });
    expect(verifyWakeWebhook({ headers: sign(older), body: older, secret, now: 1_790_000_000 })).toEqual({ ok: false, reason: 'bad_body' });
    expect(verifyWakeWebhook({ headers: { ...sign(JSON.stringify(wake)), 'webhook-signature': 'v1,!!!not base64!!!' }, body: JSON.stringify(wake), secret, now: 1_790_000_000 })).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('throws on a secret that is not one: that is configuration, not input', () => {
    expect(() => verifyWakeWebhook({ headers: {}, body: '', secret: 'plain' })).toThrow(/whsec_/);
    expect(() => verifyWakeWebhook({ headers: {}, body: '', secret: [] })).toThrow();
  });

  it('interoperates with the signer STACK runs', async () => {
    const { signStandardWebhook, generateWebhookSecret } = await import('../../../shared/src/utils/standard-webhooks.js');
    const key = generateWebhookSecret();
    const body = JSON.stringify(wake);
    const headers = signStandardWebhook({ id: 'wke_abc', body, secrets: [key] });
    expect(verifyWakeWebhook({ headers, body, secret: key }).ok).toBe(true);
  });
});
