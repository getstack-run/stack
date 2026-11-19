import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CONTROL_BREAKER_OPEN_MS,
  CONTROL_DECISION_MAX_IN_FLIGHT,
  CONTROL_DECISION_RESPONSE_MAX_BYTES,
  generateWebhookSecret,
  isBlockedIp,
  signStandardWebhook,
  UnsafeUrlError,
  verifyStandardWebhook,
  type ControlDecisionAnswer,
  type ControlDecisionRequest,
} from '@stack/shared';
import type { ControlSocketRuntime } from '@stack/vault';
import { buildDecisionRequest } from './request-builder.js';
import { RemoteDecider } from './remote-decider.js';
import type { DecisionContext } from './types.js';

// The network path (no injected fetch) resolves and fetches through the shared
// guard. Both are replaced by recorders that behave like the real guard for a
// private address, so DNS can be changed under the decider's feet.
const net = vi.hoisted(() => ({
  table: new Map<string, string[]>(),
  resolves: [] as string[],
  fetches: [] as Array<{ url: string; pinned: readonly string[] | undefined }>,
  respond: undefined as undefined | ((init: RequestInit) => Response),
  /** A lookup that is still in flight until this settles. */
  gate: undefined as undefined | Promise<void>,
  /** A lookup that fails with this. */
  failWith: undefined as undefined | Error,
}));
vi.mock('@stack/shared', async (importActual) => {
  const actual = await importActual<typeof import('@stack/shared')>();
  return {
    ...actual,
    resolvePublicUrl: vi.fn(async (raw: string, options?: { allowedProtocols?: string[] }) => {
      const url = actual.parsePublicUrl(raw, options);
      net.resolves.push(url.hostname);
      if (net.gate) await net.gate;
      if (net.failWith) throw net.failWith;
      const addresses = net.table.get(url.hostname);
      if (!addresses) return actual.resolvePublicUrl(raw, options);
      if (addresses.some((address) => actual.isBlockedIp(address))) {
        throw new actual.UnsafeUrlError(`Host ${url.hostname} resolves to a non-public address`);
      }
      return { url, addresses: addresses.map((address) => ({ address, family: 4 })) };
    }),
    publicFetch: vi.fn(async (input: string, init: RequestInit, options?: { resolvedAddresses?: readonly string[] }) => {
      net.fetches.push({ url: String(input), pinned: options?.resolvedAddresses });
      if (!net.respond) throw new Error('no fake response');
      return net.respond(init);
    }),
  };
});

const SECRET = generateWebhookSecret();
const OLD_SECRET = generateWebhookSecret();
const URL_ = 'https://control.customer.example/decide';

function enforcing(over: Partial<ControlSocketRuntime> = {}): ControlSocketRuntime {
  return {
    socketId: 'csk_1', modeSetting: 'remote', decisionUrl: URL_, decisionStatus: 'enforcing', timeoutMs: 300, onUnavailable: 'refuse',
    checkedTypes: null, ...over,
  };
}

function context(over: Partial<ControlSocketRuntime> = {}, id = 'dec_aaaaaaaaaaaaaaaaaaaaaaaa'): DecisionContext {
  const { request, body } = buildDecisionRequest({
    decisionId: id, now: new Date('2026-10-21T10:00:00Z'), deadlineMs: 300, test: false, operatorId: 'op_1', socketId: 'csk_1',
    accountId: 'acct_1', agent: { id: 'agt_1', passportJti: 'pas_1', missionId: 'ms_1' }, actorKind: 'agent',
    action: 'email.send', target: { recipients: [{ address: 'a@x.test', domain: 'x.test' }], recipient_count: 1 },
    amount: null, purpose: null, retryRef: null,
  });
  return { request, body, operatorId: 'op_1', socket: enforcing(over) };
}

interface Reply {
  status?: number;
  answer?: Partial<ControlDecisionAnswer>;
  rawBody?: string;
  secret?: string;
  headerId?: string;
  timestamp?: number;
  unsigned?: boolean;
}

function reply(request: ControlDecisionRequest, r: Reply = {}): Response {
  const body = r.rawBody ?? JSON.stringify({
    decision_id: request.decision_id, request_digest: request.request_digest, verdict: 'allow', ...r.answer,
  });
  const headers: Record<string, string> = r.unsigned
    ? {}
    : { ...signStandardWebhook({ id: r.headerId ?? request.decision_id, body, secrets: [r.secret ?? SECRET], ...(r.timestamp ? { timestamp: r.timestamp } : {}) }) };
  return new Response(body, { status: r.status ?? 200, headers });
}

function makeDecider(
  fetchFn: (url: string, init: RequestInit) => Promise<Response>,
  extra: { secrets?: string[] | null; now?: () => number } = {},
) {
  const noteAnswer = vi.fn<(operatorId: string, good: boolean) => Promise<void>>(async () => {});
  const sockets = {
    secrets: vi.fn(async () => (extra.secrets === undefined ? [SECRET] : extra.secrets)),
    noteAnswer,
  };
  const decider = new RemoteDecider({ sockets, fetchFn, urlGuard: async () => {}, ...(extra.now ? { now: extra.now } : {}) });
  return { decider, sockets, noteAnswer };
}

const parse = (init: RequestInit) => JSON.parse(String(init.body)) as ControlDecisionRequest;

beforeEach(() => {
  net.table.clear();
  net.resolves.length = 0;
  net.gate = undefined;
  net.failWith = undefined;
  net.fetches.length = 0;
  net.respond = undefined;
});
afterEach(() => vi.useRealTimers());

describe('RemoteDecider: the answer', () => {
  it('allows when the customer server answers a signed allow for this request', async () => {
    const { decider } = makeDecider(async (_u, init) => reply(parse(init), { answer: { policy_ref: 'pol_7' } }));
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'allow', policyRef: 'pol_7' });
  });

  it('denies with the reason and the pending-approval reference, cleaned for the agent', async () => {
    const { decider } = makeDecider(async (_u, init) => reply(parse(init), {
      answer: { verdict: 'deny', reason: { code: 'over_daily_limit', message: 'Limit\u0000 reached\u001b[31m' }, retry: { ref: 'apr_9', after_seconds: 60 } },
    }));
    const result = await decider.decide(context());
    expect(result).toEqual({
      verdict: 'deny', reason: { code: 'over_daily_limit', message: 'Limit  reached [31m' },
      retry: { ref: 'apr_9', after_seconds: 60 }, policyRef: null,
    });
  });

  it('signs the request with the decision secret in Standard Webhooks form, and sends no content', async () => {
    let seen: { init: RequestInit; body: string } | null = null;
    const { decider } = makeDecider(async (_u, init) => {
      seen = { init, body: String(init.body) };
      return reply(parse(init));
    }, { secrets: [SECRET, OLD_SECRET] });
    const ctx = context();
    await decider.decide(ctx);
    const sent = seen!;
    const headers = sent.init.headers as Record<string, string>;
    expect(headers['webhook-id']).toBe(ctx.request.decision_id);
    // Both live secrets signed it, so a receiver holding either accepts it.
    for (const secret of [SECRET, OLD_SECRET]) {
      expect(verifyStandardWebhook({ headers, body: sent.body, secrets: [secret], toleranceSeconds: 300 }).ok).toBe(true);
    }
    // A captured request replayed after the tolerance, and a body changed in transit, are refused.
    const issuedAt = Number(headers['webhook-timestamp']);
    expect(verifyStandardWebhook({ headers, body: sent.body, secrets: [SECRET], toleranceSeconds: 300, now: issuedAt + 301 })).toEqual({ ok: false, reason: 'stale' });
    expect(verifyStandardWebhook({ headers, body: `${sent.body} `, secrets: [SECRET], toleranceSeconds: 300 })).toEqual({ ok: false, reason: 'bad_signature' });
    expect(sent.init.redirect).toBe('manual');
    expect(JSON.parse(sent.body)).toMatchObject({ type: 'stack.decision.request', version: '1', action: { type: 'email.send' } });
    expect(sent.body).not.toMatch(/subject|"body"|password|secret|token/i);
  });
});

describe('RemoteDecider: no usable answer refuses', () => {
  const cases: Array<[string, (request: ControlDecisionRequest) => Response, string]> = [
    ['an error status', (r) => reply(r, { status: 500 }), 'http_status'],
    ['a redirect status', (r) => reply(r, { status: 302 }), 'http_status'],
    ['an unsigned answer', (r) => reply(r, { unsigned: true }), 'bad_signature'],
    ['an answer signed with another secret', (r) => reply(r, { secret: generateWebhookSecret() }), 'bad_signature'],
    ['a stale signed answer', (r) => reply(r, { timestamp: Math.floor(Date.now() / 1000) - 3_600 }), 'bad_signature'],
    ['an answer for another decision id in the header', (r) => reply(r, { headerId: 'dec_bbbbbbbbbbbbbbbbbbbbbbbb' }), 'mismatch'],
    ['an answer whose body names another decision', (r) => reply(r, { answer: { decision_id: 'dec_bbbbbbbbbbbbbbbbbbbbbbbb' } }), 'mismatch'],
    ['an answer echoing another request digest', (r) => reply(r, { answer: { request_digest: `sha256:${'0'.repeat(64)}` } }), 'mismatch'],
    ['a body that is not JSON', (r) => reply(r, { rawBody: 'allow' }), 'bad_body'],
    ['a verdict outside allow and deny', (r) => reply(r, { answer: { verdict: 'maybe' as never } }), 'bad_body'],
    ['a reason code outside the pattern', (r) => reply(r, { answer: { verdict: 'deny', reason: { code: 'No Way!' } } }), 'bad_body'],
    ['a body over 16 KB', (r) => reply(r, { rawBody: JSON.stringify({ pad: 'x'.repeat(CONTROL_DECISION_RESPONSE_MAX_BYTES) }) }), 'bad_body'],
  ];
  it.each(cases)('%s', async (_name, build, cause) => {
    const { decider } = makeDecider(async (_u, init) => build(parse(init)));
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause });
  });

  it('an unreachable server, and one that throws', async () => {
    const { decider } = makeDecider(async () => { throw new TypeError('fetch failed'); });
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'unreachable' });
  });

  it('a server that does not answer within the timeout is refused at the timeout', async () => {
    const { decider } = makeDecider((_u, init) => new Promise<Response>((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }));
    const started = Date.now();
    await expect(decider.decide(context({ timeoutMs: 120 }))).resolves.toEqual({ verdict: 'unavailable', cause: 'timeout' });
    expect(Date.now() - started).toBeLessThan(600);
  });

  it('never trusts a timeout longer than 2 seconds', async () => {
    vi.useFakeTimers();
    const { decider } = makeDecider(() => new Promise<Response>(() => {}));
    const pending = decider.decide(context({ timeoutMs: 60_000 }));
    await vi.advanceTimersByTimeAsync(2_001);
    await expect(pending).resolves.toEqual({ verdict: 'unavailable', cause: 'timeout' });
  });

  it('refuses without calling the server when the address is unverified or paused, or the secret is gone', async () => {
    const fetchFn = vi.fn(async (_u: string, init: RequestInit) => reply(parse(init)));
    const { decider } = makeDecider(fetchFn);
    await expect(decider.decide(context({ decisionStatus: 'unverified' }))).resolves.toEqual({ verdict: 'unavailable', cause: 'unverified' });
    await expect(decider.decide(context({ decisionUrl: null }))).resolves.toEqual({ verdict: 'unavailable', cause: 'unverified' });
    await expect(decider.decide(context({ decisionStatus: 'paused' }))).resolves.toEqual({ verdict: 'unavailable', cause: 'paused' });
    const noSecret = makeDecider(fetchFn, { secrets: null });
    await expect(noSecret.decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'secret_unavailable' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('counts answers that fail their signature, and clears the count on a good one', async () => {
    let good = false;
    const { decider, noteAnswer } = makeDecider(async (_u, init) => reply(parse(init), { unsigned: !good }));
    await decider.decide(context());
    expect(noteAnswer).toHaveBeenLastCalledWith('op_1', false);
    good = true;
    await decider.decide(context());
    expect(noteAnswer).toHaveBeenLastCalledWith('op_1', true);
  });
});

describe('RemoteDecider: load', () => {
  it('queues past the in-flight limit up to the deadline, then answers busy', async () => {
    const releases: Array<() => void> = [];
    const fetchFn = vi.fn((_u: string, init: RequestInit) => new Promise<Response>((resolve) => {
      releases.push(() => resolve(reply(parse(init))));
    }));
    const { decider } = makeDecider(fetchFn);
    const running = Array.from({ length: CONTROL_DECISION_MAX_IN_FLIGHT }, (_, n) =>
      decider.decide(context({ timeoutMs: 1_000 }, `dec_${String(n).padStart(24, '0')}`)));
    await vi.waitFor(() => expect(fetchFn).toHaveBeenCalledTimes(CONTROL_DECISION_MAX_IN_FLIGHT));
    const waiting = await decider.decide(context({ timeoutMs: 80 }, 'dec_zzzzzzzzzzzzzzzzzzzzzzzz'));
    expect(waiting).toEqual({ verdict: 'unavailable', cause: 'busy' });
    expect(fetchFn).toHaveBeenCalledTimes(CONTROL_DECISION_MAX_IN_FLIGHT);
    releases.forEach((release) => release());
    const answers = await Promise.all(running);
    expect(answers.every((a) => a.verdict === 'allow')).toBe(true);
  });

  it('opens a breaker after five failures in a row, then lets one probe through after 15 seconds', async () => {
    let clock = 1_000_000;
    let healthy = false;
    const fetchFn = vi.fn(async (_u: string, init: RequestInit) => (healthy ? reply(parse(init)) : reply(parse(init), { status: 500 })));
    const { decider } = makeDecider(fetchFn, { now: () => clock });
    for (let n = 0; n < 5; n += 1) {
      expect((await decider.decide(context())).verdict).toBe('unavailable');
    }
    expect(fetchFn).toHaveBeenCalledTimes(5);
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'breaker_open' });
    expect(fetchFn).toHaveBeenCalledTimes(5);
    clock += CONTROL_BREAKER_OPEN_MS + 1;
    healthy = true;
    await expect(decider.decide(context())).resolves.toMatchObject({ verdict: 'allow' });
    expect(fetchFn).toHaveBeenCalledTimes(6);
    // The probe succeeded: closed again.
    await expect(decider.decide(context())).resolves.toMatchObject({ verdict: 'allow' });
  });

  it('a failed probe reopens it for another 15 seconds', async () => {
    let clock = 5_000_000;
    const fetchFn = vi.fn(async (_u: string, init: RequestInit) => reply(parse(init), { status: 503 }));
    const { decider } = makeDecider(fetchFn, { now: () => clock });
    for (let n = 0; n < 5; n += 1) await decider.decide(context());
    clock += CONTROL_BREAKER_OPEN_MS + 1;
    await decider.decide(context());
    expect(fetchFn).toHaveBeenCalledTimes(6);
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'breaker_open' });
    expect(fetchFn).toHaveBeenCalledTimes(6);
  });
});

describe('RemoteDecider: the address is checked at the moment of every call', () => {
  const settled = () => new Promise((resolve) => setTimeout(resolve, 10));
  function networkDecider(now: () => number) {
    const sockets = { secrets: vi.fn(async () => [SECRET]), noteAnswer: vi.fn(async () => {}) };
    return new RemoteDecider({ sockets, now });
  }

  it.each([
    ['a loopback address', 'https://127.0.0.1/decide'],
    ['an IPv6 loopback', 'https://[::1]/decide'],
    ['the cloud metadata address', 'https://169.254.169.254/latest/meta-data'],
    ['a private network address', 'https://10.1.2.3/decide'],
    ['localhost', 'https://localhost/decide'],
    ['an internal name', 'https://db.internal/decide'],
    ['plain http in production', 'http://control.customer.example/decide'],
    ['URL credentials', 'https://user:pass@control.customer.example/decide'],
  ])('refuses %s without any connection', async (_name, url) => {
    const decider = networkDecider(Date.now);
    await expect(decider.decide(context({ decisionUrl: url }))).resolves.toEqual({ verdict: 'unavailable', cause: 'unsafe_address' });
    expect(net.fetches).toEqual([]);
  });

  it('pins the connection to the checked addresses, resolves again after a minute, and refuses a host that now points inside', async () => {
    let clock = 10_000_000;
    const decider = networkDecider(() => clock);
    net.table.set('control.customer.example', ['93.184.216.34']);
    net.respond = (init) => reply(parse(init));
    expect((await decider.decide(context())).verdict).toBe('allow');
    expect(net.fetches).toEqual([{ url: URL_, pinned: ['93.184.216.34'] }]);
    // Within the minute the checked answer is reused, never looked up again.
    await decider.decide(context());
    expect(net.resolves).toHaveLength(1);

    // DNS rebinding: the host now answers a private address. The decision in flight still goes only to
    // the addresses that were checked; the refresh sees the private answer and drops them.
    clock += 61_000;
    net.table.set('control.customer.example', ['10.0.0.5']);
    await expect(decider.decide(context())).resolves.toMatchObject({ verdict: 'allow' });
    expect(net.fetches.at(-1)).toEqual({ url: URL_, pinned: ['93.184.216.34'] });
    await settled();
    expect(net.resolves).toHaveLength(2);
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'unsafe_address' });
    expect(net.fetches).toHaveLength(3);
    expect(isBlockedIp('10.0.0.5')).toBe(true);
    expect(UnsafeUrlError).toBeDefined();
  });

  describe('a lookup never sits on the decision path once an address is known', () => {
    let clock: number;
    let decider: RemoteDecider;

    async function warm() {
      clock = 10_000_000;
      decider = networkDecider(() => clock);
      net.table.set('control.customer.example', ['93.184.216.34']);
      net.respond = (init) => reply(parse(init));
      await decider.decide(context());
      expect(net.resolves).toHaveLength(1);
    }

    it('the first decision for an address pays the lookup: there is nothing checked to use yet', async () => {
      clock = 10_000_000;
      decider = networkDecider(() => clock);
      net.table.set('control.customer.example', ['93.184.216.34']);
      net.respond = (init) => reply(parse(init));
      let finish!: () => void;
      net.gate = new Promise<void>((resolve) => { finish = resolve; });
      let done = false;
      const pending = decider.decide(context()).then((result) => { done = true; return result; });
      await settled();
      expect(done).toBe(false);
      finish();
      await expect(pending).resolves.toMatchObject({ verdict: 'allow' });
    });

    it('an address that is getting old is refreshed in the background while the decision goes to the checked addresses', async () => {
      await warm();
      clock += 50_000;
      let finish!: () => void;
      net.gate = new Promise<void>((resolve) => { finish = resolve; });
      net.table.set('control.customer.example', ['93.184.216.99']);
      // The lookup is stuck, yet the decision is answered at once, from the last checked addresses.
      await expect(decider.decide(context())).resolves.toMatchObject({ verdict: 'allow' });
      expect(net.fetches.at(-1)).toEqual({ url: URL_, pinned: ['93.184.216.34'] });
      expect(net.resolves).toHaveLength(2);
      finish();
      await settled();
      await decider.decide(context());
      expect(net.fetches.at(-1)).toEqual({ url: URL_, pinned: ['93.184.216.99'] });
    });

    it('asks once for a refresh however many decisions arrive while it runs', async () => {
      await warm();
      clock += 50_000;
      let finish!: () => void;
      net.gate = new Promise<void>((resolve) => { finish = resolve; });
      await Promise.all([decider.decide(context()), decider.decide(context({}, 'dec_bbbbbbbbbbbbbbbbbbbbbbbb')), decider.decide(context({}, 'dec_cccccccccccccccccccccccc'))]);
      expect(net.resolves).toHaveLength(2);
      finish();
      await settled();
      expect(net.resolves).toHaveLength(2);
    });

    it('keeps the last checked addresses when a refresh fails for any reason but an unsafe answer', async () => {
      await warm();
      clock += 70_000;
      net.failWith = new Error('SERVFAIL');
      await expect(decider.decide(context())).resolves.toMatchObject({ verdict: 'allow' });
      await settled();
      net.failWith = undefined;
      clock += 10_000;
      await expect(decider.decide(context({}, 'dec_dddddddddddddddddddddddd'))).resolves.toMatchObject({ verdict: 'allow' });
      expect(net.fetches.at(-1)).toEqual({ url: URL_, pinned: ['93.184.216.34'] });
    });

    it('drops the checked addresses the moment a refresh says the host now points inside', async () => {
      await warm();
      clock += 70_000;
      net.table.set('control.customer.example', ['10.0.0.5']);
      await decider.decide(context());
      await settled();
      await expect(decider.decide(context({}, 'dec_eeeeeeeeeeeeeeeeeeeeeeee'))).resolves.toEqual({ verdict: 'unavailable', cause: 'unsafe_address' });
    });

    it('goes back to a lookup on the decision path once the checked addresses are too old to trust', async () => {
      await warm();
      clock += 10 * 60_000;
      net.table.set('control.customer.example', ['10.0.0.5']);
      await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'unsafe_address' });
      expect(net.resolves).toHaveLength(2);
    });
  });

  it('answers unsafe when the connection layer refuses a redirect, and unreachable for a refused connection', async () => {
    const decider = networkDecider(Date.now);
    net.table.set('control.customer.example', ['93.184.216.34']);
    net.respond = () => { throw new UnsafeUrlError('Outbound redirects are not allowed'); };
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'unsafe_address' });
    net.respond = () => { throw new Error('ECONNREFUSED'); };
    await expect(decider.decide(context())).resolves.toEqual({ verdict: 'unavailable', cause: 'unreachable' });
  });
});
