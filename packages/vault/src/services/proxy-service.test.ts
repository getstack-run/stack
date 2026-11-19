import { describe, it, expect, vi, afterEach } from 'vitest';

// The proxy runs an SSRF guard (assertPublicUrl / resolvePublicUrl) that does
// a real DNS lookup before forwarding — nondeterministic in a unit test. Stub
// it to a fixed public answer so this test exercises ONLY the service logic.
const publicFetchCalls = vi.hoisted(() => [] as Array<Record<string, unknown> | undefined>);
vi.mock('@stack/shared', async (importActual) => {
  const actual = await importActual<typeof import('@stack/shared')>();
  const { PublicFetchLimitError } = await import('../../../shared/src/utils/public-fetch.js');
  return { ...actual, assertPublicUrl: vi.fn().mockResolvedValue(undefined),
    resolvePublicUrl: vi.fn(async (raw: string) => ({ url: new URL(raw), addresses: [{ address: '93.184.215.14', family: 4 }] })),
    PublicFetchLimitError,
    // Service-only fixtures; the real socket boundary is tested in shared.
    publicFetch: (input: string, init: RequestInit, options?: Record<string, unknown>) => {
      publicFetchCalls.push(options);
      return globalThis.fetch(input, init);
    } };
});

import { ProxyService } from './proxy-service.js';
import { PublicFetchLimitError } from '../../../shared/src/utils/public-fetch.js';
import type { ProxyRequestInput } from '@stack/shared';

/**
 * 244 Finding 5 — the proxy must forward a JSON `body` byte-faithful
 * whether the caller sends it as a native object OR as an already-serialized
 * JSON string (some MCP arg-encoding paths pre-stringify nested JSON). Before
 * the fix, `proxy-service.ts` did an unconditional `JSON.stringify(input.body)`,
 * so a string body got double-encoded ("{\"model\":...}") → the upstream
 * (e.g. OpenRouter) rejected it with "JSON parsing failed". The audit path
 * already guarded this; the forward path did not. This test locks both.
 */

const UPSTREAM = 'https://api.openrouter.ai/api/v1/chat/completions';

describe('OAuth credential injection', () => {
  it('injects only the access token and never refresh credentials or OAuth app secrets', () => {
    const credential = JSON.stringify({ access_token: 'synthetic-access', refresh_token: 'synthetic-refresh',
      client_id: 'client', client_secret: 'synthetic-secret', oauth_app_binding: { id: 'shared-app' }, expires_at: 1 });
    for (const provider of ['slack', 'github', 'google_drive', 'linear']) {
      expect(new ProxyService().resolveAuthHeaders(provider, credential)).toEqual({ Authorization: 'Bearer synthetic-access' });
      expect(new ProxyService().resolveAuthHeaders(provider, `  ${credential}`)).toEqual({ Authorization: 'Bearer synthetic-access' });
    }
    expect(new ProxyService().resolveAuthHeaders('slack', 'synthetic-plain')).toEqual({ Authorization: 'Bearer synthetic-plain' });
    expect(() => new ProxyService().resolveAuthHeaders('slack', JSON.stringify({ refresh_token: 'synthetic-refresh' }))).toThrow();
  });

  it('a connection of an OAuth service that holds no access token is a plain, non-retryable client error, not a retryable 503', () => {
    // GitHub connected with fields that hold no token of any kind: retrying can never make it work.
    let caught: unknown;
    try {
      new ProxyService().resolveAuthHeaders('github', JSON.stringify({ client_id: 'synthetic-client', refresh_token: 'synthetic-refresh' }));
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: 'CONNECTION_NO_ACCESS_TOKEN', statusCode: 409 });
    expect((caught as Error).message).toMatch(/no usable access token/i);
    expect((caught as Error).message).toMatch(/reconnect/i);
    expect((caught as { details?: Record<string, unknown> }).details?.['retry_after_seconds']).toBeUndefined();
  });

  it('keeps unknown provider metadata out of Bearer headers despite JSON whitespace', () => {
    const credential = '  ' + JSON.stringify({ access_token: 'synthetic-access', refresh_token: 'synthetic-refresh' });
    expect(new ProxyService().resolveAuthHeaders('custom_fixture', credential)).toEqual({ Authorization: 'Bearer synthetic-access' });
  });
});

describe('ProxyService.forward body encoding (Finding 5)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function captureOutboundBody(body: unknown): Promise<string | undefined> {
    let captured: unknown;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: { body?: unknown }) => {
        captured = init.body;
        return new Response('{"ok":true}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
    const svc = new ProxyService();
    const input = { service: 'openrouter', url: UPSTREAM, method: 'POST', body } as unknown as ProxyRequestInput;
    await svc.forward(input, {}, UPSTREAM, ['api.openrouter.ai']);
    return captured as string | undefined;
  }

  const OBJECT_BODY = { model: 'x', messages: [{ role: 'user', content: 'hi' }] };
  const CANONICAL = JSON.stringify(OBJECT_BODY);

  it('an OBJECT body is JSON-stringified once (unchanged behavior)', async () => {
    const out = await captureOutboundBody(OBJECT_BODY);
    expect(out).toBe(CANONICAL);
  });

  it('an already-serialized STRING body is passed through, NOT re-stringified', async () => {
    const out = await captureOutboundBody(CANONICAL);
    // The bug produced '"{\\"model\\":...}"' (a quoted, escaped string).
    // The fix must send the same bytes as the object path.
    expect(out).toBe(CANONICAL);
    expect(out).not.toContain('\\"'); // no escaped quotes = not double-encoded
  });

  it('object and string forms of the same body produce IDENTICAL outbound bytes', async () => {
    const fromObject = await captureOutboundBody(OBJECT_BODY);
    const fromString = await captureOutboundBody(CANONICAL);
    expect(fromString).toBe(fromObject);
  });

  it('undefined body sends no body', async () => {
    const out = await captureOutboundBody(undefined);
    expect(out).toBeUndefined();
  });

  it('never returns credential text from a transport validation error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Invalid header value: Bearer fixture-secret')));
    const service = new ProxyService();
    const result = await service.forward({ service: 'openrouter', method: 'GET' } as ProxyRequestInput,
      { Authorization: 'Bearer fixture-secret' }, UPSTREAM, ['api.openrouter.ai']);
    expect(result.status).toBe(502);
    expect(JSON.stringify(result)).not.toContain('fixture-secret');
  });

  it.each([
    { direction: 'request' as const, status: 413, message: 'Request too large' },
    { direction: 'response' as const, status: 502, message: 'Response too large' },
  ])('reports $direction size failures accurately', async ({ direction, status, message }) => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new PublicFetchLimitError('Size limit', direction, 30)));
    const result = await new ProxyService().forward({ service: 'openrouter', method: 'POST', body: 'fixture' } as ProxyRequestInput,
      {}, UPSTREAM, ['api.openrouter.ai']);
    expect(result.status).toBe(status);
    expect(result.body).toMatchObject({ error: message });
    if (direction === 'request') expect(result.body).toMatchObject({ max_bytes: 30 });
  });
});

/**
 * Credential-to-destination binding.
 *
 * `service` selects which stored credential is decrypted and injected; `url`
 * is whatever the agent asked for. Nothing connected the two, so a passport
 * granting `stripe` could send the live Stripe key to any public host — the
 * SSRF guard does not object, because an attacker's server is a perfectly
 * public address. These tests lock the binding shut.
 *
 * Note the SSRF guard is stubbed to a public answer at the top of this file, which
 * is exactly the condition under which the old code forwarded: it proves the
 * host check stands on its own rather than riding on the SSRF guard.
 */
describe('ProxyService.forward — credential-to-destination binding', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  const STRIPE = 'https://api.stripe.com/v1/charges';
  const ATTACKER = 'https://attacker.example.com/collect';

  function stubFetch() {
    const spy = vi.fn(async () => new Response('{"ok":true}', { status: 200 }));
    vi.stubGlobal('fetch', spy);
    return spy;
  }

  function call(url: string, allowedHosts: readonly string[], authHeaders = { Authorization: 'Bearer sk_live_SECRET' }) {
    const svc = new ProxyService();
    const input = { service: 'stripe', url, method: 'POST', body: { amount: 1 } } as unknown as ProxyRequestInput;
    return svc.forward(input, authHeaders, url, allowedHosts);
  }

  it('forwards to a declared host', async () => {
    const spy = stubFetch();
    const res = await call(STRIPE, ['api.stripe.com']);
    expect(res.status).toBe(200);
    expect(spy).toHaveBeenCalledOnce();
  });

  it('resolves the destination once and pins the reused connection to that answer', async () => {
    stubFetch();
    const { resolvePublicUrl } = await import('@stack/shared');
    vi.mocked(resolvePublicUrl).mockClear();
    publicFetchCalls.length = 0;
    const res = await call(STRIPE, ['api.stripe.com']);
    expect(res.status).toBe(200);
    expect(resolvePublicUrl).toHaveBeenCalledTimes(1);
    expect(publicFetchCalls).toHaveLength(1);
    expect(publicFetchCalls[0]).toMatchObject({ resolvedAddresses: ['93.184.215.14'], keepAlive: true });
  });

  it('refuses before any request when the destination resolves to a blocked address', async () => {
    const spy = stubFetch();
    const shared = await import('@stack/shared');
    vi.mocked(shared.resolvePublicUrl).mockRejectedValueOnce(new shared.UnsafeUrlError('Host api.stripe.com resolves to a non-public address'));
    const res = await call(STRIPE, ['api.stripe.com']);
    expect(res.status).toBe(400);
    expect(spy).not.toHaveBeenCalled();
  });

  it('REFUSES an undeclared host and never calls fetch', async () => {
    const spy = stubFetch();
    const res = await call(ATTACKER, ['api.stripe.com']);
    expect(res.status).toBe(403);
    expect((res.body as { code: string }).code).toBe('DESTINATION_NOT_ALLOWED');
    // The whole point: no credential left the process.
    expect(spy).not.toHaveBeenCalled();
  });

  it('never leaks the credential into the refusal body', async () => {
    stubFetch();
    const res = await call(ATTACKER, ['api.stripe.com']);
    expect(JSON.stringify(res.body)).not.toContain('sk_live_SECRET');
  });

  it('refuses when the connection declares no hosts at all', async () => {
    const spy = stubFetch();
    const res = await call(STRIPE, []);
    expect(res.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
  });

  it('checks the host AFTER query params are merged', async () => {
    const spy = stubFetch();
    const svc = new ProxyService();
    const input = {
      service: 'stripe',
      url: STRIPE,
      method: 'POST',
      query: { redirect: 'x' },
    } as unknown as ProxyRequestInput;
    const res = await svc.forward(input, {}, STRIPE, ['api.stripe.com']);
    expect(res.status).toBe(200);
    expect(spy).toHaveBeenCalledOnce();
  });

  it('is not fooled by userinfo pointing the URL at another host', async () => {
    const spy = stubFetch();
    // https://api.stripe.com@attacker.example.com/ actually resolves to
    // attacker.example.com. Naive prefix matching would forward this.
    const res = await call('https://api.stripe.com@attacker.example.com/v1', ['api.stripe.com']);
    expect(res.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
  });

  it('honours a dot-led suffix declaration for multi-host providers', async () => {
    const spy = stubFetch();
    const res = await call('https://s3.eu-north-1.amazonaws.com/bucket', ['.amazonaws.com']);
    expect(res.status).toBe(200);
    expect(spy).toHaveBeenCalledOnce();
  });
});

describe('ProxyService.forwardPrepared — durable operation transport semantics', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  const prepared = {
    service: 'stripe',
    method: 'POST' as const,
    finalUrl: 'https://api.stripe.com/v1/refunds',
    headers: { 'content-type': 'application/json', 'x-trace': 'trace-1' },
    bodyBytes: '{"amount":100}',
  };

  it('sends the admitted bytes and retains only allowlisted response headers', async () => {
    let sentBody: unknown;
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body?: unknown }) => {
      sentBody = init.body;
      return new Response('{"id":"re_1"}', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'idempotent-replayed': 'true',
          'stripe-request-id': 'req_1',
          'x-upstream-secret': `sk_test_${'a'.repeat(24)}`,
          'set-cookie': 'private=1',
        },
      });
    }));

    const outcome = await new ProxyService().forwardPrepared(
      prepared,
      { Authorization: 'Bearer fixture-secret' },
      ['api.stripe.com'],
    );
    expect(sentBody).toBe(prepared.bodyBytes);
    expect(outcome.kind).toBe('response');
    if (outcome.kind === 'response') {
      expect(outcome.response.headers).toEqual({
        'content-type': 'application/json',
        'idempotent-replayed': 'true',
        'stripe-request-id': 'req_1',
      });
    }
  });

  it('classifies failures after the dispatch claim as unknown', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new PublicFetchLimitError('limit', 'response', 10)));
    await expect(new ProxyService().forwardPrepared(prepared, {}, ['api.stripe.com']))
      .resolves.toEqual({ kind: 'outcome_unknown', reason: 'response_too_large' });

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('timed out', 'AbortError')));
    await expect(new ProxyService().forwardPrepared(prepared, {}, ['api.stripe.com']))
      .resolves.toEqual({ kind: 'outcome_unknown', reason: 'timeout' });
  });
});

describe('ProxyService egress signature (Web Bot Auth)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  const SIGNED = { Signature: 'sig1=:abc:', 'Signature-Input': 'sig1=("@authority")', 'Signature-Agent': 'sig1="https://api.stack.test"' };
  const subject = { operatorId: 'op_1', agentId: 'agt_1' };

  function capture() {
    const seen: Array<Record<string, string>> = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { headers: Record<string, string> }) => {
      seen.push(init.headers);
      return new Response('{"ok":true}', { status: 200 });
    }));
    return seen;
  }

  it('signs the request that leaves, from the URL as it is requested, after the query is merged', async () => {
    const seen = capture();
    const signer = { forAgent: vi.fn(async () => SIGNED) };
    const input = { service: 'shop', url: 'https://api.shop.example/items', method: 'GET', query: { page: '2' } } as unknown as ProxyRequestInput;
    await new ProxyService(signer).forward(input, { Authorization: 'Bearer t' }, input.url, ['api.shop.example'], subject);
    expect(signer.forAgent).toHaveBeenCalledWith(subject, { method: 'GET', url: 'https://api.shop.example/items?page=2' });
    expect(seen[0]).toMatchObject({ Authorization: 'Bearer t', ...SIGNED });
  });

  it('signs the admitted bytes\' request too, and the signature is not part of what the operation ledger hashes', async () => {
    const seen = capture();
    const signer = { forAgent: vi.fn(async () => SIGNED) };
    const prepared = { service: 'shop', method: 'POST' as const, finalUrl: 'https://api.shop.example/orders', headers: { 'content-type': 'application/json' }, bodyBytes: '{"a":1}' };
    await new ProxyService(signer).forwardPrepared(prepared, { Authorization: 'Bearer t' }, ['api.shop.example'], subject);
    expect(signer.forAgent).toHaveBeenCalledWith(subject, { method: 'POST', url: 'https://api.shop.example/orders' });
    expect(seen[0]).toMatchObject(SIGNED);
    expect(prepared.headers).toEqual({ 'content-type': 'application/json' });
  });

  it('sends nothing extra without a subject, without a signer, or for an agent the signer does not sign', async () => {
    const seen = capture();
    const input = { service: 'shop', url: 'https://api.shop.example/items', method: 'GET' } as unknown as ProxyRequestInput;
    const signer = { forAgent: vi.fn(async () => ({})) };
    await new ProxyService(signer).forward(input, {}, input.url, ['api.shop.example']);
    await new ProxyService().forward(input, {}, input.url, ['api.shop.example'], subject);
    await new ProxyService(signer).forward(input, {}, input.url, ['api.shop.example'], subject);
    expect(signer.forAgent).toHaveBeenCalledTimes(1);
    expect(seen.every((headers) => headers['Signature'] === undefined && headers['Signature-Agent'] === undefined)).toBe(true);
  });

  it('never signs a request it refused: the destination binding comes first', async () => {
    const seen = capture();
    const signer = { forAgent: vi.fn(async () => SIGNED) };
    const input = { service: 'shop', url: 'https://evil.example/x', method: 'GET' } as unknown as ProxyRequestInput;
    const res = await new ProxyService(signer).forward(input, {}, input.url, ['api.shop.example'], subject);
    expect(res.status).toBe(403);
    expect(signer.forAgent).not.toHaveBeenCalled();
    expect(seen).toHaveLength(0);
  });
});
