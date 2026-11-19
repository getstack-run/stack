import { afterEach, describe, expect, it, vi } from 'vitest';
import { OPENROUTER_IDLE_TIMEOUT_MS } from '@stack/shared';
import { callOpenRouter, forwardedRequestHeaders, rewriteLocation } from './upstream.js';
import type { OpenRouterCall } from './request.js';

const CALL: OpenRouterCall = {
  method: 'POST', path: '/chat/completions', search: '', match: null, contentType: 'application/json',
  rawBody: Buffer.from('{"a":1}'), body: { a: 1 }, upstream: new URL('https://openrouter.ai/api/v1/chat/completions'),
};

afterEach(() => {
  vi.useRealTimers();
});

describe('what goes to OpenRouter', () => {
  it('passes every header but the caller\'s credentials, cookies, STACK\'s own headers, the host and those of one hop', () => {
    expect(forwardedRequestHeaders({
      authorization: 'Bearer secret', cookie: 'a=b', 'x-passport-token': 'p', 'X-Stack-Save-Output': 'drive', 'x-stack-authority-request-id': 'r', host: 'api.getstack.run',
      connection: 'keep-alive, x-hop', 'x-hop': '1', 'keep-alive': 'timeout=5', 'proxy-authorization': 'Basic x', te: 'trailers', trailer: 'x', 'transfer-encoding': 'chunked', upgrade: 'h2c',
      'content-length': '7', expect: '100-continue',
      'content-type': 'application/json', accept: 'text/event-stream', 'http-referer': 'https://app.example', 'x-title': 'App',
      'x-openrouter-cache': 'true', 'X-OpenRouter-Metadata': 'enabled', 'x-anthropic-beta': 'a', 'anthropic-beta': 'context-1m', 'openai-beta': 'x', 'anthropic-version': '2023-06-01',
      'x-max-cost-cents': '5', 'user-agent': 'agent/1', 'x-custom': 'yes',
      forwarded: 'for=1.2.3.4', 'x-forwarded-for': '1.2.3.4', 'X-Forwarded-Proto': 'https', 'x-real-ip': '1.2.3.4', via: '1.1 proxy.example', 'fly-client-ip': '1.2.3.4', 'fly-request-id': 'r', 'fly-forwarded-port': '443',
    })).toEqual({
      'content-type': 'application/json', accept: 'text/event-stream', 'http-referer': 'https://app.example', 'x-title': 'App',
      'x-openrouter-cache': 'true', 'x-openrouter-metadata': 'enabled', 'x-anthropic-beta': 'a', 'anthropic-beta': 'context-1m', 'openai-beta': 'x', 'anthropic-version': '2023-06-01',
      'x-max-cost-cents': '5', 'user-agent': 'agent/1', 'x-custom': 'yes',
    });
  });

  it('passes a header of any length and one given twice, joined', () => {
    const long = 'a'.repeat(9_000);
    expect(forwardedRequestHeaders({ 'x-long': long, 'x-twice': ['a', 'b'], 'x-empty': '' })).toEqual({ 'x-long': long, 'x-twice': 'a, b', 'x-empty': '' });
  });

  it('sends the key last, so nothing the caller sent can stand in for it, and follows no redirect', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) => new Response('{}'));
    await callOpenRouter({ call: CALL, apiKey: 'sk-key', incomingHeaders: { authorization: 'Bearer caller' }, fetchImpl });
    const [url, init] = fetchImpl.mock.calls[0]! as unknown as [string, RequestInit & { headers: Record<string, string> }];
    expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
    expect(init.headers['authorization']).toBe('Bearer sk-key');
    expect(init.redirect).toBe('manual');
  });

  it('does not send the call at all, and reads nothing, when the caller has already hung up or hangs up before OpenRouter answers', async () => {
    const early = new AbortController();
    early.abort();
    const fetchEarly = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      if (init.signal?.aborted) reject(new DOMException('aborted', 'AbortError'));
      init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }));
    await expect(callOpenRouter({ call: CALL, apiKey: 'k', incomingHeaders: {}, signal: early.signal, fetchImpl: fetchEarly })).rejects.toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
    expect((fetchEarly.mock.calls[0]![1] as RequestInit).signal?.aborted).toBe(true);
    // Hung up while OpenRouter has not answered: the call in flight is aborted.
    const later = new AbortController();
    const fetchLater = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }));
    const pending = callOpenRouter({ call: CALL, apiKey: 'k', incomingHeaders: {}, signal: later.signal, fetchImpl: fetchLater });
    later.abort();
    await expect(pending).rejects.toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
    expect((fetchLater.mock.calls[0]![1] as RequestInit).signal?.aborted).toBe(true);
  });

  it('sends no body with a read', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) => new Response('{}'));
    await callOpenRouter({ call: { ...CALL, method: 'GET', rawBody: null }, apiKey: 'k', incomingHeaders: {}, fetchImpl });
    expect((fetchImpl.mock.calls[0]![1] as RequestInit).body).toBeUndefined();
  });

  it('says only that OpenRouter could not be reached, whatever the network said', async () => {
    const fetchImpl = vi.fn(async () => { throw new Error('getaddrinfo ENOTFOUND sk-key'); });
    await expect(callOpenRouter({ call: CALL, apiKey: 'sk-key', incomingHeaders: {}, fetchImpl })).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE', statusCode: 503, stackSide: true, message: 'OpenRouter could not be reached. Nothing was charged.',
    });
  });
});

describe('what comes back', () => {
  it('keeps the headers a caller may use and drops cookies, CORS and caching', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200, headers: {
      'content-type': 'application/json', 'x-generation-id': 'gen-1', 'x-provider-name': 'Acme', 'x-openrouter-cache-status': 'HIT',
      'retry-after': '3', 'set-cookie': '__cf_bm=x', 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=120', 'server': 'cloudflare',
    } }));
    const answer = await callOpenRouter({ call: CALL, apiKey: 'k', incomingHeaders: {}, fetchImpl });
    expect(answer.headers).toEqual({
      'content-type': 'application/json', 'x-generation-id': 'gen-1', 'x-provider-name': 'Acme', 'x-openrouter-cache-status': 'HIT', 'retry-after': '3',
    });
    expect(answer.generationIdHeader).toBe('gen-1');
  });

  it('turns a redirect into a path on this gateway, and drops one that points anywhere else', () => {
    expect(rewriteLocation('/api/v1/tools/web_search')).toBe('/v1/llm/openrouter/tools/web_search');
    expect(rewriteLocation('https://openrouter.ai/api/v1/models?x=1')).toBe('/v1/llm/openrouter/models?x=1');
    expect(rewriteLocation('https://evil.example/api/v1/models')).toBeNull();
    expect(rewriteLocation('https://openrouter.ai/other')).toBeNull();
  });

  it('streams the body and passes every byte', async () => {
    const parts = [new Uint8Array([1, 2]), new Uint8Array([3])];
    const fetchImpl = vi.fn(async () => new Response(new ReadableStream({ start(c) { for (const p of parts) c.enqueue(p); c.close(); } })));
    const answer = await callOpenRouter({ call: CALL, apiKey: 'k', incomingHeaders: {}, fetchImpl });
    const got: number[] = [];
    for await (const chunk of answer.body!) got.push(...chunk);
    expect(got).toEqual([1, 2, 3]);
  });

  it('breaks off an answer that sends nothing for too long', async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(async () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); } })));
    const answer = await callOpenRouter({ call: CALL, apiKey: 'k', incomingHeaders: {}, fetchImpl });
    const read = (async () => {
      const seen: number[] = [];
      try {
        for await (const chunk of answer.body!) seen.push(chunk.length);
      } catch (error) {
        return { seen, error };
      }
      return { seen, error: null };
    })();
    await vi.advanceTimersByTimeAsync(OPENROUTER_IDLE_TIMEOUT_MS + 1_000);
    const { seen, error } = await read;
    expect(seen).toEqual([1]);
    expect(error).toMatchObject({ code: 'UPSTREAM_TIMEOUT', statusCode: 504 });
  });

  it('passes an answer of any size on, with no cut at 1 GB', async () => {
    const chunk = new Uint8Array(64 * 1024 * 1024);
    let sent = 0;
    const fetchImpl = vi.fn(async () => new Response(new ReadableStream({
      pull(c) {
        if (sent === 17) { c.close(); return; }
        sent += 1;
        c.enqueue(chunk);
      },
    })));
    const answer = await callOpenRouter({ call: CALL, apiKey: 'k', incomingHeaders: {}, fetchImpl });
    let total = 0;
    for await (const part of answer.body!) total += part.length;
    expect(total).toBe(17 * 64 * 1024 * 1024);
    expect(total).toBeGreaterThan(1024 * 1024 * 1024);
  });
});
