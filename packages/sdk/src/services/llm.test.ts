import { describe, it, expect, vi } from 'vitest';
import { LlmService } from './llm.js';
import { PassportSession } from './passport-session.js';
import { HttpClient } from '../client.js';

/**
 * LlmService TS SDK invariants:
 *
 *   L1 — anthropic.messages.create (non-streaming) posts to
 *        /v1/llm/anthropic/messages with X-Passport-Token header
 *   L2 — openai.chat.completions.create routes to /v1/llm/openai/chat/completions
 *   L3 — openrouter.chat.completions.create routes to /v1/llm/openrouter/chat/completions
 *   L4 — streaming call returns AsyncIterable, drains chunks via postStream
 *   L5 — intentApprovalId option threads as X-Intent-Approval-Id header
 *   L6 — passport accepts both raw string AND PassportSession
 *   L7 — usage.list builds query-string + GETs /v1/llm/usage
 *   L8 — usage.summary builds query-string + GETs /v1/llm/usage/summary
 *   L9 — openai.images.generate posts to its image route with the passport
 *   L10 — openrouter.request sends any method and path under /v1/llm/openrouter with the passport and the cap
 *   L11 — openrouter.request streams when the body asks for it; requestBytes returns a file's bytes
 *   L12 — the client's requestBytes sends the key, the passport and the body, returns the bytes, and throws the API's error
 */

function makeHttpStub(overrides: Partial<HttpClient> = {}): HttpClient {
  const stub = {
    get: vi.fn(async () => ({})),
    post: vi.fn(async () => ({})),
    put: vi.fn(async () => ({})),
    patch: vi.fn(async () => ({})),
    delete: vi.fn(async () => ({})),
    requestBytes: vi.fn(async () => ({ status: 200, contentType: 'audio/mpeg', bytes: new Uint8Array([1, 2, 3]) })),
    postStream: vi.fn(async () => new ReadableStream<Uint8Array>()),
    ...overrides,
  };
  return stub as unknown as HttpClient;
}

describe('LlmService — images on your own key', () => {
  it('L9 posts to the OpenAI image route with the passport, and returns files, not bytes', async () => {
    const result = { provider: 'openai', model: 'gpt-image-1', untrusted: true, key: 'own', files: [], revised_prompts: [] };
    const client = makeHttpStub({ post: vi.fn(async () => result) as never });
    const svc = new LlmService(client);
    expect(await svc.openai.images.generate({ model: 'gpt-image-1', prompt: 'a cat', size: '1024x1024' }, { passport: 'tok' })).toEqual(result);
    expect(client.post).toHaveBeenCalledWith(
      '/v1/llm/openai/images',
      { model: 'gpt-image-1', prompt: 'a cat', size: '1024x1024' },
      expect.objectContaining({ headers: expect.objectContaining({ 'X-Passport-Token': 'tok' }) }),
    );
  });
});

describe('LlmService — non-streaming provider calls', () => {
  it('L1 anthropic.messages.create posts to right path with passport header', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.anthropic.messages.create(
      { model: 'claude-opus-4-7', messages: [{ role: 'user', content: 'hi' }], max_tokens: 100 },
      { passport: 'eyJ.passport.token' },
    );
    expect(client.post).toHaveBeenCalledWith(
      '/v1/llm/anthropic/messages',
      expect.objectContaining({ model: 'claude-opus-4-7' }),
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Passport-Token': 'eyJ.passport.token' }),
      }),
    );
  });

  it('L2 openai.chat.completions.create routes correctly', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.openai.chat.completions.create(
      { model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] },
      { passport: 'tok' },
    );
    expect(client.post).toHaveBeenCalledWith(
      '/v1/llm/openai/chat/completions',
      expect.objectContaining({ model: 'gpt-4o' }),
      expect.any(Object),
    );
  });

  it('L3 openrouter.chat.completions.create routes correctly', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.openrouter.chat.completions.create(
      { model: 'meta-llama/llama-3.1-70b', messages: [{ role: 'user', content: 'hi' }] },
      { passport: 'tok' },
    );
    expect(client.post).toHaveBeenCalledWith(
      '/v1/llm/openrouter/chat/completions',
      expect.any(Object),
      expect.any(Object),
    );
  });

  it('L5 intentApprovalId threads as X-Intent-Approval-Id', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.anthropic.messages.create(
      { model: 'x', messages: [{ role: 'user', content: 'x' }], max_tokens: 1 },
      { passport: 'tok', intentApprovalId: 'ia_xyz' },
    );
    expect(client.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Object),
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Intent-Approval-Id': 'ia_xyz' }),
      }),
    );
  });

  it('threads a cost cap of the caller\'s own as X-Max-Cost-Cents, on every provider, and sends nothing without one', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.openrouter.chat.completions.create({ model: 'x', messages: [{ role: 'user', content: 'x' }] }, { passport: 'tok', maxCostCents: 25 });
    await svc.anthropic.messages.create({ model: 'x', messages: [{ role: 'user', content: 'x' }], max_tokens: 1 }, { passport: 'tok' });
    const headers = (client.post as unknown as { mock: { calls: Array<[string, unknown, { headers: Record<string, string> }]> } }).mock.calls.map((call) => call[2].headers);
    expect(headers[0]).toMatchObject({ 'X-Max-Cost-Cents': '25' });
    expect(headers[1]).not.toHaveProperty('X-Max-Cost-Cents');
  });

  it('threads a stable authority request id as a header', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.anthropic.messages.create(
      { model: 'x', messages: [{ role: 'user', content: 'x' }], max_tokens: 1 },
      { passport: 'tok', authorityRequestId: 'authority_request_abc123' },
    );
    expect(client.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Object),
      expect.objectContaining({
        headers: expect.objectContaining({
          'X-STACK-Authority-Request-Id': 'authority_request_abc123',
        }),
      }),
    );
  });
});

describe('LlmService — streaming', () => {
  it('L4 streaming call returns AsyncIterable, drains chunks via postStream', async () => {
    const chunks = [
      'event: content_block_delta\n',
      'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n',
      'event: content_block_delta\n',
      'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" world"}}\n\n',
      'event: message_stop\n',
      'data: {"type":"message_stop"}\n\n',
    ];
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const c of chunks) controller.enqueue(encoder.encode(c));
        controller.close();
      },
    });
    const client = makeHttpStub({
      postStream: vi.fn(async () => stream) as unknown as HttpClient['postStream'],
    });
    const svc = new LlmService(client);
    const result = await svc.anthropic.messages.create(
      { model: 'x', messages: [{ role: 'user', content: 'x' }], max_tokens: 1, stream: true },
      { passport: 'tok' },
    );
    // Must be AsyncIterable.
    expect(typeof (result as AsyncIterable<unknown>)[Symbol.asyncIterator]).toBe('function');
    const events: Array<{ type: string }> = [];
    for await (const evt of result as AsyncIterable<{ type: string }>) {
      events.push(evt);
    }
    // 3 events: two content_block_delta + one message_stop.
    expect(events).toHaveLength(3);
    expect(events[0]!.type).toBe('content_block_delta');
    expect(events[2]!.type).toBe('message_stop');
    expect(client.postStream).toHaveBeenCalledTimes(1);
    expect(client.post).not.toHaveBeenCalled();
  });
});

describe('LlmService — passport input shapes', () => {
  it('L6 accepts raw string passport', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    await svc.anthropic.messages.create(
      { model: 'x', messages: [{ role: 'user', content: 'x' }], max_tokens: 1 },
      { passport: 'raw-token' },
    );
    expect(client.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Object),
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Passport-Token': 'raw-token' }),
      }),
    );
  });

  it('L6 accepts PassportSession (calls session.getToken)', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    // Build a token with exp far in the future so getToken doesn't refresh.
    const farFuture = Math.floor(Date.now() / 1000) + 3600;
    const payload = Buffer.from(JSON.stringify({ exp: farFuture })).toString('base64url');
    const fakeToken = `header.${payload}.sig`;
    const session = new PassportSession(
      client,
      { token: fakeToken, jti: 'pas_x', expires_at: new Date(farFuture * 1000).toISOString() } as never,
      { agent_id: 'agt_x' } as never,
    );
    await svc.anthropic.messages.create(
      { model: 'x', messages: [{ role: 'user', content: 'x' }], max_tokens: 1 },
      { passport: session },
    );
    expect(client.post).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Object),
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Passport-Token': fakeToken }),
      }),
    );
  });
});

describe('LlmService.usage', () => {
  it('L7 list builds query-string + GETs /v1/llm/usage', async () => {
    const client = makeHttpStub({
      get: vi.fn(async () => ({ items: [], next_cursor: null })) as unknown as HttpClient['get'],
    });
    const svc = new LlmService(client);
    await svc.usage.list({
      limit: 5,
      provider: 'anthropic',
      passport_jti: 'pas_x',
      mission_id: 'ms_x',
      agent_id: 'agt_x',
      since: '2026-05-23T00:00:00Z',
    });
    expect(client.get).toHaveBeenCalledWith(
      '/v1/llm/usage',
      expect.objectContaining({
        limit: '5',
        provider: 'anthropic',
        passport_jti: 'pas_x',
        mission_id: 'ms_x',
        agent_id: 'agt_x',
        since: '2026-05-23T00:00:00Z',
      }),
    );
  });

  it('L8 summary builds query-string + GETs /v1/llm/usage/summary', async () => {
    const client = makeHttpStub({
      get: vi.fn(async () => ({ buckets: [] })) as unknown as HttpClient['get'],
    });
    const svc = new LlmService(client);
    await svc.usage.summary({
      provider: 'openai',
      group_by_model: false,
      since: '2026-05-01T00:00:00Z',
      until: '2026-06-01T00:00:00Z',
    });
    expect(client.get).toHaveBeenCalledWith(
      '/v1/llm/usage/summary',
      expect.objectContaining({
        provider: 'openai',
        group_by_model: 'false',
        since: '2026-05-01T00:00:00Z',
        until: '2026-06-01T00:00:00Z',
      }),
    );
  });
});

describe('LlmService — any OpenRouter endpoint', () => {
  const options = { passport: 'tok', maxCostCents: 250 };
  const headers = { headers: { 'X-Passport-Token': 'tok', 'X-Max-Cost-Cents': '250' } };

  it('L10 sends each method to the one path under the gateway, with the passport and the cap, and the body as written', async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    const body = { model: 'acme/embed-1', input: 'hello' };
    await svc.openrouter.request('POST', '/embeddings', { ...options, body });
    expect(client.post).toHaveBeenCalledWith('/v1/llm/openrouter/embeddings', body, expect.objectContaining(headers));

    await svc.openrouter.request('GET', '/models?output_modalities=all', { passport: 'tok' });
    expect(client.get).toHaveBeenCalledWith('/v1/llm/openrouter/models?output_modalities=all', undefined, { headers: { 'X-Passport-Token': 'tok' } });

    await svc.openrouter.request('PUT', '/some/thing', { ...options, body: { a: 1 } });
    expect(client.put).toHaveBeenCalledWith('/v1/llm/openrouter/some/thing', { a: 1 }, expect.objectContaining(headers));
    await svc.openrouter.request('PATCH', '/some/thing', { ...options, body: { a: 2 } });
    expect(client.patch).toHaveBeenCalledWith('/v1/llm/openrouter/some/thing', { a: 2 }, expect.objectContaining(headers));
    await svc.openrouter.request('DELETE', '/some/thing', options);
    expect(client.delete).toHaveBeenCalledWith('/v1/llm/openrouter/some/thing', expect.objectContaining(headers));
  });

  it('L10 returns the parsed JSON answer as the API gave it', async () => {
    const answer = { id: 'gen-1', data: [{ embedding: [0.1] }] };
    const client = makeHttpStub({ post: vi.fn(async () => answer) as never });
    expect(await new LlmService(client).openrouter.request('POST', '/embeddings', { passport: 'tok', body: { model: 'm', input: 'x' } })).toEqual(answer);
  });

  it("L10 refuses a path that is not one of OpenRouter's, before any call", async () => {
    const client = makeHttpStub();
    const svc = new LlmService(client);
    for (const path of ['embeddings', '//evil.example/x', '']) {
      await expect(svc.openrouter.request('POST', path, { passport: 'tok' })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    }
    expect(client.post).not.toHaveBeenCalled();
  });

  it('L11 streams a call whose body asks for a stream, as chat.completions.create does', async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n'));
        controller.close();
      },
    });
    const client = makeHttpStub({ postStream: vi.fn(async () => stream) as never });
    const events: unknown[] = [];
    const answer = await new LlmService(client).openrouter.request('POST', '/responses', { passport: 'tok', body: { model: 'm', input: 'x', stream: true } }) as AsyncIterable<unknown>;
    for await (const event of answer) events.push(event);
    expect(client.postStream).toHaveBeenCalledWith('/v1/llm/openrouter/responses', expect.objectContaining({ stream: true }), expect.any(Object));
    expect(client.post).not.toHaveBeenCalled();
    expect(events).toEqual([{ choices: [{ delta: { content: 'hi' } }] }]);
  });

  it('L11 requestBytes returns a file as its bytes and type, with the passport', async () => {
    const client = makeHttpStub();
    const file = await new LlmService(client).openrouter.requestBytes('GET', '/videos/gen-abc/content', options);
    expect(file).toEqual({ status: 200, contentType: 'audio/mpeg', bytes: new Uint8Array([1, 2, 3]) });
    expect(client.requestBytes).toHaveBeenCalledWith('GET', '/v1/llm/openrouter/videos/gen-abc/content', expect.objectContaining(headers));
    await new LlmService(client).openrouter.requestBytes('POST', '/audio/speech', { ...options, body: { model: 'm', input: 'hi' } });
    expect(client.requestBytes).toHaveBeenLastCalledWith('POST', '/v1/llm/openrouter/audio/speech', expect.objectContaining({ body: { model: 'm', input: 'hi' }, ...headers }));
  });
});

describe('HttpClient.requestBytes', () => {
  it('L12 sends the key, the headers and the body, and returns a file as bytes', async () => {
    const fetchMock = vi.fn(async () => new Response(new Uint8Array([9, 8, 7]), { status: 200, headers: { 'content-type': 'video/mp4' } }));
    vi.stubGlobal('fetch', fetchMock);
    try {
      const client = new HttpClient({ apiKey: 'sk_live_test', baseUrl: 'http://api.test' });
      const got = await client.requestBytes('POST', '/v1/llm/openrouter/audio/speech', { body: { model: 'm' }, headers: { 'X-Passport-Token': 'tok' } });
      expect(got).toEqual({ status: 200, contentType: 'video/mp4', bytes: new Uint8Array([9, 8, 7]) });
      const [url, init] = fetchMock.mock.calls[0] as unknown as [string, { method: string; headers: Record<string, string>; body: string }];
      expect(url).toBe('http://api.test/v1/llm/openrouter/audio/speech');
      expect(init.method).toBe('POST');
      expect(init.headers).toMatchObject({ Authorization: 'Bearer sk_live_test', 'X-Passport-Token': 'tok', 'Content-Type': 'application/json' });
      expect(init.body).toBe('{"model":"m"}');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("L12 throws the API's error for an answer that is not 2xx", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'MODEL_COST_CAP', message: 'The worst case is above your cap.' } }), { status: 422, headers: { 'content-type': 'application/json' } })));
    try {
      const client = new HttpClient({ apiKey: 'sk_live_test', baseUrl: 'http://api.test' });
      await expect(client.requestBytes('GET', '/v1/llm/openrouter/videos/gen-1/content')).rejects.toMatchObject({ code: 'MODEL_COST_CAP', status: 422 });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
