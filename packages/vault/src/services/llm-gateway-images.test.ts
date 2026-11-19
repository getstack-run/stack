import { describe, expect, it, vi } from 'vitest';
import { LLM_IMAGE_ENDPOINTS, LlmGatewayService } from './llm-gateway-service.js';

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

describe('LlmGatewayService.forwardImages', () => {
  const gateway = new LlmGatewayService();

  it('sends the key in the provider\'s own header to a fixed host, and returns the answer as it came', async () => {
    const fetchMock = vi.fn(async (_url: string, _init: RequestInit) => json(200, { data: [{ b64_json: 'AAAA' }] }));
    const result = await gateway.forwardImages({ provider: 'openai', apiKey: 'sk-own', body: { model: 'gpt-image-1', prompt: 'a cat' }, fetch: fetchMock as never });
    expect(result).toEqual({ status: 200, body: { data: [{ b64_json: 'AAAA' }] } });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://api.openai.com/v1/images/generations');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['authorization']).toBe('Bearer sk-own');
    expect(JSON.parse(init.body as string)).toEqual({ model: 'gpt-image-1', prompt: 'a cat' });
    // Nothing follows a redirect with the key.
    expect(init.redirect).toBe('error');
    expect(JSON.stringify(result)).not.toContain('sk-own');
  });

  it('has an images endpoint for OpenAI only, on a fixed https host', () => {
    expect(Object.keys(LLM_IMAGE_ENDPOINTS)).toEqual(['openai']);
    for (const { url } of Object.values(LLM_IMAGE_ENDPOINTS)) expect(new URL(url).protocol).toBe('https:');
  });

  it('hands a provider\'s refusal back with its status, never as a success', async () => {
    const fetchMock = vi.fn(async () => json(401, { error: { message: 'bad key' } }));
    expect(await gateway.forwardImages({ provider: 'openai', apiKey: 'k', body: {}, fetch: fetchMock as never })).toEqual({
      status: 401, body: { error: { message: 'bad key' } },
    });
  });

  it('turns an answer that is not JSON, or is larger than it will read, into a refusal with no provider text', async () => {
    const notJson = vi.fn(async () => new Response('<html>oops</html>', { status: 200 }));
    expect(await gateway.forwardImages({ provider: 'openai', apiKey: 'k', body: {}, fetch: notJson as never })).toEqual({
      status: 200, body: { error: 'invalid_json_response' },
    });
    const tooBig = vi.fn(async () => json(200, {}, { 'content-length': String(41 * 1024 * 1024) }));
    expect(await gateway.forwardImages({ provider: 'openai', apiKey: 'k', body: {}, fetch: tooBig as never })).toEqual({
      status: 502, body: { error: 'response_too_large' },
    });
  });

  it('lets a request that cannot be sent throw, so the route can say nothing was sent', async () => {
    const down = vi.fn(async () => { throw new Error('ECONNREFUSED'); });
    await expect(gateway.forwardImages({ provider: 'openai', apiKey: 'k', body: {}, fetch: down as never })).rejects.toThrow('ECONNREFUSED');
  });
});
