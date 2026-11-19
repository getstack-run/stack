import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OpenRouterPricingResolver } from './openrouter-pricing.js';

let fetchSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function fakeRedis(initial: string | null = null) {
  let stored = initial;
  return {
    get: vi.fn(async () => stored),
    setex: vi.fn(async (_key: string, _ttl: number, value: string) => {
      stored = value;
    }),
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('OpenRouterPricingResolver', () => {
  it('fetches and caches a model price', async () => {
    const redis = fakeRedis();
    fetchSpy.mockResolvedValue(jsonResponse(200, {
      data: [{
        id: 'anthropic/claude',
        pricing: { prompt: '0.000003', completion: '0.000015' },
      }],
    }));

    const result = await new OpenRouterPricingResolver(redis as never).get('anthropic/claude');
    expect(result).toEqual({ input_cents_per_1m: 300, output_cents_per_1m: 1500 });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(redis.setex).toHaveBeenCalledWith(
      'stack:openrouter-pricing:v2',
      86_400,
      expect.any(String),
    );
  });

  it('uses a cached model price', async () => {
    const redis = fakeRedis(JSON.stringify({
      'meta/model': { input_cents_per_1m: 60, output_cents_per_1m: 90 },
    }));

    const result = await new OpenRouterPricingResolver(redis as never).get('meta/model');
    expect(result).toEqual({ input_cents_per_1m: 60, output_cents_per_1m: 90 });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns null when the catalog endpoint fails', async () => {
    fetchSpy.mockResolvedValue(new Response('upstream down', { status: 503 }));
    const result = await new OpenRouterPricingResolver(fakeRedis() as never).get('any/model');
    expect(result).toBeNull();
  });

  it('returns null when the catalog request fails', async () => {
    fetchSpy.mockRejectedValue(new Error('ECONNREFUSED'));
    const result = await new OpenRouterPricingResolver(fakeRedis() as never).get('any/model');
    expect(result).toBeNull();
  });

  it('returns null when the catalog does not contain the model', async () => {
    fetchSpy.mockResolvedValue(jsonResponse(200, {
      data: [{
        id: 'known/model',
        pricing: { prompt: '0.000001', completion: '0.000002' },
      }],
    }));

    const result = await new OpenRouterPricingResolver(fakeRedis() as never).get('other/model');
    expect(result).toBeNull();
  });

  it('keeps the highest tier and every published cost field', async () => {
    fetchSpy.mockResolvedValue(jsonResponse(200, {
      data: [{
        id: 'priced/model',
        pricing: [
          {
            prompt: '0.000001',
            completion: '0.000002',
            request: '0.01',
            image: '0.02',
            web_search: '0.003',
            input_cache_read: '0.0000002',
            input_cache_write: '0.0000015',
            internal_reasoning: '0.000003',
          },
          { prompt: '0.000004', completion: '0.000005' },
        ],
      }],
    }));

    const result = await new OpenRouterPricingResolver(fakeRedis() as never).get('priced/model');
    expect(result).toEqual({
      input_cents_per_1m: 400,
      output_cents_per_1m: 500,
      cached_input_cents_per_1m: 20,
      cache_write_cents_per_1m: 150,
      internal_reasoning_cents_per_1m: 300,
      request_cents: 1,
      image_cents: 2,
      web_search_cents: 0.3,
    });
  });
});
