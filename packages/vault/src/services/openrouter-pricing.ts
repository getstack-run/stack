import type { LlmModelPricing } from '@stack/shared';

interface RedisLike {
  get(key: string): Promise<string | null>;
  setex(key: string, ttlSeconds: number, value: string): Promise<unknown>;
}

const CACHE_KEY = 'stack:openrouter-pricing:v2';
const CACHE_TTL_SECONDS = 24 * 60 * 60;
const OPENROUTER_MODELS_URL = 'https://openrouter.ai/api/v1/models';

interface OpenRouterPricing {
  prompt?: string;
  completion?: string;
  request?: string;
  image?: string;
  web_search?: string;
  internal_reasoning?: string;
  input_cache_read?: string;
  input_cache_write?: string;
}

interface OpenRouterModel {
  id: string;
  pricing?: OpenRouterPricing | OpenRouterPricing[];
}

interface OpenRouterModelsResponse {
  data?: OpenRouterModel[];
}

function usdPerTokenToCentsPer1M(value: string | undefined): number | null {
  if (typeof value !== 'string') return null;
  const usd = Number.parseFloat(value);
  if (!Number.isFinite(usd) || usd < 0) return null;
  return Math.ceil(usd * 100 * 1_000_000 * 1_000_000) / 1_000_000;
}

function usdPerUnitToCents(value: string | undefined): number | null {
  if (typeof value !== 'string') return null;
  const usd = Number.parseFloat(value);
  if (!Number.isFinite(usd) || usd < 0) return null;
  return Math.ceil(usd * 100 * 1_000_000) / 1_000_000;
}

function maximum(values: Array<number | null>): number | undefined {
  const present = values.filter((value): value is number => value !== null);
  return present.length > 0 ? Math.max(...present) : undefined;
}

/**
 * Resolve the maximum published OpenRouter price for one model.
 *
 * The model feed can contain multiple context tiers and non-token prices.
 * The resolver keeps the highest value for each field. This lets the caller
 * reserve a safe wallet amount before it sends a request.
 *
 * A cache or fetch failure returns null. Paid work must stop when STACK cannot
 * prove the maximum fee. The versioned cache key prevents older token-only
 * cache entries from bypassing the new fields.
 */
export class OpenRouterPricingResolver {
  constructor(private redis: RedisLike) {}

  async get(model: string): Promise<LlmModelPricing | null> {
    const cached = await this.redis.get(CACHE_KEY).catch(() => null);
    if (cached) {
      try {
        const parsed = JSON.parse(cached) as Record<string, LlmModelPricing>;
        return parsed[model] ?? null;
      } catch {
        // Fetch a fresh catalog when the cache is malformed.
      }
    }

    const fresh = await this.fetchAndCache().catch(() => null);
    return fresh?.[model] ?? null;
  }

  private async fetchAndCache(): Promise<Record<string, LlmModelPricing>> {
    const response = await fetch(OPENROUTER_MODELS_URL, {
      headers: { accept: 'application/json' },
    });
    if (!response.ok) {
      throw new Error(`OpenRouter /models fetch failed: ${response.status}`);
    }

    const body = (await response.json()) as OpenRouterModelsResponse;
    const dict: Record<string, LlmModelPricing> = {};
    for (const model of body.data ?? []) {
      const tiers = Array.isArray(model.pricing)
        ? model.pricing
        : model.pricing
          ? [model.pricing]
          : [];
      const input = maximum(tiers.map((tier) => usdPerTokenToCentsPer1M(tier.prompt)));
      const output = maximum(tiers.map((tier) => usdPerTokenToCentsPer1M(tier.completion)));
      if (input === undefined || output === undefined) continue;

      const cached = maximum(tiers.map((tier) => usdPerTokenToCentsPer1M(tier.input_cache_read)));
      const cacheWrite = maximum(tiers.map((tier) => usdPerTokenToCentsPer1M(tier.input_cache_write)));
      const reasoning = maximum(tiers.map((tier) => usdPerTokenToCentsPer1M(tier.internal_reasoning)));
      const request = maximum(tiers.map((tier) => usdPerUnitToCents(tier.request)));
      const image = maximum(tiers.map((tier) => usdPerUnitToCents(tier.image)));
      const webSearch = maximum(tiers.map((tier) => usdPerUnitToCents(tier.web_search)));

      dict[model.id] = {
        input_cents_per_1m: input,
        output_cents_per_1m: output,
        ...(cached !== undefined ? { cached_input_cents_per_1m: cached } : {}),
        ...(cacheWrite !== undefined ? { cache_write_cents_per_1m: cacheWrite } : {}),
        ...(reasoning !== undefined ? { internal_reasoning_cents_per_1m: reasoning } : {}),
        ...(request !== undefined ? { request_cents: request } : {}),
        ...(image !== undefined ? { image_cents: image } : {}),
        ...(webSearch !== undefined ? { web_search_cents: webSearch } : {}),
      };
    }

    await this.redis.setex(CACHE_KEY, CACHE_TTL_SECONDS, JSON.stringify(dict)).catch(() => {
      // A cache write failure only causes the next request to fetch again.
    });
    return dict;
  }
}
