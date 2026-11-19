// LLM pricing catalog.
//
// Per-provider × per-model input + output cents per 1M tokens. Used by
// LlmUsageService (packages/vault) to compute the cost of every LLM
// gateway call and debit the markup off the operator's wallet.
//
// Update policy:
//   - Anthropic + OpenAI prices live here and need a PR + constant edit
//     when the provider changes pricing. No DB migration required.
//   - OpenRouter aggregates hundreds of models and changes pricing
//     daily; their /api/v1/models endpoint is the source of truth and
//     gets fetched live + cached for 24h via OpenRouterPricingResolver
//     in packages/vault/src/services/openrouter-pricing.ts.
//
// Cost-paranoia defaults:
//   - On `model not in catalog` for anthropic/openai → return null
//     (caller records the llm_usage row with NULL cost columns + fires
//     an info-severity security_event rather than inventing prices).
//   - PRICING_FALLBACK is reserved for the OpenRouter resolver's
//     fetch-failure path (better to overestimate than under-charge).

/** Gateway markup applied on top of provider cost: none (0 bps). One price
 * list for every operator, providers at cost. Mirrors the sealed-compute markup for
 * sealed skill execution. Kept separate so the two markup paths (sealed
 * compute vs LLM gateway) can diverge later without coupling. */
export const LLM_GATEWAY_MARKUP_BPS = 0;

export interface LlmModelPricing {
  /** Provider's published input price per 1,000,000 tokens, in cents. */
  input_cents_per_1m: number;
  /** Provider's published output price per 1,000,000 tokens, in cents. */
  output_cents_per_1m: number;
  /**
   * Published price of a CACHE READ input token, per 1,000,000, in cents.
   *
   * Omitting this is not neutral: a cache read then bills at the full input
   * rate, which overstates the cost of an agent that re-sends the same corpus
   * every turn (almost entirely cache reads). Only set it from a published
   * figure; an unsourced guess here is worse than the overstatement, because
   * it is invisible.
   */
  cached_input_cents_per_1m?: number;
  /** Published cache-write price per 1,000,000 input tokens, in cents. */
  cache_write_cents_per_1m?: number;
  /** Published internal-reasoning price per 1,000,000 tokens, in cents. */
  internal_reasoning_cents_per_1m?: number;
  /** Published fixed price for one request, in cents. */
  request_cents?: number;
  /** Published fixed price for one image input, in cents. */
  image_cents?: number;
  /** Published fixed price for one web-search operation, in cents. */
  web_search_cents?: number;
}

/**
 * Cost is held in MICRO-CENTS (1 cent = 1,000,000) because whole cents cannot
 * express what these calls actually cost. A classifier call is ~0.003 cents;
 * rounding it to a cent — which is what `Math.ceil` used to do — overstates it
 * by 300x and makes every per-call pricing decision fiction. The integer-cent
 * fields remain for the dashboard and CLI, derived by rounding, and aggregates
 * must sum micro-cents and round ONCE at the end.
 */
export const MICROCENTS_PER_CENT = 1_000_000;

/** Anthropic — values from https://www.anthropic.com/pricing (Jan 2026). */
export const ANTHROPIC_PRICING: Readonly<Record<string, LlmModelPricing>> = {
  // Claude 4.x
  'claude-opus-4-7': { input_cents_per_1m: 1500, output_cents_per_1m: 7500 },
  'claude-opus-4-1': { input_cents_per_1m: 1500, output_cents_per_1m: 7500 },
  'claude-sonnet-4-6': { input_cents_per_1m: 300, output_cents_per_1m: 1500 },
  'claude-sonnet-4-5': { input_cents_per_1m: 300, output_cents_per_1m: 1500 },
  'claude-haiku-4-5-20251001': { input_cents_per_1m: 100, output_cents_per_1m: 500 },
  // Claude 3.x (legacy but still in active use)
  'claude-3-5-sonnet-20241022': { input_cents_per_1m: 300, output_cents_per_1m: 1500 },
  'claude-3-5-haiku-20241022': { input_cents_per_1m: 100, output_cents_per_1m: 500 },
  'claude-3-opus-20240229': { input_cents_per_1m: 1500, output_cents_per_1m: 7500 },
};

/** OpenAI — values from https://openai.com/pricing (Jan 2026). */
export const OPENAI_PRICING: Readonly<Record<string, LlmModelPricing>> = {
  'gpt-4o': { input_cents_per_1m: 250, output_cents_per_1m: 1000 },
  'gpt-4o-mini': { input_cents_per_1m: 15, output_cents_per_1m: 60 },
  'gpt-4-turbo': { input_cents_per_1m: 1000, output_cents_per_1m: 3000 },
  'gpt-3.5-turbo': { input_cents_per_1m: 50, output_cents_per_1m: 150 },
};

/** Conservative fallback for the OpenRouter resolver when the live
 * fetch fails. Intentionally over-priced (matches the most-expensive
 * mainstream model) so the operator gets a loud signal in the
 * dashboard rather than silently being under-charged. Never used by
 * the Anthropic/OpenAI lookups — those return null on miss. */
export const PRICING_FALLBACK: LlmModelPricing = {
  input_cents_per_1m: 1500,
  output_cents_per_1m: 7500,
};

export interface LlmCostBreakdown {
  /** Upstream provider cost in micro-cents. The authoritative figure. */
  provider_cost_microcents: number;
  /** STACK's gateway-service fee in micro-cents. */
  markup_microcents: number;
  /** provider + markup, micro-cents. */
  total_cost_microcents: number;
  /** Rounded view of provider_cost_microcents, for display only. */
  provider_cost_cents: number;
  /** Rounded view of markup_microcents, for display only. Do NOT debit
   * from this: a sub-cent markup rounds to zero here, and the caller is
   * expected to accrue micro-cents across calls instead. */
  markup_cents: number;
  /** Rounded view of total_cost_microcents, for display only. */
  total_cost_cents: number;
  /**
   * Where the provider figure came from.
   *   'provider_reported' — the provider told us what it charged. Exact,
   *      and already reflects cache discounts, batch rates and promos.
   *   'catalog' — we multiplied tokens by a list price. An estimate, and
   *      an over-estimate whenever caching is in play.
   */
  basis: 'provider_reported' | 'catalog';
}

const round = (n: number) => Math.round(n);

/** Derive the rounded cent view from a micro-cent breakdown. */
function withCents(
  provider_cost_microcents: number,
  basis: LlmCostBreakdown['basis'],
  markupBps: number,
): LlmCostBreakdown {
  const markup_microcents = round((provider_cost_microcents * markupBps) / 10_000);
  const total_cost_microcents = provider_cost_microcents + markup_microcents;
  return {
    provider_cost_microcents,
    markup_microcents,
    total_cost_microcents,
    provider_cost_cents: round(provider_cost_microcents / MICROCENTS_PER_CENT),
    markup_cents: round(markup_microcents / MICROCENTS_PER_CENT),
    total_cost_cents: round(total_cost_microcents / MICROCENTS_PER_CENT),
    basis,
  };
}

/**
 * Build a breakdown from the cost the PROVIDER reported, in USD.
 *
 * Always prefer this over `calculateLlmCost`. OpenRouter returns `usage.cost`
 * on every response and it is the amount actually billed — cache discounts,
 * provider routing and promotional rates included. Recomputing from list
 * price overstates it.
 */
export function costFromProviderReported(
  usd: number,
  markupBps: number = LLM_GATEWAY_MARKUP_BPS,
): LlmCostBreakdown {
  // USD → cents → micro-cents.
  return withCents(round(usd * 100 * MICROCENTS_PER_CENT), 'provider_reported', markupBps);
}

/**
 * Build a breakdown from tokens already used, priced at the catalogue's list price, in micro-dollars: for a call whose
 * provider never reported its cost. The basis is `catalog`.
 */
export function costFromCatalogueUsdMicros(
  usdMicros: number,
  markupBps: number = LLM_GATEWAY_MARKUP_BPS,
): LlmCostBreakdown {
  // A micro-dollar is 100 micro-cents.
  return withCents(round(usdMicros * 100), 'catalog', markupBps);
}

/**
 * Split a whole-cent wallet hold into provider cost and the STACK fee so the
 * two add up to exactly the hold. Used only when a STACK-key call could not be
 * priced from the provider's record after every retry: the hold is the
 * worst-case catalog price of the request, so the basis is `catalog`.
 */
export function costFromHeldCents(
  heldCents: number,
  markupBps: number = LLM_GATEWAY_MARKUP_BPS,
): LlmCostBreakdown {
  if (!Number.isInteger(heldCents) || heldCents <= 0) {
    throw new Error(`costFromHeldCents requires positive whole cents, got ${heldCents}`);
  }
  const total_cost_microcents = heldCents * MICROCENTS_PER_CENT;
  const provider_cost_microcents = Math.floor(
    (total_cost_microcents * 10_000) / (10_000 + markupBps),
  );
  const markup_microcents = total_cost_microcents - provider_cost_microcents;
  return {
    provider_cost_microcents,
    markup_microcents,
    total_cost_microcents,
    provider_cost_cents: round(provider_cost_microcents / MICROCENTS_PER_CENT),
    markup_cents: round(markup_microcents / MICROCENTS_PER_CENT),
    total_cost_cents: heldCents,
    basis: 'catalog',
  };
}

/**
 * ESTIMATE a cost breakdown from a pricing entry + token counts. Use only when
 * the provider reported no cost of its own — see `costFromProviderReported`.
 *
 * `cached_prompt_tokens` are billed at the model's published cache-read rate
 * when we have one. Ignoring them is what made this function overstate a
 * cache-heavy workload by 6x.
 *
 * Micro-cents make the per-1M divisor cancel exactly: a token count times a
 * cents-per-1M rate IS the micro-cent cost. No rounding until the cent view.
 */
export function calculateLlmCost(
  pricing: LlmModelPricing,
  prompt_tokens: number,
  completion_tokens: number,
  opts?: {
    cached_prompt_tokens?: number;
    request_count?: number;
    image_count?: number;
    web_search_count?: number;
    /** STACK's fee in basis points; the gateway markup unless the caller is the account path. */
    markup_bps?: number;
  },
): LlmCostBreakdown {
  const cached = Math.min(Math.max(opts?.cached_prompt_tokens ?? 0, 0), prompt_tokens);
  const fresh = prompt_tokens - cached;
  const cachedRate = pricing.cached_input_cents_per_1m ?? pricing.input_cents_per_1m;
  const provider =
    fresh * pricing.input_cents_per_1m +
    cached * cachedRate +
    completion_tokens * pricing.output_cents_per_1m +
    Math.max(0, opts?.request_count ?? 0) * (pricing.request_cents ?? 0) * MICROCENTS_PER_CENT +
    Math.max(0, opts?.image_count ?? 0) * (pricing.image_cents ?? 0) * MICROCENTS_PER_CENT +
    Math.max(0, opts?.web_search_count ?? 0) * (pricing.web_search_cents ?? 0) * MICROCENTS_PER_CENT;
  return withCents(round(provider), 'catalog', opts?.markup_bps ?? LLM_GATEWAY_MARKUP_BPS);
}
