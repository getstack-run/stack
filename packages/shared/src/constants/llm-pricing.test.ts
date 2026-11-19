import { describe, it, expect } from 'vitest';
import {
  ANTHROPIC_PRICING,
  OPENAI_PRICING,
  PRICING_FALLBACK,
  LLM_GATEWAY_MARKUP_BPS,
  MICROCENTS_PER_CENT,
  calculateLlmCost,
  costFromProviderReported,
  costFromHeldCents,
  costFromCatalogueUsdMicros,
} from './llm-pricing.js';

// The default fee is zero (no-markup.test.ts pins it); the arithmetic below is
// checked with an explicit 15% so a fee reintroduced later is still computed
// exactly, in whole micro-cents.
const FIFTEEN_PERCENT = 1500;

describe('calculateLlmCost — math', () => {
  it('C1 claude-opus-4-7 with (10000 prompt, 5000 completion)', () => {
    const pricing = ANTHROPIC_PRICING['claude-opus-4-7']!;
    const c = calculateLlmCost(pricing, 10000, 5000, { markup_bps: FIFTEEN_PERCENT });
    // 10000 * 1500/1e6 = 15c + 5000 * 7500/1e6 = 37.5c = 52.5c exactly.
    // held precisely rather than ceil'd up to 53.
    expect(c.provider_cost_microcents).toBe(52_500_000);
    expect(c.provider_cost_cents).toBe(53); // rounded VIEW only
    expect(c.markup_microcents).toBe(7_875_000); // 52.5 * 0.15
    expect(c.basis).toBe('catalog');
  });

  it('C2 gpt-4o-mini with (1M prompt, 0 completion)', () => {
    const pricing = OPENAI_PRICING['gpt-4o-mini']!;
    const c = calculateLlmCost(pricing, 1_000_000, 0, { markup_bps: FIFTEEN_PERCENT });
    expect(c.provider_cost_cents).toBe(15);
    expect(c.markup_microcents).toBe(2_250_000); // 2.25c, not ceil'd to 3
    expect(c.markup_cents).toBe(2);
    expect(c.total_cost_microcents).toBe(17_250_000);
  });

  it('C3 zero tokens → all zero', () => {
    const pricing = ANTHROPIC_PRICING['claude-sonnet-4-6']!;
    const c = calculateLlmCost(pricing, 0, 0);
    expect(c.provider_cost_microcents).toBe(0);
    expect(c.markup_cents).toBe(0);
    expect(c.total_cost_cents).toBe(0);
  });

  it('C4 PRICING_FALLBACK is the highest mainstream price (overestimate by design)', () => {
    const c = calculateLlmCost(PRICING_FALLBACK, 10000, 5000);
    expect(c.provider_cost_cents).toBe(53);
  });

  it('C5 a given markup is exactly that share of provider cost, held precisely', () => {
    for (const provider of [1, 7, 100, 999, 6666]) {
      const pricing = { input_cents_per_1m: provider, output_cents_per_1m: 0 };
      const c = calculateLlmCost(pricing, 1_000_000, 0, { markup_bps: FIFTEEN_PERCENT });
      expect(c.provider_cost_microcents).toBe(provider * MICROCENTS_PER_CENT);
      expect(c.markup_microcents).toBe(Math.round(provider * MICROCENTS_PER_CENT * 0.15));
    }
  });

  it('LLM_GATEWAY_MARKUP_BPS is zero (mirrors the sealed-compute markup): providers at cost', () => {
    expect(LLM_GATEWAY_MARKUP_BPS).toBe(0);
  });
});

// ── the two errors that made recorded cost several times the real bill ──
describe('calculateLlmCost — cost truth', () => {
  it('C7 a sub-cent call is NOT rounded up to a whole cent', () => {
    // A classifier call: 9 prompt tokens on a cheap model. The old ceil()
    // recorded this as a full cent, ~300x over, and billed a cent of markup on
    // top of it. Both figures now survive at their real size.
    const pricing = { input_cents_per_1m: 100, output_cents_per_1m: 500 };
    const c = calculateLlmCost(pricing, 9, 4);
    expect(c.provider_cost_microcents).toBe(9 * 100 + 4 * 500); // 2900 microcents
    expect(c.provider_cost_cents).toBe(0); // rounds to nothing, and should
    expect(c.provider_cost_microcents).toBeGreaterThan(0); // but is not nothing
  });

  it('C8 cached prompt tokens bill at the cache-read rate, not list price', () => {
    const pricing = {
      input_cents_per_1m: 300,
      output_cents_per_1m: 1500,
      cached_input_cents_per_1m: 30, // 10% of base, the published shape
    };
    const fresh = calculateLlmCost(pricing, 1_000_000, 0);
    const cached = calculateLlmCost(pricing, 1_000_000, 0, { cached_prompt_tokens: 900_000 });
    expect(fresh.provider_cost_microcents).toBe(300_000_000);
    // 100k fresh at 300 + 900k cached at 30.
    expect(cached.provider_cost_microcents).toBe(30_000_000 + 27_000_000);
    // This ratio IS the bug: a cache-heavy workload costed at list price.
    expect(fresh.provider_cost_microcents / cached.provider_cost_microcents).toBeCloseTo(5.26, 1);
  });

  it('C9 cached tokens are clamped to the prompt count and never go negative', () => {
    const pricing = {
      input_cents_per_1m: 300,
      output_cents_per_1m: 0,
      cached_input_cents_per_1m: 30,
    };
    const over = calculateLlmCost(pricing, 1000, 0, { cached_prompt_tokens: 999_999 });
    expect(over.provider_cost_microcents).toBe(1000 * 30); // all of it cached
    const negative = calculateLlmCost(pricing, 1000, 0, { cached_prompt_tokens: -5 });
    expect(negative.provider_cost_microcents).toBe(1000 * 300); // none of it
  });

  it('C10 a cache rate we do not have falls back to the full input rate', () => {
    // Never invent a price: with no published cache-read figure the estimate
    // stays high rather than guessing low.
    const pricing = { input_cents_per_1m: 300, output_cents_per_1m: 0 };
    const c = calculateLlmCost(pricing, 1_000_000, 0, { cached_prompt_tokens: 1_000_000 });
    expect(c.provider_cost_microcents).toBe(300_000_000);
  });

  it('C11 provider-reported cost is used verbatim and marked as such', () => {
    // The real shape of an OpenRouter response: usage.cost = 0.000029 USD.
    const c = costFromProviderReported(0.000029, FIFTEEN_PERCENT);
    expect(c.basis).toBe('provider_reported');
    expect(c.provider_cost_microcents).toBe(2900); // 0.0029c
    expect(c.markup_microcents).toBe(435); // 15%
    expect(c.provider_cost_cents).toBe(0);
  });

  it('C12 the provider-reported figure matches the bill; catalog math overstates it', () => {
    // 1,000,000 prompt + 10,000 completion tokens on a 300/1500 model: catalog
    // math gives $3.15 and the provider reports $0.60 (mostly cache reads).
    const sonnet = { input_cents_per_1m: 300, output_cents_per_1m: 1500 };
    const estimated = calculateLlmCost(sonnet, 1_000_000, 10_000);
    const estimatedUsd = estimated.provider_cost_microcents / MICROCENTS_PER_CENT / 100;
    const actual = costFromProviderReported(0.6);
    expect(estimatedUsd).toBeGreaterThan(3); // the number we recorded
    expect(actual.provider_cost_microcents / MICROCENTS_PER_CENT / 100).toBeCloseTo(0.6, 2);
    expect(estimatedUsd / 0.6).toBeGreaterThan(5); // the overstatement, ~5x
  });
});

describe('LLM pricing catalog integrity', () => {
  it('C6 every Anthropic entry has positive input + output rates', () => {
    for (const [model, p] of Object.entries(ANTHROPIC_PRICING)) {
      expect(p.input_cents_per_1m, `${model} input`).toBeGreaterThan(0);
      expect(p.output_cents_per_1m, `${model} output`).toBeGreaterThan(0);
    }
  });

  it('C6 every OpenAI entry has positive input + output rates', () => {
    for (const [model, p] of Object.entries(OPENAI_PRICING)) {
      expect(p.input_cents_per_1m, `${model} input`).toBeGreaterThan(0);
      expect(p.output_cents_per_1m, `${model} output`).toBeGreaterThan(0);
    }
  });

  it('C6 no duplicate model IDs across catalogs (collisions would shadow)', () => {
    const all = [...Object.keys(ANTHROPIC_PRICING), ...Object.keys(OPENAI_PRICING)];
    const unique = new Set(all);
    expect(unique.size).toBe(all.length);
  });

  it('C6 output rate >= input rate (standard provider pricing shape)', () => {
    for (const [model, p] of Object.entries({ ...ANTHROPIC_PRICING, ...OPENAI_PRICING })) {
      expect(p.output_cents_per_1m, `${model} out >= in`).toBeGreaterThanOrEqual(
        p.input_cents_per_1m,
      );
    }
  });

  it('C6 any cache-read rate is below the input rate it discounts', () => {
    for (const [model, p] of Object.entries({ ...ANTHROPIC_PRICING, ...OPENAI_PRICING })) {
      if (p.cached_input_cents_per_1m === undefined) continue;
      expect(p.cached_input_cents_per_1m, `${model} cached < input`).toBeLessThan(
        p.input_cents_per_1m,
      );
    }
  });
});

describe('costFromHeldCents', () => {
  it('splits a whole-cent hold into provider cost and a 15% fee, totalling the hold exactly', () => {
    const c = costFromHeldCents(115, FIFTEEN_PERCENT);
    expect(c.total_cost_microcents).toBe(115 * MICROCENTS_PER_CENT);
    expect(c.provider_cost_microcents).toBe(100 * MICROCENTS_PER_CENT);
    expect(c.markup_microcents).toBe(15 * MICROCENTS_PER_CENT);
    expect(c.basis).toBe('catalog');
  });

  it('never rounds the total away from the held amount', () => {
    for (const cents of [1, 2, 7, 33, 999, 123_457]) {
      const c = costFromHeldCents(cents);
      expect(c.provider_cost_microcents + c.markup_microcents).toBe(cents * MICROCENTS_PER_CENT);
      expect(c.markup_microcents).toBeGreaterThanOrEqual(0);
    }
  });

  it('refuses a non-positive or fractional hold', () => {
    expect(() => costFromHeldCents(0)).toThrow();
    expect(() => costFromHeldCents(1.5)).toThrow();
  });
});

describe('costFromCatalogueUsdMicros', () => {
  it('turns catalogue micro-dollars into micro-cents with the catalog basis and no fee at the default markup', () => {
    // 36,000 micro-dollars = $0.036 = 3.6 cents = 3,600,000 micro-cents.
    expect(costFromCatalogueUsdMicros(36_000)).toMatchObject({
      provider_cost_microcents: 3_600_000,
      markup_microcents: LLM_GATEWAY_MARKUP_BPS === 0 ? 0 : expect.any(Number),
      total_cost_cents: 4,
      basis: 'catalog',
    });
  });

  it('adds an explicit markup exactly', () => {
    expect(costFromCatalogueUsdMicros(10_000, FIFTEEN_PERCENT)).toMatchObject({
      provider_cost_microcents: 1_000_000,
      markup_microcents: 150_000,
      total_cost_microcents: 1_150_000,
      basis: 'catalog',
    });
  });
});
