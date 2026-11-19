import { describe, expect, it } from 'vitest';
import {
  LLM_GATEWAY_MARKUP_BPS,
} from './index.js';
import { calculateLlmCost, costFromHeldCents, costFromProviderReported } from './llm-pricing.js';

// One price list, no markup: the same fee applies to every operator on every
// path, and none of it is a percentage on a provider's cost. Providers are
// passed through at cost.

describe('no markup on any provider cost', () => {
  it('the model gateway markup constant is zero', () => {
    expect(LLM_GATEWAY_MARKUP_BPS).toBe(0);
  });

  it('a model call is charged exactly what the provider reported', () => {
    const cost = costFromProviderReported(0.04);
    expect(cost.markup_microcents).toBe(0);
    expect(cost.total_cost_microcents).toBe(cost.provider_cost_microcents);
  });

  it('a call priced from the catalog carries no fee either', () => {
    const cost = calculateLlmCost(
      { input_cents_per_1m: 300, output_cents_per_1m: 1500 },
      10_000,
      5_000,
    );
    expect(cost.markup_microcents).toBe(0);
    expect(cost.total_cost_cents).toBe(cost.provider_cost_cents);
  });

  it('a hold splits into all provider cost and no fee', () => {
    const cost = costFromHeldCents(7);
    expect(cost.markup_microcents).toBe(0);
    expect(cost.provider_cost_microcents).toBe(cost.total_cost_microcents);
  });
});
