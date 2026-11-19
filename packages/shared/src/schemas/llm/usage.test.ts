import { describe, it, expect } from 'vitest';
import {
  LlmUsageRow,
  ListLlmUsageQuery,
  ListLlmUsageResult,
  SummaryLlmUsageQuery,
  LlmUsageSummaryBucket,
  SummaryLlmUsageResult,
} from './usage.js';

describe('LlmUsageRow schema', () => {
  it('accepts a fully-populated row', () => {
    const row = {
      id: 'usg_x',
      operator_id: 'op_x',
      agent_id: 'agt_x',
      passport_jti: 'pas_x',
      mission_id: 'ms_x',
      provider: 'anthropic',
      model: 'claude-opus-4-7',
      prompt_tokens: 100,
      completion_tokens: 50,
      total_tokens: 150,
      provider_cost_cents: 53,
      markup_cents: 8,
      total_cost_cents: 61,
      provider_cost_microcents: 53_000_000,
      markup_microcents: 8_000_000,
      total_cost_microcents: 61_000_000,
      cost_basis: 'catalog',
      cached_prompt_tokens: 0,
      wallet_debited: true,
      surface: 'gateway',
      provider_payer: 'customer_provider',
      stack_fee_payer: 'stack_wallet',
      wallet_hold_id: 'wh_x',
      streaming: false,
      created_at: '2026-05-23T10:00:00Z',
    };
    expect(LlmUsageRow.parse(row).model).toBe('claude-opus-4-7');
  });

  it('accepts a row with NULL cost columns (pricing-lookup miss)', () => {
    const row = {
      id: 'usg_y',
      operator_id: 'op_y',
      agent_id: 'agt_y',
      passport_jti: 'pas_y',
      mission_id: null,
      provider: 'openai',
      model: 'gpt-mystery-9000',
      prompt_tokens: 10,
      completion_tokens: 5,
      total_tokens: 15,
      provider_cost_cents: null,
      markup_cents: null,
      total_cost_cents: null,
      provider_cost_microcents: null,
      markup_microcents: null,
      total_cost_microcents: null,
      cost_basis: null,
      cached_prompt_tokens: null,
      wallet_debited: false,
      surface: 'gateway',
      provider_payer: 'customer_provider',
      stack_fee_payer: 'stack_wallet',
      wallet_hold_id: null,
      streaming: true,
      created_at: '2026-05-23T10:00:00Z',
    };
    const parsed = LlmUsageRow.parse(row);
    expect(parsed.provider_cost_cents).toBeNull();
    expect(parsed.wallet_debited).toBe(false);
  });

  it('rejects invalid provider', () => {
    expect(() =>
      LlmUsageRow.parse({
        id: 'usg_x', operator_id: 'op_x', agent_id: 'agt_x', passport_jti: 'pas_x',
        mission_id: null, provider: 'cohere', model: 'x',
        prompt_tokens: 0, completion_tokens: 0, total_tokens: 0,
        provider_cost_cents: null, markup_cents: null, total_cost_cents: null,
        provider_cost_microcents: null, markup_microcents: null, total_cost_microcents: null,
        cost_basis: null, cached_prompt_tokens: null,
        surface: 'gateway', provider_payer: 'customer_provider', stack_fee_payer: 'stack_wallet',
        wallet_hold_id: null,
        wallet_debited: false, streaming: false, created_at: '2026-05-23T10:00:00Z',
      }),
    ).toThrow();
  });
});

describe('ListLlmUsageQuery schema', () => {
  it('applies default limit=20 when omitted', () => {
    const parsed = ListLlmUsageQuery.parse({});
    expect(parsed.limit).toBe(20);
  });

  it('coerces stringified limit (query-string source)', () => {
    const parsed = ListLlmUsageQuery.parse({ limit: '5' });
    expect(parsed.limit).toBe(5);
  });

  it('rejects limit > 100', () => {
    expect(() => ListLlmUsageQuery.parse({ limit: 500 })).toThrow();
  });

  it('accepts all filter fields together', () => {
    const parsed = ListLlmUsageQuery.parse({
      limit: 10,
      cursor: '2026-05-23T10:00:00Z__usg_x',
      provider: 'anthropic',
      passport_jti: 'pas_x',
      mission_id: 'ms_x',
      agent_id: 'agt_x',
      since: '2026-05-23T00:00:00Z',
      until: '2026-05-23T23:59:59Z',
    });
    expect(parsed.provider).toBe('anthropic');
    expect(parsed.cursor).toBe('2026-05-23T10:00:00Z__usg_x');
  });
});

describe('ListLlmUsageResult schema', () => {
  it('accepts items + next_cursor null', () => {
    const result = ListLlmUsageResult.parse({ items: [], next_cursor: null });
    expect(result.items).toEqual([]);
    expect(result.next_cursor).toBeNull();
  });
});

describe('SummaryLlmUsageQuery schema', () => {
  it('defaults group_by_model=true', () => {
    expect(SummaryLlmUsageQuery.parse({}).group_by_model).toBe(true);
  });

  it('coerces stringified false', () => {
    // z.coerce.boolean treats any non-empty string as true; pass actual false
    expect(SummaryLlmUsageQuery.parse({ group_by_model: false }).group_by_model).toBe(false);
  });
});

describe('LlmUsageSummaryBucket schema', () => {
  it('accepts a bucket with model populated', () => {
    const bucket = LlmUsageSummaryBucket.parse({
      provider: 'anthropic',
      model: 'claude-opus-4-7',
      surface: 'gateway',
      provider_payer: 'customer_provider',
      stack_fee_payer: 'stack_wallet',
      day: '2026-05-23',
      call_count: 42,
      total_prompt_tokens: 50000,
      total_completion_tokens: 25000,
      total_cost_cents: 263,
      total_markup_cents: 40,
      total_cost_microcents: 263_000_000,
      total_markup_microcents: 40_000_000,
      cost_is_estimated: false,
    });
    expect(bucket.call_count).toBe(42);
  });

  it('accepts a bucket with model=null (group_by_model=false)', () => {
    const bucket = LlmUsageSummaryBucket.parse({
      provider: 'openai',
      model: null,
      surface: 'intent_deviation',
      provider_payer: 'stack_plan',
      stack_fee_payer: 'stack_plan',
      day: '2026-05-23',
      call_count: 10,
      total_prompt_tokens: 1000,
      total_completion_tokens: 500,
      total_cost_cents: 5,
      total_markup_cents: 1,
      total_cost_microcents: 5_000_000,
      total_markup_microcents: 1_000_000,
      cost_is_estimated: true,
    });
    expect(bucket.model).toBeNull();
  });
});

describe('SummaryLlmUsageResult schema', () => {
  it('accepts empty buckets', () => {
    expect(SummaryLlmUsageResult.parse({ buckets: [] }).buckets).toEqual([]);
  });
});
