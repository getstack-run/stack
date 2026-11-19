import { describe, it, expect } from 'vitest';
import { BehavioralGenomeClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

/**
 * Coverage for the BehavioralGenomeClaim payload schema. Tests assert
 * wire-shape acceptance for the minimum-valid + maximally-populated +
 * cold-start cases, plus rejection of malformed shapes. Pins the
 * schema in PASSPORT_CLAIM_SCHEMAS so ClaimRegistryService can
 * dispatch by claim_type.
 *
 * Per ADR additive-only versioning rule: these tests pin the v1 wire
 * shape — any breaking change fails CI loudly. The 5 LLM-token fields
 * carry defaults so 5.2.5 can additively light up the producer without
 * a schema-version bump.
 */

const zeroes24 = Array.from({ length: 24 }, () => 0);

const minimalValid = {
  type: 'behavioral_genome' as const,
  passport_jti: 'jti_abc123',
  window_start_ms: 1_726_000_000_000,
  window_end_ms: 1_726_086_400_000,
  call_count: 42,
  mean_latency_ms: 120,
  stddev_latency_ms: 40,
  mean_request_bytes: 512,
  stddev_request_bytes: 128,
  mean_response_bytes: 2048,
  stddev_response_bytes: 600,
  mean_request_entropy: 5.1,
  stddev_request_entropy: 0.6,
  mean_response_entropy: 4.2,
  stddev_response_entropy: 0.8,
  error_rate: 0.02,
  time_of_day_histogram: zeroes24,
  prior_genome_ref: null,
};

const coldStart = {
  type: 'behavioral_genome' as const,
  passport_jti: 'jti_new_passport',
  window_start_ms: 1_726_000_000_000,
  window_end_ms: 1_726_086_400_000,
  call_count: 0,
  mean_latency_ms: 0,
  stddev_latency_ms: 0,
  mean_request_bytes: 0,
  stddev_request_bytes: 0,
  mean_response_bytes: 0,
  stddev_response_bytes: 0,
  mean_request_entropy: 0,
  stddev_request_entropy: 0,
  mean_response_entropy: 0,
  stddev_response_entropy: 0,
  error_rate: 0,
  time_of_day_histogram: zeroes24,
  prior_genome_ref: null,
};

const fullyPopulated = {
  ...minimalValid,
  scope_histogram: { stripe: 8, slack: 30, github: 4 },
  time_of_day_histogram: [
    0, 0, 0, 0, 0, 0, 0, 1, 3, 8, 12, 6,
    4, 2, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0,
  ],
  mean_prompt_tokens: 1200,
  stddev_prompt_tokens: 350,
  mean_completion_tokens: 480,
  stddev_completion_tokens: 110,
  model_distribution: {
    'anthropic/claude-sonnet-4-6': 28,
    'anthropic/claude-haiku-4-5-20251001': 14,
  },
  prior_genome_ref: 'pc_prev_genome_xyz',
};

describe('BehavioralGenomeClaim', () => {
  it('accepts a minimal valid payload (defaults fill in tokens + scope)', () => {
    expect(() => BehavioralGenomeClaim.parse(minimalValid)).not.toThrow();
  });

  it('accepts a fully-populated payload with prior_genome_ref set', () => {
    expect(() => BehavioralGenomeClaim.parse(fullyPopulated)).not.toThrow();
  });

  it('token fields + model_distribution round-trip with non-default values', () => {
    const parsed = BehavioralGenomeClaim.parse(fullyPopulated);
    expect(parsed.mean_prompt_tokens).toBe(1200);
    expect(parsed.stddev_prompt_tokens).toBe(350);
    expect(parsed.mean_completion_tokens).toBe(480);
    expect(parsed.stddev_completion_tokens).toBe(110);
    expect(parsed.model_distribution).toEqual({
      'anthropic/claude-sonnet-4-6': 28,
      'anthropic/claude-haiku-4-5-20251001': 14,
    });
  });

  it('accepts cold-start shape: call_count=0, all zeros, no prior', () => {
    expect(() => BehavioralGenomeClaim.parse(coldStart)).not.toThrow();
  });

  it('applies defaults for omitted scope_histogram + token fields + model_distribution', () => {
    const parsed = BehavioralGenomeClaim.parse(minimalValid);
    expect(parsed.scope_histogram).toEqual({});
    expect(parsed.mean_prompt_tokens).toBe(0);
    expect(parsed.stddev_prompt_tokens).toBe(0);
    expect(parsed.mean_completion_tokens).toBe(0);
    expect(parsed.stddev_completion_tokens).toBe(0);
    expect(parsed.model_distribution).toEqual({});
  });

  it('rejects time_of_day_histogram of wrong length', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, time_of_day_histogram: [] }),
    ).toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, time_of_day_histogram: zeroes24.slice(0, 23) }),
    ).toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, time_of_day_histogram: [...zeroes24, 0] }),
    ).toThrow();
  });

  it('rejects negative time_of_day bucket counts', () => {
    const bad = [...zeroes24];
    bad[10] = -1;
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, time_of_day_histogram: bad }),
    ).toThrow();
  });

  it('rejects non-integer call_count', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, call_count: 3.5 }),
    ).toThrow();
  });

  it('rejects negative metrics', () => {
    const negativeFields = [
      'call_count',
      'mean_latency_ms',
      'stddev_latency_ms',
      'mean_request_bytes',
      'stddev_request_bytes',
      'mean_response_bytes',
      'stddev_response_bytes',
      'mean_request_entropy',
      'stddev_request_entropy',
      'mean_response_entropy',
      'stddev_response_entropy',
    ] as const;
    for (const field of negativeFields) {
      expect(() =>
        BehavioralGenomeClaim.parse({ ...minimalValid, [field]: -1 }),
      ).toThrow();
    }
  });

  it('rejects negative token metrics', () => {
    const tokenFields = [
      'mean_prompt_tokens',
      'stddev_prompt_tokens',
      'mean_completion_tokens',
      'stddev_completion_tokens',
    ] as const;
    for (const field of tokenFields) {
      expect(() =>
        BehavioralGenomeClaim.parse({ ...minimalValid, [field]: -1 }),
      ).toThrow();
    }
  });

  it('rejects error_rate outside [0, 1]', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, error_rate: -0.01 }),
    ).toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, error_rate: 1.01 }),
    ).toThrow();
  });

  it('accepts error_rate at the boundaries', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, error_rate: 0 }),
    ).not.toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, error_rate: 1 }),
    ).not.toThrow();
  });

  it('rejects window_end_ms <= window_start_ms', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({
        ...minimalValid,
        window_start_ms: 1_726_000_000_000,
        window_end_ms: 1_726_000_000_000,
      }),
    ).toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({
        ...minimalValid,
        window_start_ms: 1_726_000_000_000,
        window_end_ms: 1_725_999_999_999,
      }),
    ).toThrow();
  });

  it('rejects empty passport_jti', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, passport_jti: '' }),
    ).toThrow();
  });

  it('rejects malformed prior_genome_ref', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, prior_genome_ref: 'pc_' }),
    ).toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, prior_genome_ref: 'ms_abc' }),
    ).toThrow();
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, prior_genome_ref: '' }),
    ).toThrow();
  });

  it('accepts null prior_genome_ref (cold start)', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, prior_genome_ref: null }),
    ).not.toThrow();
  });

  it('accepts well-formed prior_genome_ref', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({ ...minimalValid, prior_genome_ref: 'pc_abc_123-xyz' }),
    ).not.toThrow();
  });

  it('rejects scope_histogram with negative count', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({
        ...minimalValid,
        scope_histogram: { stripe: -1 },
      }),
    ).toThrow();
  });

  it('rejects scope_histogram with non-integer count', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({
        ...minimalValid,
        scope_histogram: { stripe: 2.5 },
      }),
    ).toThrow();
  });

  it('rejects model_distribution with negative count', () => {
    expect(() =>
      BehavioralGenomeClaim.parse({
        ...minimalValid,
        model_distribution: { 'anthropic/claude-sonnet-4-6': -1 },
      }),
    ).toThrow();
  });

  it('rejects missing required fields', () => {
    const requiredFields = [
      'type',
      'passport_jti',
      'window_start_ms',
      'window_end_ms',
      'call_count',
      'mean_latency_ms',
      'stddev_latency_ms',
      'mean_request_bytes',
      'stddev_request_bytes',
      'mean_response_bytes',
      'stddev_response_bytes',
      'mean_request_entropy',
      'stddev_request_entropy',
      'mean_response_entropy',
      'stddev_response_entropy',
      'error_rate',
      'time_of_day_histogram',
      'prior_genome_ref',
    ] as const;
    for (const field of requiredFields) {
      const stripped = { ...minimalValid } as Record<string, unknown>;
      delete stripped[field];
      expect(() => BehavioralGenomeClaim.parse(stripped)).toThrow();
    }
  });
});

describe('PASSPORT_CLAIM_SCHEMAS dispatch', () => {
  it('registers behavioral_genome claim type', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.behavioral_genome).toBe(BehavioralGenomeClaim);
  });

  it('PASSPORT_CLAIM_SCHEMAS.behavioral_genome accepts a minimal valid payload', () => {
    expect(() =>
      PASSPORT_CLAIM_SCHEMAS.behavioral_genome.parse(minimalValid),
    ).not.toThrow();
  });
});
