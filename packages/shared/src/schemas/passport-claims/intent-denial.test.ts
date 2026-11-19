import { describe, it, expect } from 'vitest';
import { IntentDenialClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

const sampleIntent = {
  type: 'intent_claim' as const,
  intent_type: 'http_call' as const,
  agent_id: 'ag_test1',
  named_intent: 'stripe:charges:create',
  target: 'api.stripe.com',
  action: 'POST /v1/charges',
  parameters: { amount: 10000, currency: 'usd' },
  estimated_cost: { wallet_cents: 5, tokens: null, gas_gwei: null },
  accountability: 'standard' as const,
  reason: null,
  requires: [],
  user_subject: null,
  mission_ref: null,
  submitted_at: 1_726_000_000_000,
};

const baseValid = {
  type: 'intent_denial' as const,
  attempted_intent: sampleIntent,
  denial_reason: 'constraint_violation' as const,
  message: 'amount exceeds per-action limit of $50',
  parameters_hash: 'a'.repeat(64),
  retry_count: 1,
  metadata: {},
  denied_at: 1_726_000_000_000,
};

describe('IntentDenialClaim', () => {
  it('accepts a full valid payload', () => {
    expect(() => IntentDenialClaim.parse(baseValid)).not.toThrow();
  });

  it('accepts each denial_reason value', () => {
    for (const r of [
      'constraint_violation',
      'scope_mismatch',
      'accountability_monotonicity',
      'detector_block',
      'tier_limit',
      'simulation_failure',
      'requires_unmet',
    ] as const) {
      expect(() =>
        IntentDenialClaim.parse({ ...baseValid, denial_reason: r }),
      ).not.toThrow();
    }
  });

  it('accepts a detector_block denial with denying_detector_key', () => {
    expect(() =>
      IntentDenialClaim.parse({
        ...baseValid,
        denial_reason: 'detector_block',
        denying_detector_key: 'prompt_injection_llm',
      }),
    ).not.toThrow();
  });

  it('accepts denial without denying_detector_key (non-detector denial)', () => {
    expect(() =>
      IntentDenialClaim.parse({
        ...baseValid,
        denial_reason: 'scope_mismatch',
      }),
    ).not.toThrow();
  });

  it('defaults retry_count to 1 when omitted', () => {
    const { retry_count: _omit, ...rest } = baseValid;
    const parsed = IntentDenialClaim.parse(rest);
    expect(parsed.retry_count).toBe(1);
  });

  it('defaults metadata to empty object', () => {
    const { metadata: _omit, ...rest } = baseValid;
    const parsed = IntentDenialClaim.parse(rest);
    expect(parsed.metadata).toEqual({});
  });

  it('accepts higher retry_count values', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, retry_count: 47 }),
    ).not.toThrow();
  });

  it('rejects retry_count of 0 or negative', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, retry_count: 0 }),
    ).toThrow();
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, retry_count: -1 }),
    ).toThrow();
  });

  it('rejects unknown denial_reason', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, denial_reason: 'rate_limit' as never }),
    ).toThrow();
  });

  it('rejects malformed parameters_hash (not hex / wrong length)', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, parameters_hash: 'not-hex' }),
    ).toThrow();
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, parameters_hash: 'a'.repeat(63) }),
    ).toThrow();
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, parameters_hash: 'A'.repeat(64) }),
    ).toThrow();
  });

  it('rejects malformed denying_detector_key', () => {
    expect(() =>
      IntentDenialClaim.parse({
        ...baseValid,
        denial_reason: 'detector_block',
        denying_detector_key: 'PromptInjection',
      }),
    ).toThrow();
  });

  it('rejects message exceeding 1024 chars', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, message: 'x'.repeat(1025) }),
    ).toThrow();
  });

  it('rejects malformed attempted_intent', () => {
    expect(() =>
      IntentDenialClaim.parse({
        ...baseValid,
        attempted_intent: { ...sampleIntent, agent_id: 'not-an-agent' },
      }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.intent_denial).toBe(IntentDenialClaim);
  });

  // mission_ref retrofit
  it('accepts mission_ref as a valid mission_id', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, mission_ref: 'ms_run_42' }),
    ).not.toThrow();
  });

  it('accepts mission_ref omitted (additive nullable optional)', () => {
    expect(() => IntentDenialClaim.parse({ ...baseValid })).not.toThrow();
  });

  it('rejects mission_ref with wrong prefix', () => {
    expect(() =>
      IntentDenialClaim.parse({ ...baseValid, mission_ref: 'pc_old_shape' }),
    ).toThrow();
  });
});
