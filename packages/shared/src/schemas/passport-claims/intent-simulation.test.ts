import { describe, it, expect } from 'vitest';
import { IntentSimulationClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

const baseValid = {
  type: 'intent_simulation' as const,
  intent_claim_ref: 'pc_abc123',
  allowed: true,
  denial_reasons: [],
  simulated_cost: {
    wallet_cents: 5,
    tokens: null,
    gas_gwei: null,
  },
  predicted_detector_fires: [],
  simulated_at: 1_726_000_000_000,
};

describe('IntentSimulationClaim', () => {
  it('accepts a valid allowed simulation', () => {
    expect(() => IntentSimulationClaim.parse(baseValid)).not.toThrow();
  });

  it('accepts a denied simulation with reasons', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        allowed: false,
        denial_reasons: ['constraint_violation', 'scope_mismatch'],
      }),
    ).not.toThrow();
  });

  it('accepts a simulation without intent_claim_ref (hypothetical dry-run)', () => {
    const { intent_claim_ref: _omit, ...rest } = baseValid;
    expect(() => IntentSimulationClaim.parse(rest)).not.toThrow();
  });

  it('accepts predicted_detector_fires', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        predicted_detector_fires: [
          { detector_key: 'scope_drift', severity: 'medium' },
          { detector_key: 'output_injection', severity: 'high' },
        ],
      }),
    ).not.toThrow();
  });

  it('accepts a projected_http result for http_call simulations', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        projected_http: {
          status_code: 200,
          headers_summary: { 'content-type': 'application/json' },
        },
      }),
    ).not.toThrow();
  });

  it('defaults denial_reasons + predicted_detector_fires to empty arrays', () => {
    const minimal = {
      type: 'intent_simulation',
      allowed: true,
      simulated_cost: { wallet_cents: null, tokens: null, gas_gwei: null },
      simulated_at: 1_726_000_000_000,
    };
    const parsed = IntentSimulationClaim.parse(minimal);
    expect(parsed.denial_reasons).toEqual([]);
    expect(parsed.predicted_detector_fires).toEqual([]);
  });

  it('rejects unknown denial_reason in array', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        allowed: false,
        denial_reasons: ['rate_limit' as never],
      }),
    ).toThrow();
  });

  it('rejects malformed detector_key in predicted fires', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        predicted_detector_fires: [
          { detector_key: 'BadKey', severity: 'medium' },
        ],
      }),
    ).toThrow();
  });

  it('rejects malformed intent_claim_ref', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        intent_claim_ref: 'not-a-claim',
      }),
    ).toThrow();
  });

  it('rejects negative simulated_cost.wallet_cents', () => {
    expect(() =>
      IntentSimulationClaim.parse({
        ...baseValid,
        simulated_cost: { wallet_cents: -1, tokens: null, gas_gwei: null },
      }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.intent_simulation).toBe(IntentSimulationClaim);
  });

  // mission_ref retrofit
  it('accepts mission_ref as a valid mission_id', () => {
    expect(() =>
      IntentSimulationClaim.parse({ ...baseValid, mission_ref: 'ms_run_42' }),
    ).not.toThrow();
  });

  it('accepts mission_ref omitted (additive nullable optional)', () => {
    expect(() => IntentSimulationClaim.parse({ ...baseValid })).not.toThrow();
  });

  it('rejects mission_ref with wrong prefix', () => {
    expect(() =>
      IntentSimulationClaim.parse({ ...baseValid, mission_ref: 'pc_old_shape' }),
    ).toThrow();
  });
});
