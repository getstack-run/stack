import { describe, it, expect } from 'vitest';
import { MissionClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

/**
 * Coverage for the MissionClaim payload schema. Tests assert wire-shape
 * acceptance for the minimum-valid + maximally-populated cases, plus
 * rejection of malformed shapes. Pins the schema in PASSPORT_CLAIM_SCHEMAS
 * so ClaimRegistryService can dispatch by claim_type.
 *
 * Per ADR additive-only versioning rule: these tests pin the v1 wire
 * shape — any breaking change fails CI loudly.
 */

const minimalValid = {
  type: 'mission' as const,
  mission_id: 'ms_RefundReq42xY',
  operator_id: 'op_acme',
  intent_summary: 'process customer refund #ord_123',
  started_at: 1_726_000_000_000,
  expires_at: 1_726_000_900_000,
};

const fullyPopulated = {
  ...minimalValid,
  intent_services: ['stripe', 'slack'],
  baseline_profile: { call_count: 12, mean_latency_ms: 240 },
  expected_output_shape: {
    type: 'object',
    required: ['refund_id'],
    properties: { refund_id: { type: 'string', pattern: '^re_' } },
  },
  expected_counterparties: ['ch_acme123', 'C12345'],
  max_actions: 50,
  max_dropoff_bytes: 5_242_880,
  coverage_cap_cents: 50_000,
  max_duration_seconds: 900,
  max_concurrent_intents: 5,
  max_actions_per_service: { stripe: 5, slack: 50 },
  cap_behavior: {
    max_actions: 'auto_revoke' as const,
    max_duration_seconds: 'deny_and_flag' as const,
  },
  completed_at: 1_726_000_500_000,
  terminal_state: 'completed_successful' as const,
  revoke_reason: null,
};

describe('MissionClaim', () => {
  it('accepts a minimal valid payload', () => {
    expect(() => MissionClaim.parse(minimalValid)).not.toThrow();
  });

  it('applies defaults for omitted optional fields', () => {
    const parsed = MissionClaim.parse(minimalValid);
    expect(parsed.intent_services).toEqual([]);
    expect(parsed.baseline_profile).toBeNull();
    expect(parsed.expected_output_shape).toBeNull();
    expect(parsed.expected_counterparties).toEqual([]);
    expect(parsed.max_actions).toBeNull();
    expect(parsed.max_dropoff_bytes).toBeNull();
    expect(parsed.coverage_cap_cents).toBeNull();
    expect(parsed.max_duration_seconds).toBeNull();
    expect(parsed.max_concurrent_intents).toBeNull();
    expect(parsed.max_actions_per_service).toEqual({});
    expect(parsed.cap_behavior).toEqual({});
    expect(parsed.completed_at).toBeNull();
    expect(parsed.terminal_state).toBeNull();
    expect(parsed.revoke_reason).toBeNull();
  });

  it('accepts a fully-populated payload with all six caps and overrides', () => {
    expect(() => MissionClaim.parse(fullyPopulated)).not.toThrow();
  });

  it('rejects an invalid mission_id prefix', () => {
    expect(() =>
      MissionClaim.parse({ ...minimalValid, mission_id: 'mission_xyz' }),
    ).toThrow();
  });

  it('rejects an empty mission_id', () => {
    expect(() =>
      MissionClaim.parse({ ...minimalValid, mission_id: '' }),
    ).toThrow();
  });

  it('rejects negative caps', () => {
    expect(() =>
      MissionClaim.parse({ ...minimalValid, max_actions: -1 }),
    ).toThrow();
    expect(() =>
      MissionClaim.parse({ ...minimalValid, max_duration_seconds: 0 }),
    ).toThrow();
    expect(() =>
      MissionClaim.parse({ ...minimalValid, max_concurrent_intents: -5 }),
    ).toThrow();
    expect(() =>
      MissionClaim.parse({ ...minimalValid, coverage_cap_cents: -100 }),
    ).toThrow();
  });

  it('accepts max_dropoff_bytes = 0 (nonnegative, lockdown shape)', () => {
    expect(() =>
      MissionClaim.parse({ ...minimalValid, max_dropoff_bytes: 0 }),
    ).not.toThrow();
  });

  it('rejects per-service cap with non-positive value', () => {
    expect(() =>
      MissionClaim.parse({
        ...minimalValid,
        max_actions_per_service: { stripe: 0 },
      }),
    ).toThrow();
  });

  it('rejects cap_behavior with unknown cap name', () => {
    expect(() =>
      MissionClaim.parse({
        ...minimalValid,
        cap_behavior: { bogus_cap: 'auto_revoke' },
      }),
    ).toThrow();
  });

  it('rejects cap_behavior with unknown behavior value', () => {
    expect(() =>
      MissionClaim.parse({
        ...minimalValid,
        cap_behavior: { max_actions: 'explode' },
      }),
    ).toThrow();
  });

  it('accepts each terminal_state enum value', () => {
    const states = [
      'completed_successful',
      'completed_expired',
      'completed_cap_breached',
      'revoked_adversarial',
      'revoked_operator_clean',
    ] as const;
    for (const s of states) {
      expect(() =>
        MissionClaim.parse({ ...minimalValid, terminal_state: s }),
      ).not.toThrow();
    }
  });

  it('rejects unknown terminal_state', () => {
    expect(() =>
      MissionClaim.parse({ ...minimalValid, terminal_state: 'done' }),
    ).toThrow();
  });

  it('accepts each revoke_reason enum value', () => {
    const reasons = [
      'adversarial',
      'cap_breach_hard',
      'operator_initiated_clean',
      'cascade_from_passport',
    ] as const;
    for (const r of reasons) {
      expect(() =>
        MissionClaim.parse({ ...minimalValid, revoke_reason: r }),
      ).not.toThrow();
    }
  });

  it('rejects intent_summary longer than 500 chars', () => {
    expect(() =>
      MissionClaim.parse({
        ...minimalValid,
        intent_summary: 'x'.repeat(501),
      }),
    ).toThrow();
  });

  it('rejects missing required fields', () => {
    const requiredFields = ['mission_id', 'operator_id', 'intent_summary', 'started_at', 'expires_at'] as const;
    for (const field of requiredFields) {
      const stripped = { ...minimalValid } as Record<string, unknown>;
      delete stripped[field];
      expect(() => MissionClaim.parse(stripped)).toThrow();
    }
  });
});

describe('PASSPORT_CLAIM_SCHEMAS dispatch', () => {
  it('registers mission claim type', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.mission).toBe(MissionClaim);
  });

  it('PASSPORT_CLAIM_SCHEMAS.mission accepts a minimal valid mission payload', () => {
    expect(() =>
      PASSPORT_CLAIM_SCHEMAS.mission.parse(minimalValid),
    ).not.toThrow();
  });
});
