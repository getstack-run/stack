import { describe, it, expect } from 'vitest';
import { EntityObservationClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

const baseValid = {
  type: 'entity_observation' as const,
  intent_outcome_ref: 'pc_outcome_abc123',
  entities: ['api.stripe.com', 'user@example.com', 'acct_12345'],
  entity_types: ['url_host', 'email', 'account_id'] as const,
  agent_id: 'ag_test1',
  metadata: { extraction_method: 'regex', confidence: 0.95 },
  observed_at: 1_726_000_000_000,
};

describe('EntityObservationClaim', () => {
  it('accepts a full valid payload', () => {
    expect(() => EntityObservationClaim.parse(baseValid)).not.toThrow();
  });

  it('accepts minimum required fields (no intent_outcome_ref, defaults)', () => {
    expect(() =>
      EntityObservationClaim.parse({
        type: 'entity_observation',
        agent_id: 'ag_min',
        observed_at: 1_726_000_000_000,
      }),
    ).not.toThrow();
  });

  it('defaults entities + entity_types + metadata when omitted', () => {
    const parsed = EntityObservationClaim.parse({
      type: 'entity_observation',
      agent_id: 'ag_default',
      observed_at: 1_726_000_000_000,
    });
    expect(parsed.entities).toEqual([]);
    expect(parsed.entity_types).toEqual([]);
    expect(parsed.metadata).toEqual({});
  });

  it('rejects malformed agent_id', () => {
    expect(() =>
      EntityObservationClaim.parse({ ...baseValid, agent_id: 'agent_123' }),
    ).toThrow();
  });

  it('rejects malformed intent_outcome_ref', () => {
    expect(() =>
      EntityObservationClaim.parse({ ...baseValid, intent_outcome_ref: 'not-a-claim-id' }),
    ).toThrow();
  });

  it('rejects unknown entity_type', () => {
    expect(() =>
      EntityObservationClaim.parse({
        ...baseValid,
        entity_types: ['url_host', 'mystery_type'],
      }),
    ).toThrow();
  });

  it('rejects entities array over the 256 cap', () => {
    const tooMany = Array.from({ length: 257 }, (_, i) => `entity-${i}.example.com`);
    expect(() =>
      EntityObservationClaim.parse({ ...baseValid, entities: tooMany }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.entity_observation).toBe(EntityObservationClaim);
  });

  // mission_ref retrofit
  it('accepts mission_ref as a valid mission_id', () => {
    expect(() =>
      EntityObservationClaim.parse({ ...baseValid, mission_ref: 'ms_run_42' }),
    ).not.toThrow();
  });

  it('accepts mission_ref omitted (additive nullable optional)', () => {
    expect(() => EntityObservationClaim.parse({ ...baseValid })).not.toThrow();
  });

  it('rejects mission_ref with wrong prefix', () => {
    expect(() =>
      EntityObservationClaim.parse({ ...baseValid, mission_ref: 'pc_old_shape' }),
    ).toThrow();
  });
});
