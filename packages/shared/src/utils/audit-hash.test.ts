import { describe, it, expect } from 'vitest';
import {
  computeAuditEntryHash,
  AUDIT_CHAIN_GENESIS,
  AUDIT_HASH_VERSION_CURRENT,
} from './audit-hash.js';
// Hoisted deliberately. This used to be a dynamic `await import` inside the
// float8 test, and loading the whole schema module costs more than the 5s
// per-test budget on a cold transform - so the one structural test guarding
// the audit chain's float precision failed on a TIMEOUT, not on a real
// regression, and was the single thing keeping the suite red. A structural
// assertion on column metadata has no reason to defer its import.
import { auditLog } from '../db/schema/index.js';

const base = {
  entry_id: 'aud_A',
  timestamp: 1700000000000,
  operator_id: 'op_1',
  agent_id: 'agt_1',
  layer: 'vault',
  action: 'passport.issue',
  outcome: 'success',
  prev_entry_hash: AUDIT_CHAIN_GENESIS,
};

describe('computeAuditEntryHash', () => {
  it('produces a 64-character hex sha256', () => {
    const h = computeAuditEntryHash(base);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic — same input, same hash', () => {
    expect(computeAuditEntryHash(base)).toBe(computeAuditEntryHash({ ...base }));
  });

  it('differs when any field changes (tamper detection)', () => {
    const h0 = computeAuditEntryHash(base);
    expect(computeAuditEntryHash({ ...base, action: 'passport.revoke' })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, outcome: 'failure' })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, agent_id: 'agt_2' })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, operator_id: 'op_2' })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, timestamp: base.timestamp + 1 })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, entry_id: 'aud_B' })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, layer: 'proxy' })).not.toBe(h0);
    expect(computeAuditEntryHash({ ...base, prev_entry_hash: 'a'.repeat(64) })).not.toBe(h0);
  });

  it('chains — each entry binds to the prior entry_hash', () => {
    const h1 = computeAuditEntryHash(base);
    const h2 = computeAuditEntryHash({ ...base, entry_id: 'aud_B', prev_entry_hash: h1 });
    const h2Alt = computeAuditEntryHash({
      ...base,
      entry_id: 'aud_B',
      prev_entry_hash: AUDIT_CHAIN_GENESIS,
    });
    // Same row, different prev_entry_hash, different resulting hash —
    // this is what makes insertion/deletion detectable on verification.
    expect(h2).not.toBe(h2Alt);
  });

  it('genesis constant is 64 zero-chars', () => {
    expect(AUDIT_CHAIN_GENESIS).toBe('0'.repeat(64));
    expect(AUDIT_CHAIN_GENESIS).toHaveLength(64);
  });

  describe('v2 complete stored-field binding', () => {
    const v2 = {
      ...base,
      hash_version: AUDIT_HASH_VERSION_CURRENT,
      trace_id: 'tr_synthetic',
      span_id: 'sp_synthetic',
      parent_span_id: 'sp_parent',
      passport_jti: 'pas_synthetic',
      duration_ms: 17,
      payload_hash: 'p'.repeat(64),
      error_code: 'SYNTHETIC_ERROR',
      error_message: 'synthetic message',
      claim_binding_status: 'bound' as const,
      passport_claims_at_event: ['b'.repeat(64), 'a'.repeat(64)],
      request_bytes: 11,
      response_bytes: 12,
      request_entropy: 1.25,
      response_entropy: 2.5,
      actor_grant_id: 'pgr_synthetic',
      actor_partner_operator_id: 'op_partner',
    };

    it('changes when any stored security field changes', () => {
      const original = computeAuditEntryHash(v2);
      const mutations: Record<string, unknown>[] = [
        { entry_id: 'aue_other' },
        { trace_id: 'tr_other' },
        { span_id: 'sp_other' },
        { parent_span_id: null },
        { timestamp: 1_700_000_000_001 },
        { operator_id: 'op_other' },
        { agent_id: 'agt_other' },
        { passport_jti: 'pas_other' },
        { layer: 'proxy' },
        { action: 'other.action' },
        { outcome: 'denied' },
        { duration_ms: 18 },
        { payload_hash: 'q'.repeat(64) },
        { error_code: null },
        { error_message: 'other message' },
        { claim_binding_status: 'no_active_claims' },
        { passport_claims_at_event: ['a'.repeat(64)] },
        { request_bytes: 99 },
        { response_bytes: 99 },
        { request_entropy: 7.5 },
        { response_entropy: 7.5 },
        { actor_grant_id: null },
        { actor_partner_operator_id: null },
        { prev_entry_hash: 'f'.repeat(64) },
      ];
      for (const mutation of mutations) {
        expect(computeAuditEntryHash({ ...v2, ...mutation })).not.toBe(original);
      }
    });

    it('requires every v2 identity and claim-binding field', () => {
      expect(() => computeAuditEntryHash({ ...v2, trace_id: undefined }))
        .toThrow('Audit hash v2 requires');
      expect(() => computeAuditEntryHash({ ...v2, claim_binding_status: undefined }))
        .toThrow('Audit hash v2 requires');
    });

    it('anchors v2 to a legacy head without changing the legacy hash', () => {
      const legacyHead = computeAuditEntryHash(base);
      const anchored = computeAuditEntryHash({ ...v2, prev_entry_hash: legacyHead });
      expect(legacyHead).toBe(computeAuditEntryHash(base));
      expect(anchored).not.toBe(computeAuditEntryHash({ ...v2, prev_entry_hash: AUDIT_CHAIN_GENESIS }));
    });
  });

  describe('passport_claims_at_event (chain claim binding)', () => {
    it('absent and empty-array produce identical legacy hashes', () => {
      const legacy = computeAuditEntryHash(base);
      const empty = computeAuditEntryHash({ ...base, passport_claims_at_event: [] });
      expect(empty).toBe(legacy);
    });

    it('non-empty claim list produces a different hash', () => {
      const legacy = computeAuditEntryHash(base);
      const withClaims = computeAuditEntryHash({
        ...base,
        passport_claims_at_event: ['c'.repeat(64)],
      });
      expect(withClaims).not.toBe(legacy);
    });

    it('order-independent — sorted canonicalization', () => {
      const a = computeAuditEntryHash({
        ...base,
        passport_claims_at_event: ['aaaa', 'bbbb', 'cccc'],
      });
      const b = computeAuditEntryHash({
        ...base,
        passport_claims_at_event: ['cccc', 'aaaa', 'bbbb'],
      });
      expect(a).toBe(b);
    });

    it('tamper detection — flipping any attached claim hash changes the result', () => {
      const h = computeAuditEntryHash({
        ...base,
        passport_claims_at_event: ['aaaa', 'bbbb'],
      });
      const flipped = computeAuditEntryHash({
        ...base,
        passport_claims_at_event: ['aaaa', 'cccc'],
      });
      expect(flipped).not.toBe(h);
    });
  });

 describe('body metrics (bytes + entropy)', () => {
    it('absent and null produce identical legacy hashes for every new field', () => {
      const legacy = computeAuditEntryHash(base);
      expect(computeAuditEntryHash({ ...base, request_bytes: null })).toBe(legacy);
      expect(computeAuditEntryHash({ ...base, response_bytes: null })).toBe(legacy);
      expect(computeAuditEntryHash({ ...base, request_entropy: null })).toBe(legacy);
      expect(computeAuditEntryHash({ ...base, response_entropy: null })).toBe(legacy);
      expect(
        computeAuditEntryHash({
          ...base,
          request_bytes: null,
          response_bytes: null,
          request_entropy: null,
          response_entropy: null,
        }),
      ).toBe(legacy);
    });

    it('including any non-null body metric produces a different hash', () => {
      const legacy = computeAuditEntryHash(base);
      expect(computeAuditEntryHash({ ...base, request_bytes: 0 })).not.toBe(legacy);
      expect(computeAuditEntryHash({ ...base, response_bytes: 1024 })).not.toBe(legacy);
      expect(computeAuditEntryHash({ ...base, request_entropy: 4.2 })).not.toBe(legacy);
      expect(computeAuditEntryHash({ ...base, response_entropy: 7.9 })).not.toBe(legacy);
    });

    it('tamper detection — flipping any body metric value changes the result', () => {
      const h = computeAuditEntryHash({
        ...base,
        request_bytes: 512,
        response_bytes: 2048,
        request_entropy: 4.2,
        response_entropy: 5.8,
      });
      expect(
        computeAuditEntryHash({
          ...base,
          request_bytes: 513,
          response_bytes: 2048,
          request_entropy: 4.2,
          response_entropy: 5.8,
        }),
      ).not.toBe(h);
      expect(
        computeAuditEntryHash({
          ...base,
          request_bytes: 512,
          response_bytes: 2048,
          request_entropy: 4.20001,
          response_entropy: 5.8,
        }),
      ).not.toBe(h);
    });

    it('zero is a meaningful value, distinct from null', () => {
      const withZero = computeAuditEntryHash({ ...base, request_bytes: 0 });
      const withNull = computeAuditEntryHash({ ...base, request_bytes: null });
      expect(withZero).not.toBe(withNull);
    });

    it('field order in input does not affect hash (object spread stability)', () => {
      const a = computeAuditEntryHash({
        ...base,
        request_bytes: 100,
        response_entropy: 5.0,
      });
      const b = computeAuditEntryHash({
        ...base,
        response_entropy: 5.0,
        request_bytes: 100,
      });
      expect(a).toBe(b);
    });
  });

 describe('grant attribution (actor_grant_id + actor_partner_operator_id)', () => {
    it('absent and null produce identical legacy hashes', () => {
      const legacy = computeAuditEntryHash(base);
      expect(computeAuditEntryHash({ ...base, actor_grant_id: null })).toBe(legacy);
      expect(computeAuditEntryHash({ ...base, actor_partner_operator_id: null })).toBe(legacy);
      expect(
        computeAuditEntryHash({
          ...base,
          actor_grant_id: null,
          actor_partner_operator_id: null,
        }),
      ).toBe(legacy);
    });

    it('a grant-attributed entry hashes differently from the user acting directly', () => {
      const legacy = computeAuditEntryHash(base);
      expect(computeAuditEntryHash({ ...base, actor_grant_id: 'pgr_abc' })).not.toBe(legacy);
      expect(
        computeAuditEntryHash({ ...base, actor_partner_operator_id: 'op_partner' }),
      ).not.toBe(legacy);
    });

    it('tamper detection — re-attributing to a different grant or partner changes the hash', () => {
      const h = computeAuditEntryHash({
        ...base,
        actor_grant_id: 'pgr_abc',
        actor_partner_operator_id: 'op_partner',
      });
      expect(
        computeAuditEntryHash({
          ...base,
          actor_grant_id: 'pgr_xyz',
          actor_partner_operator_id: 'op_partner',
        }),
      ).not.toBe(h);
      expect(
        computeAuditEntryHash({
          ...base,
          actor_grant_id: 'pgr_abc',
          actor_partner_operator_id: 'op_other',
        }),
      ).not.toBe(h);
      // Stripping the attribution entirely (re-attributing to the user) also breaks the chain.
      expect(computeAuditEntryHash(base)).not.toBe(h);
    });
  });

  describe('float precision — schema-vs-hash drift regression', () => {
    // Regression for the 2026-05-23 chain break (commit-history-ref:
    // migration 0017 audit_entropy_float8). The audit_log.request_entropy
    // + response_entropy columns were originally `real` (float4). The
    // writer hashed the float64 value returned by shannonEntropy(); the
    // INSERT rounded to float4; reading back returned the rounded value
    // (widened to float64); re-hashing returned a different value →
    // chain mismatch. Migration 0017 widened both columns to
    // `double precision` (float8) so the writer's bytes survive the
    // round-trip.
    //
    // This test guards against a regression by hashing rows whose
    // entropy carries precision below float4's representable range. If
    // a future schema change drops the columns back to `real`, the
    // structural test below (column type assertion) catches it
    // immediately. Hash-shape stability is asserted here.

    it('non-trivial float64 entropy values produce stable hashes across calls', () => {
      // A specific float64 that does NOT round to itself under float4
      // (Math.fround). Picked from the failure mode: shannonEntropy
      // outputs values like 5.04672005... — float4 representation is
      // 5.04672 exactly. Float64 preserves the underlying bytes.
      const messy = 5.046720756072998;
      expect(Math.fround(messy)).not.toBe(messy); // sanity — float4 lossy
      const h1 = computeAuditEntryHash({ ...base, request_entropy: messy });
      const h2 = computeAuditEntryHash({ ...base, request_entropy: messy });
      expect(h1).toBe(h2);
      // The same input round-tripped through a float4 column would
      // hash differently. The migration 0017 invariant: the schema
      // stores float8 so the writer's bytes survive.
      const lossy = Math.fround(messy);
      expect(computeAuditEntryHash({ ...base, request_entropy: lossy })).not.toBe(h1);
    });

    it('audit_log.request_entropy + response_entropy MUST be double precision (float8)', () => {
      // Direct schema-level structural test. The columns were `real`
      // (float4) until migration 0017. Reverting to `real` would
      // re-introduce the 2026-05-23 break shape. Test reads the schema
      // declaration via the Drizzle column metadata and asserts the
      // SQL type is `double precision` (the Drizzle helper for float8).
      //
      // Failure mode this catches: a future PR drops `doublePrecision`
      // for `real` to "save 4 bytes per row" or similar plausible-
      // sounding optimization. The test fails before the row hits
      // production and corrupts a chain.
      const reqCol = auditLog.request_entropy as unknown as { columnType: string; dataType?: string };
      const respCol = auditLog.response_entropy as unknown as { columnType: string; dataType?: string };
      // Drizzle's column metadata: `columnType` is the column-builder
      // type (PgDoublePrecision vs PgReal). Use a substring check —
      // the internal name has carried minor variations across
      // drizzle-orm versions (PgDoublePrecision / DoublePrecision).
      expect(reqCol.columnType.toLowerCase()).toContain('doubleprecision');
      expect(respCol.columnType.toLowerCase()).toContain('doubleprecision');
    });
  });
});
