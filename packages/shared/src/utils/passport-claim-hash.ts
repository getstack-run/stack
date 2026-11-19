import { sha256 } from './index.js';
import { canonicalize } from './json-canonicalize.js';

/**
 * Deterministic hash for a passport-attached claim.
 *
 * The hash binds three values into a single sha256 fingerprint:
 *   - passport_id (claim attaches to a specific passport — different
 *     passports cannot share a claim hash even with identical bodies)
 *   - type discriminator (e.g. 'svid_attestation')
 *   - body (the typed claim payload)
 *
 * Used by:
 *   - passport_claims.claim_hash — the immutable signed fingerprint stored
 *     on the row. Mutating body_json after attach would break this hash;
 *     the row carries no UPDATE path for body_json.
 *   - audit_log.passport_claims_at_event — the chain-bound array of
 *     attached-claim hashes captured at audit-write time. The chain hash
 *     covers this set, so any tamper with attached claims invalidates
 *     every subsequent audit entry on that operator's chain.
 *
 * Determinism requirement: object key order MUST NOT affect the output.
 * JSON.stringify preserves insertion order (not lexicographic), so we
 * walk the value recursively, sorting object keys at every level.
 * Arrays preserve order (semantic: arrays are sequences).
 */
export function computePassportClaimHash(input: {
  passport_id: string;
  type: string;
  body: Record<string, unknown>;
}): string {
  const canonical = canonicalize({
    passport_id: input.passport_id,
    type: input.type,
    body: input.body,
  });
  return sha256(canonical);
}

// canonicalize was previously a private helper in this file; Phase
// 5.4.4 extracted it to `./json-canonicalize.ts` so the pack manifest
// content_hash uses the same canonicalisation rule as claim hashing.
// Shape is unchanged — moving the function does not alter any
// previously-computed claim_hash value.
