/**
 * Recursive canonical JSON serialiser.
 *
 * Approximates RFC 8785 JSON Canonicalization Scheme (JCS) for the
 * value shapes STACK actually emits (integers + strings + booleans +
 * nulls + arrays + objects). Object keys are sorted lexicographically
 * at every depth; arrays preserve order (semantic: arrays are
 * sequences); primitives use `JSON.stringify` for their natural
 * quoting/encoding rules. Output is a single-line string with no
 * whitespace.
 *
 * Symbol keys, `undefined` values, and functions are filtered out by
 * `JSON.stringify` semantics — same behaviour as `JSON.stringify`
 * itself.
 *
 * Used by:
 *   - `computePassportClaimHash` (`./passport-claim-hash.ts`) — claim
 *     hash binding (`passport_claims.claim_hash`).
 *   - `EvidencePackService.export` — content_hash on the
 *     evidence-pack manifest, the byte-level identity of a pack.
 *
 * Deviation from strict RFC 8785: JCS Section 3.2.2.3 mandates an
 * exact ECMAScript ToString conversion for numbers (including the
 * `0` for negative zero rule and exponent normalisation for floats).
 * `JSON.stringify` on V8 matches ECMAScript ToString for the integer
 * range STACK uses (unix-ms timestamps, counts, claim_version).
 * Floating-point fields are not in our pack manifest schema — every
 * numeric field is integer-typed at the Zod layer. If we later
 * introduce a float-bearing claim type in the pack scope, this helper
 * must move to a full RFC 8785 implementation.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  const t = typeof value;
  if (t === 'number' || t === 'string' || t === 'boolean') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canonicalize(v));
    }
    return '{' + parts.join(',') + '}';
  }
  // Functions / symbols → JSON.stringify returns undefined; mirror by
  // emitting `null` so the canonical output stays parseable.
  return 'null';
}
