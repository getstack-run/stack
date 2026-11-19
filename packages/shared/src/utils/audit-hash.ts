import { sha256 } from './index.js';

/**
 * Genesis seed for a brand-new chain. A per-operator chain starts here
 * when no prior row exists.
 */
export const AUDIT_CHAIN_GENESIS = '0'.repeat(64);
export const AUDIT_HASH_VERSION_CURRENT = 2 as const;
export type AuditHashVersion = 1 | typeof AUDIT_HASH_VERSION_CURRENT;
export type AuditClaimBindingStatus =
  | 'legacy_unbound'
  | 'not_applicable'
  | 'no_active_claims'
  | 'bound';

/**
 * The exact fields that contribute to an audit entry's hash, in the
 * canonical order. Both the writer and the verifier use this shape so
 * they cannot drift.
 *
 * Optional fields use the "include only when present" pattern: legacy
 * rows written before a field existed produce the same hash as if the
 * field were never defined, preserving backward chain compatibility.
 *
 * `passport_claims_at_event` (optional): set of passport-claim hashes
 * attached at audit-write time, sorted lexicographically. Included
 * ONLY when a non-empty array.
 *
 * `request_bytes`, `response_bytes`, `request_entropy`,
 * `response_entropy`: per-call byte sizes and
 * Shannon entropy of request/response bodies. Populated by the proxy at
 * audit-write time. Included in the hash ONLY when non-null. These are
 * detector inputs for the behavioral_anomaly detector — tamper-evidence
 * on them matters for forensics.
 *
 * `actor_grant_id`, `actor_partner_operator_id`:
 * partner-acting-for-user attribution. Set on entries written under a
 * grant-authenticated request. Hash-binding them makes the acting
 * partner tamper-evident on the user's chain — a partner (or STACK)
 * cannot later re-attribute an action to the user themselves without
 * breaking the chain. Included ONLY when non-null.
 */
export interface AuditEntryHashInput {
  hash_version?: AuditHashVersion;
  entry_id: string;
  trace_id?: string;
  span_id?: string;
  parent_span_id?: string | null;
  timestamp: number;
  operator_id: string;
  agent_id: string;
  passport_jti?: string;
  layer: string;
  action: string;
  outcome: string;
  duration_ms?: number | null;
  payload_hash?: string | null;
  error_code?: string | null;
  error_message?: string | null;
  prev_entry_hash: string;
  claim_binding_status?: AuditClaimBindingStatus;
  passport_claims_at_event?: string[];
  request_bytes?: number | null;
  response_bytes?: number | null;
  request_entropy?: number | null;
  response_entropy?: number | null;
  actor_grant_id?: string | null;
  actor_partner_operator_id?: string | null;
}

/**
 * Deterministic hash of a single audit row, chaining against the prior
 * entry's hash. JSON.stringify over a fixed-shape object is stable
 * because the object literal's key order is preserved in JSON output.
 *
 * For chain backward-compat, each optional field is included in the
 * canonical input ONLY when the writer passes a non-empty / non-null
 * value. Existing chains keep verifying; new entries lock-step with
 * whatever optional fields the producer recorded.
 */
export function computeAuditEntryHash(input: AuditEntryHashInput): string {
  const version = input.hash_version ?? 1;
  if (version === AUDIT_HASH_VERSION_CURRENT) {
    if (
      input.trace_id === undefined ||
      input.span_id === undefined ||
      input.passport_jti === undefined ||
      input.claim_binding_status === undefined
    ) {
      throw new Error('Audit hash v2 requires trace, span, passport and claim-binding fields');
    }
    return computeAuditEntryHashV2(input);
  }
  if (version !== 1) {
    throw new Error(`Unsupported audit hash version: ${String(version)}`);
  }

  return computeAuditEntryHashV1(input);
}

function computeAuditEntryHashV1(input: AuditEntryHashInput): string {
  const claims = input.passport_claims_at_event;
  const includeClaims = Array.isArray(claims) && claims.length > 0;
  const canonical = JSON.stringify({
    entry_id: input.entry_id,
    timestamp: input.timestamp,
    operator_id: input.operator_id,
    agent_id: input.agent_id,
    layer: input.layer,
    action: input.action,
    outcome: input.outcome,
    prev_entry_hash: input.prev_entry_hash,
    ...(includeClaims ? { passport_claims_at_event: [...claims].sort() } : {}),
    ...(input.request_bytes != null ? { request_bytes: input.request_bytes } : {}),
    ...(input.response_bytes != null ? { response_bytes: input.response_bytes } : {}),
    ...(input.request_entropy != null ? { request_entropy: input.request_entropy } : {}),
    ...(input.response_entropy != null ? { response_entropy: input.response_entropy } : {}),
    ...(input.actor_grant_id != null ? { actor_grant_id: input.actor_grant_id } : {}),
    ...(input.actor_partner_operator_id != null
      ? { actor_partner_operator_id: input.actor_partner_operator_id }
      : {}),
  });
  return sha256(canonical);
}

function computeAuditEntryHashV2(input: AuditEntryHashInput): string {
  const canonical = JSON.stringify({
    hash_version: AUDIT_HASH_VERSION_CURRENT,
    entry_id: input.entry_id,
    trace_id: input.trace_id,
    span_id: input.span_id,
    parent_span_id: input.parent_span_id ?? null,
    timestamp: input.timestamp,
    operator_id: input.operator_id,
    agent_id: input.agent_id,
    passport_jti: input.passport_jti,
    layer: input.layer,
    action: input.action,
    outcome: input.outcome,
    duration_ms: input.duration_ms ?? null,
    payload_hash: input.payload_hash ?? null,
    error_code: input.error_code ?? null,
    error_message: input.error_message ?? null,
    prev_entry_hash: input.prev_entry_hash,
    claim_binding_status: input.claim_binding_status,
    passport_claims_at_event: [...(input.passport_claims_at_event ?? [])].sort(),
    request_bytes: input.request_bytes ?? null,
    response_bytes: input.response_bytes ?? null,
    request_entropy: input.request_entropy ?? null,
    response_entropy: input.response_entropy ?? null,
    actor_grant_id: input.actor_grant_id ?? null,
    actor_partner_operator_id: input.actor_partner_operator_id ?? null,
  });
  return sha256(canonical);
}
