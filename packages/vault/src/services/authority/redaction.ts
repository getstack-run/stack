/** Redacted views of authority records: the only shapes that leave the service. */
import type {
  AuthorityApprovalRequestRecord,
  AuthorityBindingRecord,
  AuthorityPresentationRecord,
  AuthorityPrincipalRecord,
  AuthorityProofRecord,
  AuthorityReceiverRecord,
  AuthorityUseRecord,
  ReceiverTransactionReceiptRecord,
  ReceiverTransactionReceiptView,
} from './records.js';

export function safePrincipal(row: AuthorityPrincipalRecord) {
  return {
    id: row.id,
    kind: row.kind,
    status: row.status,
    created_at: row.created_at.toISOString(),
    revoked_at: row.revoked_at?.toISOString() ?? null,
    erased_at: row.erased_at?.toISOString() ?? null,
  };
}

export function safeProof(row: AuthorityProofRecord) {
  return {
    id: row.id,
    version: row.version,
    subject_principal_id: row.subject_principal_id,
    represented_principal_id: row.represented_principal_id,
    profile_version_id: row.profile_version_id,
    proof_kind: row.proof_kind,
    source_kind: row.source_kind,
    issuer_identifier: row.issuer_identifier,
    schema_uri: row.schema_uri,
    schema_version: row.schema_version,
    native_format: row.native_format,
    native_evidence_hash: row.native_evidence_hash,
    normalized_facts_hash: row.normalized_facts_hash,
    verification_method: row.verification_method,
    verifier_identifier: row.verifier_identifier,
    verifier_version: row.verifier_version,
    assurance_uri: row.assurance_uri,
    verified_at: row.verified_at.toISOString(),
    valid_from: row.valid_from.toISOString(),
    expires_at: row.expires_at?.toISOString() ?? null,
    status: row.status,
    status_fresh_until: row.status_fresh_until?.toISOString() ?? null,
    claim_id: row.claim_id,
    created_at: row.created_at.toISOString(),
    revoked_at: row.revoked_at?.toISOString() ?? null,
    erased_at: row.erased_at?.toISOString() ?? null,
    tombstone_hash: row.tombstone_hash,
  };
}

export function safeBinding(row: AuthorityBindingRecord) {
  return {
    id: row.id,
    version: row.version,
    principal_id: row.principal_id,
    agent_id: row.agent_id,
    agent_key_thumbprint: row.agent_key_thumbprint,
    receiver_id: row.receiver_id,
    receiver_profile_version_id: row.receiver_profile_version_id,
    domain_profile_version_id: row.domain_profile_version_id,
    mission_ids: row.mission_ids,
    parent_binding_id: row.parent_binding_id,
    parent_binding_version: row.parent_binding_version,
    lineage_root_id: row.lineage_root_id,
    lineage_root_version: row.lineage_root_version,
    delegation_depth: row.delegation_depth,
    purpose_code: row.purpose_code,
    purpose_hash: row.purpose_hash,
    scope_hash: row.scope_hash,
    disclosure_policy_hash: row.disclosure_policy_hash,
    allow_further_delegation: row.allow_further_delegation,
    max_delegation_depth: row.max_delegation_depth,
    proof_set_hash: row.proof_set_hash,
    valid_from: row.valid_from.toISOString(),
    expires_at: row.expires_at.toISOString(),
    status: row.status,
    claim_id: row.claim_id,
    claim_hash: row.claim_hash,
    created_at: row.created_at.toISOString(),
    activated_at: row.activated_at?.toISOString() ?? null,
    revoked_at: row.revoked_at?.toISOString() ?? null,
  };
}

export function safeApprovalRequest(row: AuthorityApprovalRequestRecord) {
  return {
    id: row.id,
    binding_id: row.binding_id,
    binding_version: row.binding_version,
    authority_use_id: row.authority_use_id,
    phase: row.phase,
    group_key: row.group_key,
    request_hash: row.request_hash,
    challenge_hash: row.challenge_hash,
    required_weight: row.required_weight,
    collected_weight: row.collected_weight,
    reject_mode: row.reject_mode,
    status: row.status,
    created_at: row.created_at.toISOString(),
    expires_at: row.expires_at.toISOString(),
    satisfied_at: row.satisfied_at?.toISOString() ?? null,
    consumed_at: row.consumed_at?.toISOString() ?? null,
  };
}

export function safeReceiver(row: AuthorityReceiverRecord) {
  return {
    id: row.id,
    mode: row.mode,
    status: row.status,
    canonical_identifier: row.canonical_identifier,
    display_name: row.display_name,
    current_profile_version_id: row.current_profile_version_id,
    created_at: row.created_at?.toISOString(),
    verified_at: row.verified_at?.toISOString() ?? null,
    revoked_at: row.revoked_at?.toISOString() ?? null,
  };
}

export function safePresentation(row: AuthorityPresentationRecord) {
  return {
    id: row.id,
    authority_use_id: row.authority_use_id,
    status: row.status,
    disclosure_manifest: row.disclosure_manifest,
    proof_refs: row.proof_refs.map((proof) => ({
      proof_id: proof.id,
      proof_version: proof.version,
    })),
    expires_at: row.expires_at.toISOString(),
  };
}

export function safeReceipt(row: ReceiverTransactionReceiptRecord): ReceiverTransactionReceiptView {
  return {
    id: row.id,
    authority_use_id: row.authority_use_id,
    presentation_id: row.presentation_id,
    receiver_id: row.receiver_id,
    outcome: row.outcome,
    receipt_hash: row.receipt_hash,
    request_hash: row.request_hash,
    result_hash: row.result_hash,
    verified_at: row.verified_at.toISOString(),
    received_at: row.received_at.toISOString(),
  };
}

export function safeUse(row: AuthorityUseRecord) {
  return {
    id: row.id,
    binding_id: row.binding_id,
    binding_version: row.binding_version,
    passport_jti: row.passport_jti,
    mission_id: row.mission_id,
    agent_id: row.agent_id,
    receiver_id: row.receiver_id,
    receiver_profile_version_id: row.receiver_profile_version_id,
    receiver_request_id: row.receiver_request_id,
    action_uri: row.action_uri,
    resource_hash: row.resource_hash,
    request_hash: row.request_hash,
    effective_scope_hash: row.effective_scope_hash,
    proof_set_hash: row.proof_set_hash,
    disclosure_manifest: row.disclosure_manifest,
    verification_mode: row.verification_mode,
    proof_strength: row.proof_strength,
    status: row.status,
    denial_code: row.denial_code,
    created_at: row.created_at.toISOString(),
    authorized_at: row.authorized_at?.toISOString() ?? null,
  };
}
