/** Persisted record shapes and runtime-context types shared by the authority modules. */
import type { Database, HumanOperatorAuthor } from '@stack/shared';
import type { JWK } from 'jose';

export type AuthorityProofStatus =
  | 'pending'
  | 'active'
  | 'suspended'
  | 'revoked'
  | 'replaced'
  | 'erased';

export type AuthorityBindingStatus =
  | 'draft'
  | 'pending_approval'
  | 'active'
  | 'suspended'
  | 'revoked'
  | 'replaced'
  | 'erased';

export type AuthorityDbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface AuthorityPrincipalRecord {
  id: string;
  operator_id: string;
  kind: 'person' | 'organisation';
  label_encrypted: string | null;
  status: 'active' | 'revoked' | 'erased';
  created_at: Date;
  revoked_at: Date | null;
  revoked_reason: string | null;
  erased_at: Date | null;
  tombstone_hash: string | null;
  tombstone_claim_id: string | null;
}

export interface AuthorityProofProfileVersionRecord {
  id: string;
  operator_id: string | null;
  proof_kind: string;
  schema_uri: string;
  schema_version: string;
  adapter_key: string;
  adapter_version: number;
  accepted_native_formats: string[];
  status: 'active' | 'retired';
  content_hash: string;
  config_json: Record<string, unknown>;
}

export interface AuthorityReceiverRecord {
  id: string;
  managed_by_operator_id: string;
  mode: 'native' | 'proxy_bridge' | 'internal';
  status: 'pending' | 'active' | 'suspended' | 'revoked';
  current_profile_version_id: string | null;
  canonical_identifier?: string;
  display_name?: string;
  proxy_service_connection_id?: string | null;
  created_at?: Date;
  verified_at?: Date | null;
  revoked_at?: Date | null;
}

export interface AuthorityReceiverProfileRecord {
  id: string;
  receiver_id: string;
  status: 'active' | 'retired';
  content_hash: string;
  audience: string;
  delivery_endpoint: string | null;
  config_json: Record<string, unknown>;
  profile_key?: string;
  version?: number;
  schema_uri?: string;
  schema_version?: string;
  adapter_key?: string;
  adapter_version?: number;
}

export interface AuthorityProofRecord {
  id: string;
  version: number;
  operator_id: string;
  subject_principal_id: string;
  represented_principal_id: string | null;
  profile_version_id: string;
  proof_kind: string;
  source_kind: 'legacy_identity_claim' | 'external_native' | 'stack_derived';
  legacy_identity_claim_id: string | null;
  issuer_identifier: string;
  issuer_key_thumbprint: string | null;
  original_relying_party_identifier: string | null;
  schema_uri: string;
  schema_version: string;
  native_format: string;
  native_evidence_encrypted: string | null;
  normalized_facts_encrypted: string | null;
  native_evidence_hash: string;
  normalized_facts_hash: string | null;
  verification_method: string;
  verifier_identifier: string;
  verifier_version: string;
  assurance_uri: string | null;
  verified_at: Date;
  valid_from: Date;
  expires_at: Date | null;
  status: AuthorityProofStatus;
  status_fresh_until: Date | null;
  last_status_result: 'valid' | 'revoked' | 'unknown' | null;
  last_status_checked_at: Date | null;
  claim_id: string | null;
  created_at: Date;
  revoked_at: Date | null;
  revoked_reason: string | null;
  erased_at: Date | null;
  tombstone_hash: string | null;
  tombstone_claim_id: string | null;
  supersedes_version: number | null;
}

export interface AuthorityBindingRecord {
  id: string;
  version: number;
  operator_id: string;
  principal_id: string;
  agent_id: string;
  agent_key_thumbprint: string;
  receiver_id: string;
  receiver_profile_version_id: string;
  domain_profile_version_id: string | null;
  mission_ids: string[];
  parent_binding_id: string | null;
  parent_binding_version: number | null;
  lineage_root_id: string;
  lineage_root_version: number;
  delegation_depth: number;
  purpose_code: string;
  purpose_statement_encrypted: string | null;
  purpose_hash: string;
  scope_encrypted: string | null;
  scope_hash: string;
  approval_policy_encrypted: string | null;
  approval_policy_hash: string;
  disclosure_policy_encrypted: string | null;
  disclosure_policy_hash: string;
  delegation_policy: Record<string, unknown>;
  delegation_policy_hash: string;
  allow_further_delegation: boolean;
  max_delegation_depth: number;
  proof_set_hash: string;
  valid_from: Date;
  expires_at: Date;
  status: AuthorityBindingStatus;
  claim_id: string | null;
  claim_hash: string | null;
  created_at: Date;
  activated_at: Date | null;
  revoked_at: Date | null;
  revoked_reason: string | null;
  erased_at: Date | null;
  tombstone_hash: string | null;
  tombstone_claim_id: string | null;
}

export type AuthorityErasureTargetKind =
  | 'principal'
  | 'binding'
  | 'proof'
  | 'presentation'
  | 'receiver_transaction_receipt';

export interface AuthorityErasureTarget {
  target_kind: AuthorityErasureTargetKind;
  target_id: string;
  target_version: number | null;
  prior_artifact_digest: string;
  prior_claim_digest: string | null;
}

export interface AuthorityErasureTombstone extends AuthorityErasureTarget {
  tombstone_digest: string;
  tombstone_claim_id: string;
}

export interface AuthorityBindingProofRecord {
  binding_id: string;
  binding_version: number;
  proof_id: string;
  proof_version: number;
  role: string;
  authoriser_principal_id: string | null;
  group_key: string;
  weight: number;
  required: boolean;
  ordinal: number;
}

export interface AuthorityReceiverKeyRecord {
  id: string;
  receiver_id: string;
  key_id: string;
  use: 'request_signing' | 'response_encryption' | 'receipt_signing' | 'transport_mtls';
  algorithm: string;
  public_jwk: JWK;
  thumbprint: string;
  status: 'active' | 'retired' | 'revoked';
  valid_from: Date;
  valid_until: Date | null;
}

export interface AuthorityApprovalClaimContext {
  decision_id: string;
  request_id: string;
  binding_id: string;
  binding_version: number;
  authority_use_id: string | null;
  authoriser_principal_id: string;
  identity_proof_id: string;
  identity_proof_version: number;
  capacity_proof_id: string | null;
  capacity_proof_version: number | null;
  decision_proof_id: string;
  decision_proof_version: number;
  decision: 'approve' | 'reject';
  weight: number;
  request_hash: string;
  phase: AuthorityApprovalRequestRecord['phase'];
  group_key_hash: string;
  approval_requirement_hash: string;
  decided_at: Date;
  expires_at: Date | null;
  revoked_at: Date | null;
}

export interface AuthorityApprovalRequestRecord {
  id: string;
  operator_id: string;
  binding_id: string;
  binding_version: number;
  authority_use_id: string | null;
  phase: 'activation' | 'action' | 'presentation';
  group_key: string;
  request_hash: string;
  challenge_hash: string;
  required_weight: number;
  collected_weight: number;
  reject_mode: 'any_reject' | 'threshold_reject';
  status: 'pending' | 'satisfied' | 'rejected' | 'expired' | 'consumed' | 'cancelled';
  created_at: Date;
  expires_at: Date;
  satisfied_at: Date | null;
  consumed_at: Date | null;
}

export interface AuthorityEvaluationInput {
  bindingId: string;
  bindingVersion?: number;
  passportJti: string;
  agentId: string;
  agentKeyThumbprint: string;
  receiverId: string;
  receiverRequestId: string;
  missionId?: string;
  actionUri: string;
  resourceRef?: string;
  requestHash: string;
  normalizedRequest: unknown;
  disclosureManifest?: Array<{ fact_id: string; mode: string }>;
  verificationMode: 'native_receiver' | 'proxy_mediated';
}

export type AuthorityRuntimeBoundary =
  | { kind: 'proxy'; serviceConnectionId: string; provider: string; method: string }
  | { kind: 'llm'; serviceConnectionId: string; provider: string; operation: string }
  | { kind: 'skill'; skillId: string }
  | { kind: 'a2a'; receiverAgentId: string }
  | { kind: 'dropoff'; action: 'create' | 'deposit' | 'collect'; participantAgentId: string };

export type AuthorityMutationActor =
  | HumanOperatorAuthor
  | {
      kind: 'agent';
      agent_id: string;
      passport_jti: string;
    };

export interface AuthorityEvaluationResult {
  allowed: boolean;
  authorityUseId?: string;
  /** Existing lifecycle state when this stable runtime request is resumed. */
  executionState?: AuthorityUseRecord['status'];
  bindingId: string;
  bindingVersion: number;
  proofStrength?: 'native_issuer_evidence' | 'native_stack_attestation' | 'proxy_stack_enforced';
  receiverId?: string;
  receiverProfileVersionId?: string;
  denialCode?: string;
}

export interface AuthorityUseInsert {
  id: string;
  operator_id: string;
  binding_id: string;
  binding_version: number;
  passport_jti: string;
  mission_id: string | null;
  agent_id: string;
  agent_key_thumbprint: string;
  receiver_id: string;
  receiver_profile_version_id: string;
  domain_profile_version_id: string | null;
  receiver_request_id: string;
  action_uri: string;
  resource_hash: string | null;
  request_hash: string;
  effective_scope_hash: string;
  proof_set_hash: string;
  disclosure_manifest: Array<{ fact_id: string; mode: string }>;
  verification_mode: 'native_receiver' | 'proxy_mediated';
  proof_strength: 'native_issuer_evidence' | 'native_stack_attestation' | 'proxy_stack_enforced';
  status:
    | 'pending'
    | 'waiting_approval'
    | 'authorized'
    | 'denied'
    | 'dispatched'
    | 'succeeded'
    | 'failed';
  denial_code: string | null;
  created_at: Date;
  authorized_at: Date | null;
}

export interface AuthorityUseRecord extends AuthorityUseInsert {
  intent_claim_id: string | null;
  outcome_claim_id: string | null;
  dispatched_at: Date | null;
  completed_at: Date | null;
  result_hash: string | null;
}

export interface AuthorityReceiverAuthContext {
  receiverId: string;
  keyId: string;
  jti: string;
  expiresAt: Date;
  payload: Record<string, unknown>;
}

export interface ReceiverTransactionReceiptView {
  id: string;
  authority_use_id: string;
  presentation_id: string | null;
  receiver_id: string;
  outcome: 'accepted' | 'rejected' | 'failed';
  receipt_hash: string;
  request_hash: string;
  result_hash: string | null;
  verified_at: string;
  received_at: string;
}

export interface AuthorityPresentationRecord {
  id: string;
  operator_id: string;
  authority_use_id: string;
  binding_id: string;
  binding_version: number;
  receiver_id: string;
  receiver_profile_version_id: string;
  request_signing_key_id: string;
  response_encryption_key_id: string;
  nonce_hash: string;
  state_hash: string | null;
  signed_request_hash: string;
  request_payload_encrypted: string | null;
  requested_fact_ids: string[];
  presentation_jti_hash: string;
  payload_hash: string | null;
  disclosure_manifest: Array<{ fact_id: string; mode: string }>;
  proof_refs: Array<{ id: string; version: number }>;
  signing_key_id: string | null;
  signing_algorithm: string | null;
  key_management_algorithm: string | null;
  content_encryption_algorithm: string | null;
  status:
    | 'pending'
    | 'prepared'
    | 'delivered'
    | 'delivery_failed'
    | 'accepted'
    | 'rejected'
    | 'expired'
    | 'erased';
  created_at: Date;
  expires_at: Date;
  prepared_at: Date | null;
  delivered_at: Date | null;
  last_error_code: string | null;
  erased_at: Date | null;
  tombstone_hash: string | null;
  tombstone_claim_id: string | null;
}

export type AuthorityPresentationPatch = Partial<
  Pick<
    AuthorityPresentationRecord,
    | 'status'
    | 'payload_hash'
    | 'signing_key_id'
    | 'signing_algorithm'
    | 'key_management_algorithm'
    | 'content_encryption_algorithm'
    | 'prepared_at'
    | 'delivered_at'
    | 'last_error_code'
    | 'request_payload_encrypted'
  >
>;

export interface ReceiverTransactionReceiptRecord {
  id: string;
  operator_id: string;
  authority_use_id: string;
  presentation_id: string | null;
  receiver_id: string;
  receiver_profile_version_id: string;
  receiver_key_id: string;
  receipt_jti_hash: string;
  native_format: string;
  native_receipt_encrypted: string | null;
  receipt_hash: string;
  request_hash: string;
  result_hash: string | null;
  outcome: 'accepted' | 'rejected' | 'failed';
  external_transaction_ref_hash: string | null;
  verified_at: Date;
  received_at: Date;
  claim_id: string | null;
  erased_at: Date | null;
  tombstone_hash: string | null;
  tombstone_claim_id: string | null;
}
