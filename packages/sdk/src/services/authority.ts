import type { HttpClient } from '../client.js';

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = Record<string, JsonValue>;

export type AuthorityPrincipalKind = 'person' | 'organisation';
export type AuthorityProofKind = 'identity' | 'capacity' | 'mandate' | 'consent' | 'signature' | 'domain' | 'workload';
export type AuthorityProofRole = 'principal_identity' | 'authoriser_identity' | 'authoriser_capacity' | 'mandate' | 'consent' | 'domain';
export type AuthorityDisclosureMode = 'predicate' | 'pairwise' | 'exact_private' | 'issuer_evidence' | 'status_only';
export type AuthorityConstraintOp = 'eq' | 'not_eq' | 'in' | 'not_in' | 'lt' | 'lte' | 'gt' | 'gte' | 'exists' | 'not_exists';

export interface AuthorityConstraint {
  path: string;
  op: AuthorityConstraintOp;
  value?: string | number | boolean | Array<string | number | boolean>;
  /** Opaque reference to a value retained in encrypted proof facts. */
  value_ref?: string;
}

export interface AuthorityScope {
  actions: Array<{ action_uri: string; resource_refs?: string[]; constraints?: AuthorityConstraint[] }>;
  limits?: JsonObject;
}

export interface AuthorityDisclosurePolicy {
  rules?: Array<{
    fact_id: string;
    mode: AuthorityDisclosureMode;
    profile_version_id?: string;
    required?: boolean;
  }>;
  principal_confirmation_required?: boolean;
  max_retention_seconds?: number | null;
  live_status_required?: boolean;
}

export interface AuthorityMutationOptions {
  /** Stable key reused for an exact retry. Required by every authority mutation. */
  idempotencyKey: string;
  /** Governance step-up approval for protected operator mutations. */
  governanceApprovalId?: string;
}

export interface CreateEnterpriseOidcAuthorityRequestInput {
  organisation_name: string;
  role_name: string;
  role_claim_path: string;
  role_claim_value: string;
  agent_id: string;
  mission_id?: string;
  service_connection_id: string;
  provider: string;
  purpose: string;
  http_method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  resource_path: string;
  constraints?: AuthorityConstraint[];
  expires_at: string | Date;
}

export interface EnterpriseOidcAuthorityRequest {
  request_id: string;
  status: 'pending' | 'rejected' | 'expired' | 'completed';
  approval_url: string;
  created_at: string;
  expires_at: string;
  completed_at?: string;
  rejected_at?: string;
  result?: {
    binding_id: string;
    binding_version: number;
    binding_status: string;
    organisation_principal_id: string;
    approver_principal_id: string;
    receiver_id: string;
    identity_proof_id: string;
    capacity_proof_id: string;
    approval_request_id: string;
    expires_at: string;
  };
}

export interface CreateAuthorityPrincipalInput { kind: AuthorityPrincipalKind; label?: string }
export interface ImportAuthorityProofInput {
  subject_principal_id: string;
  represented_principal_id?: string;
  profile_version_id: string;
  proof_kind: AuthorityProofKind;
  issuer_identifier: string;
  schema_uri: string;
  schema_version: string;
  native_format: string;
  /** Sensitive write-only provider evidence. It is never returned by safe reads. */
  native_evidence: string;
}
export interface CreateAuthorityProofCollectionSessionInput {
  subject_principal_id: string;
  represented_principal_id?: string;
  profile_version_id: string;
  issuer_identifier: string;
  native_format: string;
}
export interface AuthorityBindingProofInput {
  proof_id: string;
  proof_version: number;
  role: AuthorityProofRole;
  authoriser_principal_id?: string;
  group_key: string;
  weight?: number;
  required?: boolean;
  ordinal?: number;
}
export interface CreateAuthorityBindingInput {
  principal_id: string;
  agent_id: string;
  agent_key_thumbprint?: string;
  receiver_id: string;
  receiver_profile_version_id: string;
  domain_profile_version_id?: string;
  mission_ids?: string[];
  purpose_code: string;
  purpose_statement?: string;
  scope: AuthorityScope;
  approval_policy: JsonObject;
  disclosure_policy: AuthorityDisclosurePolicy;
  delegation_policy: { allow_further_delegation: boolean; max_delegation_depth: number };
  valid_from: string | Date;
  expires_at: string | Date;
  proofs: AuthorityBindingProofInput[];
}
export interface DelegateAuthorityBindingInput {
  child_agent_id: string;
  child_agent_key_thumbprint?: string;
  mission_ids?: string[];
  scope: AuthorityScope;
  disclosure_policy: AuthorityDisclosurePolicy;
  allow_further_delegation?: boolean;
  max_delegation_depth: number;
  valid_from: string | Date;
  expires_at: string | Date;
}
export type CreateAuthorityApprovalRequestsInput =
  | { phase: 'activation' }
  | { phase: 'action' | 'presentation'; authority_use_id: string };
export type CreateAuthorityProfileVersionInput = {
  profile_kind: 'proof' | 'domain';
  profile_key: string;
  version: number;
  schema_uri: string;
  schema_version: string;
  adapter_key: string;
  adapter_version: number;
  config_json: JsonObject;
} | {
  profile_kind: 'receiver';
  profile_key: string;
  version: number;
  receiver_id: string;
  schema_uri: string;
  schema_version: string;
  adapter_key: string;
  adapter_version: number;
  config_json: JsonObject;
};
export interface CreateAuthorityReceiverInput {
  mode: 'native' | 'proxy_bridge' | 'internal';
  canonical_identifier: string;
  display_name: string;
  proxy_service_connection_id?: string;
}
export interface AddAuthorityReceiverKeyInput {
  key_id: string;
  use: 'request_signing' | 'response_encryption' | 'receipt_signing' | 'transport_mtls';
  algorithm: 'EdDSA' | 'ES256' | 'ECDH-ES+A256KW';
  /** Public asymmetric JWK only; private and symmetric members are rejected. */
  public_jwk: JsonObject;
  valid_from: string | Date;
  valid_until?: string | Date;
}

/** All SDK read models are the API's PII-free safe projections. */
export interface AuthorityPrincipal { id: string; kind: AuthorityPrincipalKind; status: string; created_at: string; revoked_at?: string | null; erased_at?: string | null }
export interface AuthorityProof { id: string; version: number; subject_principal_id: string; proof_kind: AuthorityProofKind; status: string; claim_id?: string | null; created_at: string; [key: string]: JsonValue | undefined }
export interface AuthorityBinding { id: string; version: number; principal_id: string; agent_id: string; receiver_id: string; status: string; claim_id?: string | null; created_at: string; [key: string]: JsonValue | undefined }
export interface AuthorityReceiver { id: string; mode: 'native' | 'proxy_bridge' | 'internal'; status: string; canonical_identifier: string; display_name: string; current_profile_version_id?: string | null; created_at: string; [key: string]: JsonValue | undefined }
export interface AuthorityApprovalRequest { id: string; binding_id: string; binding_version: number; phase: string; status: string; request_hash: string; [key: string]: JsonValue | undefined }
export interface AuthorityUse { id: string; binding_id: string; binding_version: number; agent_id: string; receiver_id: string; status: string; created_at: string; [key: string]: JsonValue | undefined }
export interface AuthorityPresentation { id: string; authority_use_id: string; status: string; disclosure_manifest: JsonValue; proof_refs: JsonValue; expires_at: string; [key: string]: JsonValue | undefined }
export interface AuthorityTombstone { target_kind: string; target_id: string; target_version?: number | null; tombstone_digest: string; tombstone_claim_id: string; [key: string]: JsonValue | undefined }
export type AuthoritySafeRecord = Record<string, JsonValue>;

function mutationHeaders(options: AuthorityMutationOptions): Record<string, string> {
  if (!/^[\x21-\x7e]{1,128}$/.test(options.idempotencyKey)) {
    throw new Error('idempotencyKey must contain 1-128 visible ASCII characters');
  }
  return {
    'Idempotency-Key': options.idempotencyKey,
    ...(options.governanceApprovalId ? { 'X-Governance-Approval': options.governanceApprovalId } : {}),
  };
}

const versionQuery = (version?: number) => ({ version: version === undefined ? undefined : String(version) });

export class AuthorityService {
  constructor(private readonly client: HttpClient) {}

  createEnterpriseOidcRequest(input: CreateEnterpriseOidcAuthorityRequestInput, options: AuthorityMutationOptions) {
    return this.client.post<EnterpriseOidcAuthorityRequest>(
      '/v1/authority/enterprise-oidc/requests',
      { ...input, expires_at: input.expires_at instanceof Date ? input.expires_at.toISOString() : input.expires_at },
      { headers: mutationHeaders(options) },
    );
  }
  getEnterpriseOidcRequest(id: string) {
    return this.client.get<EnterpriseOidcAuthorityRequest>(`/v1/authority/enterprise-oidc/requests/${encodeURIComponent(id)}`);
  }

  createPrincipal(input: CreateAuthorityPrincipalInput, options: AuthorityMutationOptions) { return this.client.post<{ principal: AuthorityPrincipal }>('/v1/authority/principals', input, { headers: mutationHeaders(options) }); }
  listPrincipals() { return this.client.get<{ principals: AuthorityPrincipal[] }>('/v1/authority/principals'); }
  getPrincipal(id: string) { return this.client.get<{ principal: AuthorityPrincipal }>(`/v1/authority/principals/${id}`); }
  archivePrincipal(id: string, reasonCode: string, options: AuthorityMutationOptions) { return this.client.post<{ principal: AuthorityPrincipal }>(`/v1/authority/principals/${id}/archive`, { reason_code: reasonCode }, { headers: mutationHeaders(options) }); }
  erasePrincipal(id: string, options: AuthorityMutationOptions) { return this.client.post<{ tombstone: AuthorityTombstone }>(`/v1/authority/principals/${id}/erase`, {}, { headers: mutationHeaders(options) }); }

  importProof(input: ImportAuthorityProofInput, options: AuthorityMutationOptions) { return this.client.post<{ proof: AuthorityProof }>('/v1/authority/proofs/import', input, { headers: mutationHeaders(options) }); }
  createProofCollectionSession(input: CreateAuthorityProofCollectionSessionInput, options: AuthorityMutationOptions) { return this.client.post<{ session: AuthoritySafeRecord }>('/v1/authority/proof-collection-sessions', input, { headers: mutationHeaders(options) }); }
  getProofCollectionSession(id: string) { return this.client.get<{ session: AuthoritySafeRecord }>(`/v1/authority/proof-collection-sessions/${id}`); }
  listProofs() { return this.client.get<{ proofs: AuthorityProof[] }>('/v1/authority/proofs'); }
  getProof(id: string, version?: number) { return this.client.get<{ proof: AuthorityProof }>(`/v1/authority/proofs/${id}`, versionQuery(version)); }
  revokeProof(id: string, reasonCode: string, options: AuthorityMutationOptions) { return this.client.post<{ proof: AuthorityProof }>(`/v1/authority/proofs/${id}/revoke`, { reason_code: reasonCode }, { headers: mutationHeaders(options) }); }
  eraseProof(id: string, options: AuthorityMutationOptions) { return this.client.post<{ proof: AuthorityProof }>(`/v1/authority/proofs/${id}/erase`, {}, { headers: mutationHeaders(options) }); }

  createBinding(input: CreateAuthorityBindingInput, options: AuthorityMutationOptions) { return this.client.post<{ binding: AuthorityBinding }>('/v1/authority/bindings', input, { headers: mutationHeaders(options) }); }
  listBindings() { return this.client.get<{ bindings: AuthorityBinding[] }>('/v1/authority/bindings'); }
  getBinding(id: string, version?: number) { return this.client.get<{ binding: AuthorityBinding }>(`/v1/authority/bindings/${id}`, versionQuery(version)); }
  createApprovalRequests(id: string, input: CreateAuthorityApprovalRequestsInput, options: AuthorityMutationOptions) { return this.client.post<{ approval_requests: AuthorityApprovalRequest[] }>(`/v1/authority/bindings/${id}/approval-requests`, input, { headers: mutationHeaders(options) }); }
  listApprovalRequests(id: string) { return this.client.get<{ approval_requests: AuthorityApprovalRequest[] }>(`/v1/authority/bindings/${id}/approval-requests`); }
  activateBinding(id: string, options: AuthorityMutationOptions, version?: number) { return this.client.post<{ binding: AuthorityBinding }>(`/v1/authority/bindings/${id}/activate${version === undefined ? '' : `?version=${encodeURIComponent(String(version))}`}`, {}, { headers: mutationHeaders(options) }); }
  delegateBinding(id: string, input: DelegateAuthorityBindingInput, options: AuthorityMutationOptions) { return this.client.post<{ binding: AuthorityBinding }>(`/v1/authority/bindings/${id}/delegate`, input, { headers: mutationHeaders(options) }); }
  revokeBinding(id: string, reasonCode: string, options: AuthorityMutationOptions) { return this.client.post<{ binding: AuthorityBinding }>(`/v1/authority/bindings/${id}/revoke`, { reason_code: reasonCode }, { headers: mutationHeaders(options) }); }
  eraseBinding(id: string, options: AuthorityMutationOptions) { return this.client.post<{ tombstone: AuthorityTombstone }>(`/v1/authority/bindings/${id}/erase`, {}, { headers: mutationHeaders(options) }); }

  createReceiver(input: CreateAuthorityReceiverInput, options: AuthorityMutationOptions) { return this.client.post<{ receiver: AuthorityReceiver }>('/v1/authority/receivers', input, { headers: mutationHeaders(options) }); }
  listReceivers() { return this.client.get<{ receivers: AuthorityReceiver[] }>('/v1/authority/receivers'); }
  getReceiver(id: string) { return this.client.get<{ receiver: AuthorityReceiver }>(`/v1/authority/receivers/${id}`); }
  createReceiverVerificationChallenge(id: string, options: AuthorityMutationOptions) { return this.client.post<{ challenge: AuthoritySafeRecord }>(`/v1/authority/receivers/${id}/verification-challenges`, {}, { headers: mutationHeaders(options) }); }
  verifyReceiver(id: string, options: AuthorityMutationOptions) { return this.client.post<{ receiver: AuthorityReceiver }>(`/v1/authority/receivers/${id}/verify`, {}, { headers: mutationHeaders(options) }); }
  addReceiverKey(id: string, input: AddAuthorityReceiverKeyInput, options: AuthorityMutationOptions) { return this.client.post<{ key: AuthoritySafeRecord }>(`/v1/authority/receivers/${id}/keys`, input, { headers: mutationHeaders(options) }); }
  revokeReceiverKey(id: string, keyId: string, reasonCode: string, options: AuthorityMutationOptions) { return this.client.post<{ key: AuthoritySafeRecord }>(`/v1/authority/receivers/${id}/keys/${keyId}/revoke`, { reason_code: reasonCode }, { headers: mutationHeaders(options) }); }

  createProfileVersion(input: CreateAuthorityProfileVersionInput, options: AuthorityMutationOptions) { return this.client.post<{ profile: AuthoritySafeRecord }>('/v1/authority/profile-versions', input, { headers: mutationHeaders(options) }); }
  activateProfileVersion(id: string, profileKind: 'proof' | 'domain' | 'receiver', options: AuthorityMutationOptions) { return this.client.post<{ profile: AuthoritySafeRecord }>(`/v1/authority/profile-versions/${id}/activate`, { profile_kind: profileKind }, { headers: mutationHeaders(options) }); }
  listUses() { return this.client.get<{ uses: AuthorityUse[] }>('/v1/authority/uses'); }
  getUse(id: string) { return this.client.get<{ use: AuthorityUse }>(`/v1/authority/uses/${id}`); }
  listPresentations() { return this.client.get<{ presentations: AuthorityPresentation[] }>('/v1/authority/presentations'); }
  getPresentation(id: string) { return this.client.get<{ presentation: AuthorityPresentation }>(`/v1/authority/presentations/${id}`); }
  erasePresentation(id: string, options: AuthorityMutationOptions) { return this.client.post<{ tombstone: AuthorityTombstone }>(`/v1/authority/presentations/${id}/erase`, {}, { headers: mutationHeaders(options) }); }
}
