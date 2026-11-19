import { z } from 'zod';
import { AuthorityProofKind, Sha256Digest } from '../authority.js';

const opaqueId = (prefix: string) => z.string().regex(
  new RegExp(`^${prefix}_[\\w-]+$`),
  `id must be ${prefix}_*`,
);
const UnixSeconds = z.number().int().nonnegative();
const OptionalExpiry = UnixSeconds.nullable();
const ActionIdentifier = z.string().min(1).max(1024)
  .regex(/^[A-Za-z][A-Za-z0-9._:/-]*$/, 'must be a machine-readable action identifier')
  .refine((value) => !/\d{6,}/.test(value), 'must not contain identifier-like digit runs');

/** PII-free proof verification provenance. Native evidence remains encrypted at rest. */
export const ExternalProofVerificationClaim = z.object({
  type: z.literal('external_proof_verification'),
  proof_id: opaqueId('prf'),
  proof_version: z.number().int().positive(),
  subject_principal_id: opaqueId('prn'),
  represented_principal_id: opaqueId('prn').nullable(),
  profile_version_id: opaqueId('apv'),
  proof_kind: AuthorityProofKind,
  source_kind: z.enum(['legacy_identity_claim', 'external_native', 'stack_derived']),
  issuer_identifier: z.string().min(1).max(1024),
  issuer_key_thumbprint: Sha256Digest.nullable(),
  schema_uri: z.string().min(1).max(1024),
  schema_version: z.string().min(1).max(128),
  native_format: z.string().min(1).max(128),
  native_evidence_hash: Sha256Digest,
  normalized_facts_hash: Sha256Digest.nullable(),
  verification_method: z.string().min(1).max(256),
  verifier_identifier: z.string().min(1).max(1024),
  verifier_version: z.string().min(1).max(128),
  assurance_uri: z.string().min(1).max(1024).nullable(),
  verified_at: UnixSeconds,
  valid_from: UnixSeconds,
  expires_at: OptionalExpiry,
  status: z.enum(['pending', 'active', 'suspended', 'revoked', 'replaced', 'erased']),
}).strict();
export type ExternalProofVerificationClaim = z.infer<typeof ExternalProofVerificationClaim>;

/** Signed, non-PII commitment to an immutable authority binding version. */
export const AuthorityBindingClaim = z.object({
  type: z.literal('authority_binding'),
  binding_id: opaqueId('abn'),
  binding_version: z.number().int().positive(),
  binding_digest: Sha256Digest,
  principal_id: opaqueId('prn'),
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/),
  agent_key_thumbprint: Sha256Digest,
  receiver_id: opaqueId('rcv'),
  receiver_profile_version_id: opaqueId('apv'),
  domain_profile_version_id: opaqueId('apv').nullable(),
  mission_ids: z.array(opaqueId('ms')).max(64),
  lineage_root_id: opaqueId('abn'),
  lineage_root_version: z.number().int().positive(),
  parent_binding_id: opaqueId('abn').nullable(),
  parent_binding_version: z.number().int().positive().nullable(),
  delegation_depth: z.number().int().min(0).max(4),
  purpose_code: z.string().min(1).max(256),
  purpose_hash: Sha256Digest,
  scope_hash: Sha256Digest,
  approval_policy_hash: Sha256Digest,
  disclosure_policy_hash: Sha256Digest,
  delegation_policy_hash: Sha256Digest,
  proof_set_hash: Sha256Digest,
  valid_from: UnixSeconds,
  expires_at: UnixSeconds,
  status: z.enum(['draft', 'pending_approval', 'active', 'suspended', 'revoked', 'replaced']),
}).strict();
export type AuthorityBindingClaim = z.infer<typeof AuthorityBindingClaim>;

/** Signed approval or rejection of one exact authority request digest. */
export const AuthorityApprovalClaim = z.object({
  type: z.literal('authority_approval'),
  decision_id: opaqueId('apd'),
  request_id: opaqueId('apr'),
  binding_id: opaqueId('abn'),
  binding_version: z.number().int().positive(),
  authority_use_id: opaqueId('aus').nullable(),
  authoriser_principal_id: opaqueId('prn'),
  identity_proof_id: opaqueId('prf'),
  identity_proof_version: z.number().int().positive(),
  capacity_proof_id: opaqueId('prf').nullable(),
  capacity_proof_version: z.number().int().positive().nullable(),
  decision_proof_id: opaqueId('prf'),
  decision_proof_version: z.number().int().positive(),
  decision: z.enum(['approve', 'reject']),
  weight: z.number().int().positive(),
  request_hash: Sha256Digest,
  phase: z.enum(['activation', 'action', 'presentation']),
  group_key_hash: Sha256Digest,
  approval_requirement_hash: Sha256Digest,
  decided_at: UnixSeconds,
  expires_at: OptionalExpiry,
  revoked_at: OptionalExpiry,
}).strict();
export type AuthorityApprovalClaim = z.infer<typeof AuthorityApprovalClaim>;

/** PII-free record that an exact action was evaluated under a binding. */
export const AuthorityUseClaim = z.object({
  type: z.literal('authority_use'),
  authority_use_id: opaqueId('aus'),
  binding_id: opaqueId('abn'),
  binding_version: z.number().int().positive(),
  binding_digest: Sha256Digest,
  passport_jti_hash: Sha256Digest,
  mission_id: opaqueId('ms').nullable(),
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/),
  agent_key_thumbprint: Sha256Digest,
  receiver_id: opaqueId('rcv'),
  receiver_profile_version_id: opaqueId('apv'),
  domain_profile_version_id: opaqueId('apv').nullable(),
  receiver_request_id_hash: Sha256Digest,
  action_uri: ActionIdentifier,
  resource_hash: Sha256Digest.nullable(),
  request_hash: Sha256Digest,
  effective_scope_hash: Sha256Digest,
  proof_set_hash: Sha256Digest,
  disclosure_manifest_hash: Sha256Digest,
  verification_mode: z.enum(['native_receiver', 'proxy_mediated']),
  proof_strength: z.enum([
    'native_issuer_evidence',
    'native_stack_attestation',
    'proxy_stack_enforced',
  ]),
  status: z.enum(['pending', 'waiting_approval', 'authorized', 'denied', 'dispatched', 'succeeded', 'failed']),
  denial_code: z.string().max(128).nullable(),
  created_at: UnixSeconds,
  completed_at: OptionalExpiry,
  result_hash: Sha256Digest.nullable(),
}).strict();
export type AuthorityUseClaim = z.infer<typeof AuthorityUseClaim>;

/** Receiver-signed transaction outcome; native receipt bytes stay encrypted at rest. */
export const ReceiverTransactionReceiptClaim = z.object({
  type: z.literal('receiver_transaction_receipt'),
  receipt_id: opaqueId('rtr'),
  authority_use_id: opaqueId('aus'),
  presentation_id: opaqueId('prs').nullable(),
  receiver_id: opaqueId('rcv'),
  receiver_profile_version_id: opaqueId('apv'),
  receiver_key_id: opaqueId('rky'),
  receipt_jti_hash: Sha256Digest,
  native_format: z.string().min(1).max(128),
  receipt_hash: Sha256Digest,
  presentation_payload_hash: Sha256Digest,
  action_uri: ActionIdentifier,
  request_hash: Sha256Digest,
  result_hash: Sha256Digest.nullable(),
  outcome: z.enum(['accepted', 'rejected', 'failed']),
  external_transaction_ref_hash: Sha256Digest.nullable(),
  verified_at: UnixSeconds,
  received_at: UnixSeconds,
}).strict();
export type ReceiverTransactionReceiptClaim = z.infer<typeof ReceiverTransactionReceiptClaim>;

/**
 * PII-free proof that an authority artifact's sensitive payload was erased.
 * The signed claim preserves only opaque references and high-entropy digests.
 */
export const AuthorityErasureTombstoneClaim = z.object({
  type: z.literal('authority_erasure_tombstone'),
  target_kind: z.enum([
    'principal',
    'binding',
    'proof',
    'presentation',
    'receiver_transaction_receipt',
  ]),
  target_id: z.string().regex(/^(prn|abn|prf|prs|rtr)_[\w-]+$/),
  target_version: z.number().int().positive().nullable(),
  prior_artifact_digest: Sha256Digest,
  prior_claim_digest: Sha256Digest.nullable(),
  tombstone_digest: Sha256Digest,
  erased_at: UnixSeconds,
}).strict().superRefine((claim, ctx) => {
  const expectedPrefix = {
    principal: 'prn_',
    binding: 'abn_',
    proof: 'prf_',
    presentation: 'prs_',
    receiver_transaction_receipt: 'rtr_',
  }[claim.target_kind];
  if (!claim.target_id.startsWith(expectedPrefix)) {
    ctx.addIssue({
      code: 'custom',
      path: ['target_id'],
      message: `target_id must use ${expectedPrefix} for ${claim.target_kind}`,
    });
  }
  const versioned = claim.target_kind === 'binding' || claim.target_kind === 'proof';
  if (versioned !== (claim.target_version !== null)) {
    ctx.addIssue({
      code: 'custom',
      path: ['target_version'],
      message: versioned
        ? 'target_version is required for versioned authority artifacts'
        : 'target_version must be null for unversioned authority artifacts',
    });
  }
});
export type AuthorityErasureTombstoneClaim = z.infer<typeof AuthorityErasureTombstoneClaim>;
