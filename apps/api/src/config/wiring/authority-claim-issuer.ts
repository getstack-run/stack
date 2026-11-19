import { createHash } from 'node:crypto';
import { canonicalize, sha256, type Database } from '@stack/shared';
import {
  PassportClaimsRepository,
  type AuthorityClaimIssuer,
  type ClaimRegistryService,
} from '@stack/vault';

function authorityDigest(value: string): string {
  return `sha256:${sha256(value)}`;
}

function authorityUnixSeconds(value: Date | null): number | null {
  return value ? Math.floor(value.getTime() / 1000) : null;
}

/**
 * Signs authority rail records (proofs, bindings, approvals, uses, receiver
 * receipts, erasure tombstones) as claims in the existing signed-claim
 * registry. Sensitive evidence and disclosure values never enter these
 * payloads; every digest below is already a canonical sha256:* commitment
 * computed by the vault.
 */
export function createAuthorityClaimIssuer(
  claimRegistry: ClaimRegistryService,
): AuthorityClaimIssuer {
  const registerAuthorityClaim = async (
    input: Parameters<ClaimRegistryService['registerClaim']>[0],
    transaction?: Parameters<AuthorityClaimIssuer['registerExternalProofVerificationClaim']>[1],
  ) => {
    const result = await claimRegistry.registerClaim(
      input,
      transaction
        ? { persistence: new PassportClaimsRepository(transaction as unknown as Database) }
        : undefined,
    );
    const envelopeBytes = Buffer.from(result.envelopeCose, 'base64url');
    return {
      claimId: result.claimId,
      claimHash: `sha256:${createHash('sha256').update(envelopeBytes).digest('hex')}`,
    };
  };

  return {
    registerExternalProofVerificationClaim: ({ operatorId, proof }, transaction) =>
      registerAuthorityClaim(
        {
          operatorId,
          subjectOverride: 'operator',
          claimType: 'external_proof_verification',
          payload: {
            type: 'external_proof_verification',
            proof_id: proof.id,
            proof_version: proof.version,
            subject_principal_id: proof.subject_principal_id,
            represented_principal_id: proof.represented_principal_id,
            profile_version_id: proof.profile_version_id,
            proof_kind: proof.proof_kind,
            source_kind: proof.source_kind,
            issuer_identifier: proof.issuer_identifier,
            issuer_key_thumbprint: proof.issuer_key_thumbprint,
            schema_uri: proof.schema_uri,
            schema_version: proof.schema_version,
            native_format: proof.native_format,
            native_evidence_hash: proof.native_evidence_hash,
            normalized_facts_hash: proof.normalized_facts_hash,
            verification_method: proof.verification_method,
            verifier_identifier: proof.verifier_identifier,
            verifier_version: proof.verifier_version,
            assurance_uri: proof.assurance_uri,
            verified_at: authorityUnixSeconds(proof.verified_at),
            valid_from: authorityUnixSeconds(proof.valid_from),
            expires_at: authorityUnixSeconds(proof.expires_at),
            status: proof.status,
          },
        },
        transaction,
      ),
    registerBindingClaim: ({ operatorId, binding, bindingDigest }, transaction) =>
      registerAuthorityClaim(
        {
          operatorId,
          subjectOverride: 'operator',
          claimType: 'authority_binding',
          payload: {
            type: 'authority_binding',
            binding_id: binding.id,
            binding_version: binding.version,
            binding_digest: bindingDigest,
            principal_id: binding.principal_id,
            agent_id: binding.agent_id,
            agent_key_thumbprint: binding.agent_key_thumbprint,
            receiver_id: binding.receiver_id,
            receiver_profile_version_id: binding.receiver_profile_version_id,
            domain_profile_version_id: binding.domain_profile_version_id,
            mission_ids: binding.mission_ids,
            lineage_root_id: binding.lineage_root_id,
            lineage_root_version: binding.lineage_root_version,
            parent_binding_id: binding.parent_binding_id,
            parent_binding_version: binding.parent_binding_version,
            delegation_depth: binding.delegation_depth,
            purpose_code: binding.purpose_code,
            purpose_hash: binding.purpose_hash,
            scope_hash: binding.scope_hash,
            approval_policy_hash: binding.approval_policy_hash,
            disclosure_policy_hash: binding.disclosure_policy_hash,
            delegation_policy_hash: binding.delegation_policy_hash,
            proof_set_hash: binding.proof_set_hash,
            valid_from: authorityUnixSeconds(binding.valid_from),
            expires_at: authorityUnixSeconds(binding.expires_at),
            status: binding.status,
          },
        },
        transaction,
      ),
    registerApprovalClaim: ({ operatorId, claim }, transaction) =>
      registerAuthorityClaim(
        {
          operatorId,
          subjectOverride: 'operator',
          claimType: 'authority_approval',
          payload: {
            type: 'authority_approval',
            ...claim,
            decided_at: authorityUnixSeconds(claim.decided_at),
            expires_at: authorityUnixSeconds(claim.expires_at),
            revoked_at: authorityUnixSeconds(claim.revoked_at),
          },
        },
        transaction,
      ),
    registerAuthorityUseClaim: (
      { operatorId, use, bindingDigest, domainProfileVersionId },
      transaction,
    ) =>
      registerAuthorityClaim(
        {
          operatorId,
          passportJti: use.passport_jti,
          claimType: 'authority_use',
          payload: {
            type: 'authority_use',
            authority_use_id: use.id,
            binding_id: use.binding_id,
            binding_version: use.binding_version,
            binding_digest: bindingDigest,
            passport_jti_hash: authorityDigest(use.passport_jti),
            mission_id: use.mission_id,
            agent_id: use.agent_id,
            agent_key_thumbprint: use.agent_key_thumbprint,
            receiver_id: use.receiver_id,
            receiver_profile_version_id: use.receiver_profile_version_id,
            domain_profile_version_id: domainProfileVersionId,
            receiver_request_id_hash: authorityDigest(use.receiver_request_id),
            action_uri: use.action_uri,
            resource_hash: use.resource_hash,
            request_hash: use.request_hash,
            effective_scope_hash: use.effective_scope_hash,
            proof_set_hash: use.proof_set_hash,
            disclosure_manifest_hash: authorityDigest(canonicalize(use.disclosure_manifest)),
            verification_mode: use.verification_mode,
            proof_strength: use.proof_strength,
            status: use.status,
            denial_code: use.denial_code,
            created_at: authorityUnixSeconds(use.created_at),
            completed_at: 'completed_at' in use ? authorityUnixSeconds(use.completed_at) : null,
            result_hash: 'result_hash' in use ? use.result_hash : null,
          },
        },
        transaction,
      ),
    registerReceiverReceiptClaim: (
      { operatorId, receipt, presentationPayloadHash, actionUri },
      transaction,
    ) =>
      registerAuthorityClaim(
        {
          operatorId,
          subjectOverride: 'operator',
          claimType: 'receiver_transaction_receipt',
          payload: {
            type: 'receiver_transaction_receipt',
            receipt_id: receipt.id,
            authority_use_id: receipt.authority_use_id,
            presentation_id: receipt.presentation_id,
            receiver_id: receipt.receiver_id,
            receiver_profile_version_id: receipt.receiver_profile_version_id,
            receiver_key_id: receipt.receiver_key_id,
            receipt_jti_hash: receipt.receipt_jti_hash,
            native_format: receipt.native_format,
            receipt_hash: receipt.receipt_hash,
            presentation_payload_hash: presentationPayloadHash,
            action_uri: actionUri,
            request_hash: receipt.request_hash,
            result_hash: receipt.result_hash,
            outcome: receipt.outcome,
            external_transaction_ref_hash: receipt.external_transaction_ref_hash,
            verified_at: authorityUnixSeconds(receipt.verified_at),
            received_at: authorityUnixSeconds(receipt.received_at),
          },
        },
        transaction,
      ),
    registerAuthorityErasureTombstone: ({ operatorId, tombstone, erasedAt }, transaction) =>
      registerAuthorityClaim(
        {
          operatorId,
          subjectOverride: 'operator',
          claimType: 'authority_erasure_tombstone',
          payload: {
            type: 'authority_erasure_tombstone',
            target_kind: tombstone.target_kind,
            target_id: tombstone.target_id,
            target_version: tombstone.target_version,
            prior_artifact_digest: tombstone.prior_artifact_digest,
            prior_claim_digest: tombstone.prior_claim_digest,
            tombstone_digest: tombstone.tombstone_digest,
            erased_at: authorityUnixSeconds(erasedAt),
          },
        },
        transaction,
      ),
  };
}
