import { createHash } from 'node:crypto';
import { PassportClaimsRepository, type AuthorityClaimIssuer, type ClaimRegistryService } from '@stack/vault';
import { canonicalize, sha256 } from '@stack/shared';
import type { WorkerDb } from '../redis.js';

/**
 * Issues the signed `authority_use` claim when a runtime authority use
 * completes. Registration can run inside the caller's transaction, in which case
 * the claim row is written through that transaction's connection.
 */
export function createRuntimeAuthorityUseClaimIssuer(
  claimRegistry: ClaimRegistryService,
): Pick<AuthorityClaimIssuer, 'registerAuthorityUseClaim'> {
  return {
    async registerAuthorityUseClaim(
      { operatorId, use, bindingDigest, domainProfileVersionId },
      transaction,
    ) {
      const result = await claimRegistry.registerClaim(
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
            passport_jti_hash: `sha256:${sha256(use.passport_jti)}`,
            mission_id: use.mission_id,
            agent_id: use.agent_id,
            agent_key_thumbprint: use.agent_key_thumbprint,
            receiver_id: use.receiver_id,
            receiver_profile_version_id: use.receiver_profile_version_id,
            domain_profile_version_id: domainProfileVersionId,
            receiver_request_id_hash: `sha256:${sha256(use.receiver_request_id)}`,
            action_uri: use.action_uri,
            resource_hash: use.resource_hash,
            request_hash: use.request_hash,
            effective_scope_hash: use.effective_scope_hash,
            proof_set_hash: use.proof_set_hash,
            disclosure_manifest_hash: `sha256:${sha256(canonicalize(use.disclosure_manifest))}`,
            verification_mode: use.verification_mode,
            proof_strength: use.proof_strength,
            status: use.status,
            denial_code: use.denial_code,
            created_at: Math.floor(use.created_at.getTime() / 1000),
            completed_at:
              'completed_at' in use && use.completed_at
                ? Math.floor(use.completed_at.getTime() / 1000)
                : null,
            result_hash: 'result_hash' in use ? use.result_hash : null,
          },
        },
        transaction
          ? {
              persistence: new PassportClaimsRepository(
                transaction as unknown as WorkerDb,
              ),
            }
          : undefined,
      );
      return {
        claimId: result.claimId,
        claimHash: `sha256:${createHash('sha256')
          .update(Buffer.from(result.envelopeCose, 'base64url'))
          .digest('hex')}`,
      };
    },
  };
}
