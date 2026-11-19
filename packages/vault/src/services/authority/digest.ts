/** Canonical digests and commitment envelopes for authority artefacts. */
import { ForbiddenError, canonicalize, sha256 as rawSha256 } from '@stack/shared';
import { createHash, randomBytes } from 'node:crypto';
import type { AuthorityBindingProofRecord, AuthorityBindingRecord } from './records.js';

/** Canonical wire/storage digest representation for authority artefacts. */
export function sha256(value: string): string {
  return `sha256:${rawSha256(value)}`;
}

export function transactionRequestHash(
  receiverRequestId: string,
  normalizedRequest: unknown,
): string {
  return sha256(
    canonicalize({ receiver_request_id: receiverRequestId, normalized_request: normalizedRequest }),
  );
}

export function transactionResourceHash(receiverRequestId: string, resourceRef: string): string {
  return sha256(
    canonicalize({ receiver_request_id: receiverRequestId, resource_ref: resourceRef }),
  );
}

export function committedEnvelope(value: unknown): { plaintext: string; hash: string } {
  const plaintext = canonicalize({
    value,
    commitment_nonce: randomBytes(16).toString('base64url'),
  });
  return { plaintext, hash: sha256(plaintext) };
}

/** RFC 7638 canonical Ed25519 JWK thumbprint used in authority bindings. */
export function authorityAgentKeyThumbprint(jwk: { kty: string; crv: string; x: string }): string {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !/^[A-Za-z0-9_-]+$/.test(jwk.x)) {
    throw new ForbiddenError('authority agent keys must be public Ed25519 JWKs');
  }
  const canonical = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x });
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export function bindingDigest(
  binding: AuthorityBindingRecord,
  links: AuthorityBindingProofRecord[],
): string {
  return sha256(
    canonicalize({
      id: binding.id,
      version: binding.version,
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
      valid_from: binding.valid_from.toISOString(),
      expires_at: binding.expires_at.toISOString(),
      proofs: links
        .map((link) => ({
          proof_id: link.proof_id,
          proof_version: link.proof_version,
          role: link.role,
          authoriser_principal_id: link.authoriser_principal_id,
          group_key: link.group_key,
          weight: link.weight,
          required: link.required,
          ordinal: link.ordinal,
        }))
        .sort((a, b) => `${a.role}:${a.proof_id}`.localeCompare(`${b.role}:${b.proof_id}`)),
    }),
  );
}
