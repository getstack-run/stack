/** The single path by which a verified authority proof is committed, signed and stored. */
import { ServiceUnavailableError, canonicalize, generateId } from '@stack/shared';
import { randomBytes } from 'node:crypto';
import type { AuthorityProofRecord } from './records.js';
import type { VerifiedAuthorityProof } from './contracts.js';
import type { AuthorityRepositoryPort } from './port.js';
import type { AuthorityCore } from './core.js';
import { proofContext } from './kms-context.js';
import { sha256 } from './digest.js';

/** What a native proof says about itself, as pinned by the profile that verified it. */
export interface ExternalNativeProofInput {
  operatorId: string;
  subjectPrincipalId: string;
  representedPrincipalId: string | undefined;
  profileVersionId: string;
  proofKind: AuthorityProofRecord['proof_kind'];
  schemaUri: string;
  schemaVersion: string;
  nativeFormat: string;
  nativeEvidence: string;
  /** The normalized facts to commit; callers may extend the adapter's facts. */
  facts: Record<string, unknown>;
  verified: VerifiedAuthorityProof;
}

/** Refusals raised when the verification claim cannot be signed or comes back unusable. */
export interface ProofClaimFailureMessages {
  signing: string;
  claim: string;
}

const EXTERNAL_PROOF_CLAIM_FAILURES: ProofClaimFailureMessages = {
  signing: 'external proof verification signing is unavailable',
  claim: 'external proof verification claim is unavailable',
};

/**
 * Registers the signed verification claim for `unsigned` and inserts the proof
 * carrying that claim id. A failed or empty claim never leaves a stored proof.
 */
export async function signAndInsertProof(
  core: AuthorityCore,
  repo: AuthorityRepositoryPort,
  operatorId: string,
  unsigned: AuthorityProofRecord,
  failures: ProofClaimFailureMessages,
): Promise<AuthorityProofRecord> {
  const signed = await core.deps.claimIssuer
    .registerExternalProofVerificationClaim(
      { operatorId, proof: unsigned },
      repo.currentTransaction(),
    )
    .catch(() => {
      throw new ServiceUnavailableError(failures.signing);
    });
  if (!signed.claimId || !signed.claimHash) throw new ServiceUnavailableError(failures.claim);
  return repo.insertProof({ ...unsigned, claim_id: signed.claimId });
}

/**
 * Commits native evidence and normalized facts under nonce-bound envelopes,
 * encrypts both to the proof, signs the verification claim and stores the
 * version-1 proof.
 */
export async function persistExternalNativeProof(
  core: AuthorityCore,
  repo: AuthorityRepositoryPort,
  input: ExternalNativeProofInput,
): Promise<AuthorityProofRecord> {
  const { operatorId, verified } = input;
  const id = generateId('prf');
  const version = 1;
  const nativeEnvelope = canonicalize({
    evidence: input.nativeEvidence,
    commitment_nonce: randomBytes(16).toString('base64url'),
  });
  const factsEnvelope = canonicalize({
    facts: input.facts,
    commitment_nonce: randomBytes(16).toString('base64url'),
  });
  const [nativeEncrypted, factsEncrypted] = await Promise.all([
    core.deps.kms.encrypt(
      nativeEnvelope,
      proofContext(operatorId, id, version, 'authority_proof_native'),
    ),
    core.deps.kms.encrypt(
      factsEnvelope,
      proofContext(operatorId, id, version, 'authority_proof_facts'),
    ),
  ]);
  const unsigned: AuthorityProofRecord = {
    id,
    version,
    operator_id: operatorId,
    subject_principal_id: input.subjectPrincipalId,
    represented_principal_id: input.representedPrincipalId ?? null,
    profile_version_id: input.profileVersionId,
    proof_kind: input.proofKind,
    source_kind: 'external_native',
    legacy_identity_claim_id: null,
    issuer_identifier: verified.issuerIdentifier,
    issuer_key_thumbprint: verified.issuerKeyThumbprint ?? null,
    original_relying_party_identifier: null,
    schema_uri: input.schemaUri,
    schema_version: input.schemaVersion,
    native_format: input.nativeFormat,
    native_evidence_encrypted: nativeEncrypted.ciphertext,
    normalized_facts_encrypted: factsEncrypted.ciphertext,
    native_evidence_hash: sha256(nativeEnvelope),
    normalized_facts_hash: sha256(factsEnvelope),
    verification_method: verified.verificationMethod,
    verifier_identifier: verified.verifierIdentifier,
    verifier_version: verified.verifierVersion,
    assurance_uri: verified.assuranceUri ?? null,
    verified_at: verified.verifiedAt,
    valid_from: verified.validFrom,
    expires_at: verified.expiresAt ?? null,
    status: 'active',
    status_fresh_until: verified.statusFreshUntil ?? null,
    last_status_result: 'valid',
    last_status_checked_at: verified.statusFreshUntil ? verified.verifiedAt : null,
    claim_id: null,
    created_at: core.now(),
    revoked_at: null,
    revoked_reason: null,
    erased_at: null,
    tombstone_hash: null,
    tombstone_claim_id: null,
    supersedes_version: null,
  };
  return signAndInsertProof(core, repo, operatorId, unsigned, EXTERNAL_PROOF_CLAIM_FAILURES);
}
