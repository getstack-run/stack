/** Authority proofs: evidence import, legacy identity facades, listing and revocation. */
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  generateId,
  type AttachAuthorityProofInput,
} from '@stack/shared';
import type { AuthorityProofRecord } from './records.js';
import type { AuthorityServiceDeps, CreateLegacyIdentityProofFacadeInput } from './contracts.js';
import { AuthorityCore } from './core.js';
import { readFact } from './fact-path.js';
import { safeProof } from './redaction.js';
import { persistExternalNativeProof, signAndInsertProof } from './proof-persistence.js';
import { sha256 } from './digest.js';

function mappedAssuranceUris(mapping: unknown): Set<string> {
  const values = new Set<string>();
  const visit = (value: unknown): void => {
    if (typeof value === 'string') {
      values.add(value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value && typeof value === 'object')
      Object.values(value as Record<string, unknown>).forEach(visit);
  };
  visit(mapping);
  return values;
}

export class ProofService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(private readonly core: AuthorityCore) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async attachProof(operatorId: string, input: AttachAuthorityProofInput, idempotencyKey: string) {
    return this.core.idempotent(
      operatorId,
      'proof.attach',
      idempotencyKey,
      {
        ...input,
        native_evidence: sha256(input.native_evidence),
      },
      async (repo) => {
        const principal = await repo.findPrincipal(operatorId, input.subject_principal_id);
        if (!principal || principal.status !== 'active')
          throw new NotFoundError('AuthorityPrincipal', input.subject_principal_id);
        if (input.represented_principal_id) {
          const represented = await repo.findPrincipal(operatorId, input.represented_principal_id);
          if (!represented || represented.status !== 'active') {
            throw new NotFoundError('AuthorityPrincipal', input.represented_principal_id);
          }
        }

        const profile = await repo.findProofProfileVersion(operatorId, input.profile_version_id);
        if (!profile || profile.status !== 'active')
          throw new ForbiddenError('authority proof profile is unavailable');
        if (
          profile.proof_kind !== input.proof_kind ||
          profile.schema_uri !== input.schema_uri ||
          profile.schema_version !== input.schema_version ||
          !profile.accepted_native_formats.includes(input.native_format)
        )
          throw new ForbiddenError('authority proof does not match its immutable profile');

        const adapter = this.core.adapters.get(`${profile.adapter_key}@${profile.adapter_version}`);
        if (!adapter)
          throw new ServiceUnavailableError('required authority proof verifier is unavailable');
        const verified = await adapter.verify({
          nativeEvidence: input.native_evidence,
          nativeFormat: input.native_format,
          expectedIssuer: input.issuer_identifier,
          expectedSubjectPrincipalId: input.subject_principal_id,
          ...(input.represented_principal_id
            ? { expectedRepresentedPrincipalId: input.represented_principal_id }
            : {}),
          profile,
        });
        if (verified.issuerIdentifier !== input.issuer_identifier) {
          throw new ForbiddenError('authority proof issuer mismatch');
        }
        const proofConfig = profile.config_json;
        const validation = proofConfig.validation as Record<string, unknown>;
        const freshness = proofConfig.freshness as Record<string, unknown>;
        if (
          verified.assuranceUri &&
          !mappedAssuranceUris(proofConfig.assurance_mapping).has(verified.assuranceUri)
        ) {
          throw new ForbiddenError(
            'authority proof assurance is not mapped by the immutable profile',
          );
        }
        const acceptedIssuers = (validation.accepted_issuer_ids as string[]) ?? [];
        if (acceptedIssuers.length > 0 && !acceptedIssuers.includes(verified.issuerIdentifier)) {
          throw new ForbiddenError(
            'authority proof issuer is not accepted by the immutable profile',
          );
        }
        if (validation.signature_required === true && !verified.signatureVerified) {
          throw new ForbiddenError('authority proof signature was not verified');
        }
        const acceptedAlgs = (validation.accepted_signature_algs as string[]) ?? [];
        if (
          verified.signatureVerified &&
          (acceptedAlgs.length === 0 ||
            !verified.signatureAlgorithm ||
            !acceptedAlgs.includes(verified.signatureAlgorithm))
        ) {
          throw new ForbiddenError('authority proof signature algorithm is not accepted');
        }
        if (
          verified.subjectPrincipalId !== input.subject_principal_id ||
          (verified.representedPrincipalId ?? undefined) !== input.represented_principal_id
        ) {
          throw new ForbiddenError('authority proof subject binding mismatch');
        }
        for (const factPath of (validation.required_claim_paths as string[]) ?? []) {
          readFact(verified.normalizedFacts, factPath);
        }
        const verificationTime = this.now();
        if (verified.validFrom > verificationTime) {
          throw new ForbiddenError('authority proof is not yet valid');
        }
        if (verified.expiresAt && verified.expiresAt <= verificationTime) {
          throw new ForbiddenError('authority proof is expired');
        }
        const maxAgeSeconds = Number(freshness.maximum_age_seconds ?? 0);
        if (
          !Number.isFinite(maxAgeSeconds) ||
          maxAgeSeconds < 0 ||
          verified.verifiedAt.getTime() + maxAgeSeconds * 1000 < verificationTime.getTime()
        ) {
          throw new ForbiddenError('authority proof is older than its immutable profile permits');
        }
        if (
          freshness.live_status_required === true &&
          (!verified.statusFreshUntil || verified.statusFreshUntil <= verificationTime)
        ) {
          throw new ServiceUnavailableError('authority proof profile requires live issuer status');
        }

        const bindsMandateTerms = ['mandate', 'consent', 'signature'].includes(input.proof_kind);
        if (
          bindsMandateTerms &&
          (!verified.mandateTermsDigest ||
            !/^sha256:[0-9a-f]{64}$/.test(verified.mandateTermsDigest) ||
            (verified.normalizedFacts.mandate_terms_digest !== undefined &&
              verified.normalizedFacts.mandate_terms_digest !== verified.mandateTermsDigest))
        ) {
          throw new ForbiddenError('authority mandate proof has no canonical exact-terms digest');
        }
        const canonicalFacts = bindsMandateTerms
          ? { ...verified.normalizedFacts, mandate_terms_digest: verified.mandateTermsDigest }
          : verified.normalizedFacts;

        return safeProof(
          await persistExternalNativeProof(this.core, repo, {
            operatorId,
            subjectPrincipalId: input.subject_principal_id,
            representedPrincipalId: input.represented_principal_id,
            profileVersionId: input.profile_version_id,
            proofKind: input.proof_kind,
            schemaUri: input.schema_uri,
            schemaVersion: input.schema_version,
            nativeFormat: input.native_format,
            nativeEvidence: input.native_evidence,
            facts: canonicalFacts,
            verified,
          }),
        );
      },
      201,
    );
  }

  /** Direct evidence import. Caller supplies native bytes, never verification results. */
  async importProof(operatorId: string, input: AttachAuthorityProofInput, idempotencyKey: string) {
    return this.attachProof(operatorId, input, idempotencyKey);
  }

  async createLegacyIdentityProofFacade(
    operatorId: string,
    input: CreateLegacyIdentityProofFacadeInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      'proof.legacy-facade.create',
      idempotencyKey,
      input,
      async (repo) => {
        const [principal, legacy, profile] = await Promise.all([
          repo.findPrincipal(operatorId, input.subject_principal_id),
          repo.findLegacyIdentityClaim(operatorId, input.identity_claim_id),
          repo.findProofProfileVersion(operatorId, input.profile_version_id),
        ]);
        if (!principal || principal.status !== 'active')
          throw new NotFoundError('AuthorityPrincipal', input.subject_principal_id);
        if (!legacy || legacy.expires_at <= this.now() || legacy.layer !== 'identity') {
          throw new ForbiddenError(
            'legacy identity claim is unavailable, expired, or not identity evidence',
          );
        }
        if (!profile || profile.status !== 'active' || profile.proof_kind !== 'identity') {
          throw new ForbiddenError('legacy identity proof profile is unavailable or incompatible');
        }
        const adapter = this.core.adapters.get(`${profile.adapter_key}@${profile.adapter_version}`);
        if (
          !adapter?.bindLegacyIdentitySubject ||
          !(await adapter.bindLegacyIdentitySubject({
            operatorId,
            identityClaimId: legacy.id,
            signedClaimId: legacy.signed_claim_id,
            subjectPrincipalId: principal.id,
            profile,
          }))
        ) {
          throw new ForbiddenError(
            'legacy identity claim is not authoritatively bound to the selected principal',
          );
        }
        const validation = profile.config_json.validation as Record<string, unknown>;
        const acceptedIssuers = (validation.accepted_issuer_ids as string[]) ?? [];
        if (!acceptedIssuers.includes(legacy.provider_key))
          throw new ForbiddenError('legacy identity issuer is not accepted by the profile');
        const prior = await repo.findLegacyProofFacade(
          operatorId,
          legacy.id,
          principal.id,
          profile.id,
        );
        if (prior?.status === 'active') return safeProof(prior);
        const id = prior?.id ?? generateId('prf');
        const version = (prior?.version ?? 0) + 1;
        const now = this.now();
        const unsigned: AuthorityProofRecord = {
          id,
          version,
          operator_id: operatorId,
          subject_principal_id: principal.id,
          represented_principal_id: null,
          profile_version_id: profile.id,
          proof_kind: 'identity',
          source_kind: 'legacy_identity_claim',
          legacy_identity_claim_id: legacy.id,
          issuer_identifier: legacy.provider_key,
          issuer_key_thumbprint: null,
          original_relying_party_identifier: null,
          schema_uri: profile.schema_uri,
          schema_version: profile.schema_version,
          native_format: 'stack/legacy-identity-claim-ref',
          native_evidence_encrypted: null,
          normalized_facts_encrypted: null,
          native_evidence_hash: legacy.signed_claim_hash,
          normalized_facts_hash: null,
          verification_method: 'stack:legacy-identity-facade',
          verifier_identifier: 'stack:identity-claim-registry',
          verifier_version: '1',
          assurance_uri: `stack:assurance:${legacy.assurance_level}`,
          verified_at: legacy.verified_at,
          valid_from: legacy.verified_at,
          expires_at: legacy.expires_at,
          status: 'active',
          status_fresh_until: legacy.expires_at,
          last_status_result: 'valid',
          last_status_checked_at: now,
          claim_id: null,
          created_at: now,
          revoked_at: null,
          revoked_reason: null,
          erased_at: null,
          tombstone_hash: null,
          tombstone_claim_id: null,
          supersedes_version: prior?.version ?? null,
        };
        return safeProof(
          await signAndInsertProof(this.core, repo, operatorId, unsigned, {
            signing: 'legacy identity facade signing is unavailable',
            claim: 'legacy identity facade claim is unavailable',
          }),
        );
      },
      201,
    );
  }

  async invalidateLegacyIdentityClaim(operatorId: string, identityClaimId: string, reason: string) {
    const facades = await this.deps.repo.listLegacyProofFacades(operatorId, identityClaimId);
    const passportJtis = new Set<string>();
    for (const facade of facades) {
      await this.deps.repo.transitionProof({
        operatorId,
        proofId: facade.id,
        from: ['pending', 'active', 'suspended'],
        to: 'revoked',
        now: this.now(),
        reason,
      });
      const cascade = await this.deps.repo.cascadeProofInvalidation(
        operatorId,
        facade.id,
        this.now(),
        reason,
      );
      cascade.passportJtis.forEach((jti) => passportJtis.add(jti));
    }
    await this.deps.passportRevocationPublisher.publishAuthorityRevocations(
      [...passportJtis],
      reason,
    );
  }

  async listProofs(operatorId: string) {
    return (await this.deps.repo.listProofs(operatorId)).map(safeProof);
  }

  async getProof(operatorId: string, proofId: string, version?: number) {
    const row = await this.deps.repo.findProof(operatorId, proofId, version);
    if (!row) throw new NotFoundError('AuthorityProof', proofId);
    return safeProof(row);
  }

  async revokeProof(operatorId: string, proofId: string, reason: string, idempotencyKey: string) {
    return this.core.idempotent(
      operatorId,
      `proof.revoke:${proofId}`,
      idempotencyKey,
      { reason },
      async (repo) => {
        const now = this.now();
        const row = await repo.transitionProof({
          operatorId,
          proofId,
          from: ['pending', 'active', 'suspended'],
          to: 'revoked',
          now,
          reason,
        });
        if (!row) throw new NotFoundError('AuthorityProof', proofId);
        const cascade = await repo.cascadeProofInvalidation(
          operatorId,
          proofId,
          now,
          'required_proof_revoked',
        );
        await this.deps.passportRevocationPublisher
          .publishAuthorityRevocations(cascade.passportJtis, reason)
          .catch(() => {
            throw new ServiceUnavailableError('authority Passport revocation propagation failed');
          });
        return safeProof(row);
      },
    );
  }
}
