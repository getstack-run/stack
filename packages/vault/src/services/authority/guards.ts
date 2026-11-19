/** Usability guards and encrypted-commitment readers shared by every binding-facing flow. */
import {
  ForbiddenError,
  ServiceUnavailableError,
  canonicalize,
  type AuthorityDisclosurePolicy,
  type AuthorityReference,
  type AuthorityScope,
} from '@stack/shared';
import type { AuthorityBindingRecord, AuthorityProofRecord } from './records.js';
import type { AuthorityRepositoryPort } from './port.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import { bindingContext, proofContext } from './kms-context.js';
import { bindingDigest, sha256 } from './digest.js';

export class AuthorityGuards {
  private readonly deps: AuthorityServiceDeps;

  constructor(core: AuthorityCore) {
    this.deps = core.deps;
  }

  async assertProofUsable(
    repo: AuthorityRepositoryPort,
    proof: AuthorityProofRecord,
    now: Date,
    lineage: Set<string> = new Set<string>(),
  ): Promise<void> {
    const proofKey = `${proof.id}:${proof.version}`;
    if (lineage.has(proofKey))
      throw new ForbiddenError('authority proof dependency cycle is invalid');
    lineage.add(proofKey);
    if (proof.status !== 'active')
      throw new ForbiddenError(`required authority proof is ${proof.status}`);
    if (proof.valid_from > now)
      throw new ForbiddenError('required authority proof is not yet valid');
    if (proof.expires_at && proof.expires_at <= now)
      throw new ForbiddenError('required authority proof expired');
    const profile = await repo.findProofProfileVersion(proof.operator_id, proof.profile_version_id);
    if (!profile || profile.status !== 'active')
      throw new ForbiddenError('required authority proof profile is unavailable');
    const freshness = profile.config_json.freshness as Record<string, unknown>;
    const maximumAgeSeconds = Number(freshness.maximum_age_seconds ?? 0);
    if (
      !Number.isFinite(maximumAgeSeconds) ||
      maximumAgeSeconds < 0 ||
      proof.verified_at.getTime() + maximumAgeSeconds * 1000 < now.getTime()
    ) {
      throw new ForbiddenError('required authority proof exceeds its maximum age');
    }
    if (freshness.live_status_required === true) {
      if (
        proof.last_status_result !== 'valid' ||
        !proof.last_status_checked_at ||
        !proof.status_fresh_until ||
        proof.status_fresh_until <= now
      ) {
        throw new ServiceUnavailableError(
          'required authority proof live status is unavailable or stale',
        );
      }
    } else if (proof.last_status_result === 'revoked') {
      throw new ForbiddenError('required authority proof was revoked by its issuer');
    }
    if (!proof.native_evidence_encrypted && proof.source_kind !== 'legacy_identity_claim') {
      throw new ForbiddenError('required authority proof evidence is unavailable');
    }
    if (proof.source_kind === 'legacy_identity_claim') {
      if (
        !proof.legacy_identity_claim_id ||
        !(await repo.findLegacyIdentityClaim(proof.operator_id, proof.legacy_identity_claim_id))
      ) {
        throw new ForbiddenError('source legacy identity claim is unavailable or revoked');
      }
    }
    const sources =
      typeof repo.listProofSources === 'function'
        ? await repo.listProofSources(proof.operator_id, proof.id, proof.version)
        : [];
    for (const source of sources) {
      await this.assertProofUsable(repo, source, now, lineage);
    }
    lineage.delete(proofKey);
  }

  async assertBindingUsable(
    repo: AuthorityRepositoryPort,
    binding: AuthorityBindingRecord,
    now: Date,
    options: { requireActive?: boolean; lineage?: Set<string> } = {},
  ): Promise<void> {
    const lineage = options.lineage ?? new Set<string>();
    const lineageKey = `${binding.id}:${binding.version}`;
    if (lineage.has(lineageKey) || lineage.size > 4)
      throw new ForbiddenError('authority delegation lineage is invalid');
    lineage.add(lineageKey);
    if ((options.requireActive ?? true) && binding.status !== 'active') {
      throw new ForbiddenError(`authority binding is ${binding.status}`);
    }
    if (binding.valid_from > now || binding.expires_at <= now)
      throw new ForbiddenError('authority binding is outside its validity window');
    const principal = await repo.findPrincipal(binding.operator_id, binding.principal_id);
    if (!principal || principal.status !== 'active')
      throw new ForbiddenError('authority principal is unavailable');
    const key = await repo.resolveCurrentAgentKey(binding.operator_id, binding.agent_id);
    if (!key?.active || key.thumbprint !== binding.agent_key_thumbprint) {
      throw new ForbiddenError('authority agent key is no longer current');
    }
    const receiver = await repo.findReceiver(binding.operator_id, binding.receiver_id);
    if (
      !receiver ||
      receiver.status !== 'active' ||
      receiver.current_profile_version_id !== binding.receiver_profile_version_id
    ) {
      throw new ForbiddenError('authority receiver or profile is unavailable');
    }
    const profile = await repo.findReceiverProfile(
      binding.operator_id,
      binding.receiver_profile_version_id,
    );
    if (!profile || profile.status !== 'active')
      throw new ForbiddenError('authority receiver profile is unavailable');
    for (const missionId of binding.mission_ids) {
      if (!(await repo.isMissionActive(binding.operator_id, missionId))) {
        throw new ForbiddenError('authority Mission is unavailable');
      }
    }
    const links = await repo.listBindingProofs(binding.operator_id, binding.id, binding.version);
    for (const link of links.filter((item) => item.required)) {
      const proof = await repo.findProof(binding.operator_id, link.proof_id, link.proof_version);
      if (!proof) throw new ForbiddenError('required authority proof is unavailable');
      await this.assertProofUsable(repo, proof, now);
    }
    if (binding.parent_binding_id) {
      const parent = await repo.findBinding(
        binding.operator_id,
        binding.parent_binding_id,
        binding.parent_binding_version ?? undefined,
      );
      if (!parent || parent.status !== 'active')
        throw new ForbiddenError('authority parent binding is unavailable');
      await this.assertBindingUsable(repo, parent, now, { requireActive: true, lineage });
    }
  }

  async decryptBindingScope(binding: AuthorityBindingRecord): Promise<AuthorityScope> {
    if (!binding.scope_encrypted)
      throw new ForbiddenError('authority binding scope is unavailable');
    return this.decryptCommittedBindingValue<AuthorityScope>(
      binding.scope_encrypted,
      bindingContext(binding.operator_id, binding.id, binding.version, 'authority_binding_scope'),
      binding.scope_hash,
    );
  }

  async decryptBindingDisclosure(
    binding: AuthorityBindingRecord,
  ): Promise<AuthorityDisclosurePolicy> {
    if (!binding.disclosure_policy_encrypted)
      throw new ForbiddenError('authority binding disclosure policy is unavailable');
    return this.decryptCommittedBindingValue<AuthorityDisclosurePolicy>(
      binding.disclosure_policy_encrypted,
      bindingContext(
        binding.operator_id,
        binding.id,
        binding.version,
        'authority_binding_disclosure',
      ),
      binding.disclosure_policy_hash,
    );
  }

  async decryptBindingApproval(binding: AuthorityBindingRecord): Promise<Record<string, unknown>> {
    if (!binding.approval_policy_encrypted)
      throw new ForbiddenError('authority binding approval policy is unavailable');
    return this.decryptCommittedBindingValue<Record<string, unknown>>(
      binding.approval_policy_encrypted,
      bindingContext(
        binding.operator_id,
        binding.id,
        binding.version,
        'authority_binding_approval',
      ),
      binding.approval_policy_hash,
    );
  }

  private async decryptCommittedBindingValue<T>(
    ciphertext: string,
    context: Record<string, string>,
    expectedHash: string,
  ): Promise<T> {
    const plaintext = await this.deps.kms.decrypt(ciphertext, context);
    if (sha256(plaintext) !== expectedHash)
      throw new ForbiddenError('authority binding commitment mismatch');
    let envelope: unknown;
    try {
      envelope = JSON.parse(plaintext);
    } catch {
      throw new ForbiddenError('authority binding commitment envelope is invalid');
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      throw new ForbiddenError('authority binding commitment envelope is invalid');
    }
    const record = envelope as Record<string, unknown>;
    if (
      typeof record.commitment_nonce !== 'string' ||
      !/^[A-Za-z0-9_-]{22,}$/.test(record.commitment_nonce) ||
      !Object.prototype.hasOwnProperty.call(record, 'value')
    ) {
      throw new ForbiddenError('authority binding commitment envelope is invalid');
    }
    return record.value as T;
  }

  async reencryptBindingCommitment(
    ciphertext: string,
    sourceContext: Record<string, string>,
    expectedHash: string,
    targetContext: Record<string, string>,
  ): Promise<{ ciphertext: string }> {
    const plaintext = await this.deps.kms.decrypt(ciphertext, sourceContext);
    if (sha256(plaintext) !== expectedHash)
      throw new ForbiddenError('authority binding commitment mismatch');
    return this.deps.kms.encrypt(plaintext, targetContext);
  }

  async authorityReference(binding: AuthorityBindingRecord): Promise<AuthorityReference> {
    if (!binding.claim_id) throw new ForbiddenError('authority binding has no signed claim');
    const links = await this.deps.repo.listBindingProofs(
      binding.operator_id,
      binding.id,
      binding.version,
    );
    return {
      binding_id: binding.id,
      binding_version: binding.version,
      binding_claim_id: binding.claim_id,
      binding_digest: bindingDigest(binding, links),
      receiver_id: binding.receiver_id,
      receiver_profile_version_id: binding.receiver_profile_version_id,
      expires_at: Math.floor(binding.expires_at.getTime() / 1000),
    };
  }

  async assertReferenceMatches(
    binding: AuthorityBindingRecord,
    ref: AuthorityReference,
  ): Promise<void> {
    const expected = await this.authorityReference(binding);
    if (canonicalize(expected) !== canonicalize(ref)) {
      throw new ForbiddenError('authority reference does not match the immutable binding');
    }
  }

  async decryptProofFactEnvelope(proof: AuthorityProofRecord): Promise<{
    facts: Record<string, unknown>;
    commitmentNonce: string;
  }> {
    if (!proof.normalized_facts_encrypted || !proof.normalized_facts_hash) {
      throw new ForbiddenError('normalized proof facts are unavailable');
    }
    const plaintext = await this.deps.kms.decrypt(
      proof.normalized_facts_encrypted,
      proofContext(proof.operator_id, proof.id, proof.version, 'authority_proof_facts'),
    );
    if (sha256(plaintext) !== proof.normalized_facts_hash) {
      throw new ForbiddenError('normalized proof facts commitment mismatch');
    }
    let envelope: unknown;
    try {
      envelope = JSON.parse(plaintext);
    } catch {
      throw new ForbiddenError('normalized proof facts envelope is invalid');
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      throw new ForbiddenError('normalized proof facts envelope is invalid');
    }
    const record = envelope as Record<string, unknown>;
    if (
      typeof record.commitment_nonce !== 'string' ||
      !/^[A-Za-z0-9_-]{22,}$/.test(record.commitment_nonce) ||
      !record.facts ||
      typeof record.facts !== 'object' ||
      Array.isArray(record.facts)
    ) {
      throw new ForbiddenError('normalized proof facts envelope is invalid');
    }
    return {
      facts: record.facts as Record<string, unknown>,
      commitmentNonce: record.commitment_nonce,
    };
  }

  async decryptProofFacts(proof: AuthorityProofRecord): Promise<Record<string, unknown>> {
    return (await this.decryptProofFactEnvelope(proof)).facts;
  }

  async decryptProofNativeEvidence(proof: AuthorityProofRecord): Promise<string> {
    if (!proof.native_evidence_encrypted)
      throw new ForbiddenError('native proof evidence is unavailable');
    const plaintext = await this.deps.kms.decrypt(
      proof.native_evidence_encrypted,
      proofContext(proof.operator_id, proof.id, proof.version, 'authority_proof_native'),
    );
    if (sha256(plaintext) !== proof.native_evidence_hash) {
      throw new ForbiddenError('native proof evidence commitment mismatch');
    }
    let envelope: unknown;
    try {
      envelope = JSON.parse(plaintext);
    } catch {
      throw new ForbiddenError('native proof evidence envelope is invalid');
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      throw new ForbiddenError('native proof evidence envelope is invalid');
    }
    const record = envelope as Record<string, unknown>;
    if (
      typeof record.evidence !== 'string' ||
      typeof record.commitment_nonce !== 'string' ||
      !/^[A-Za-z0-9_-]{22,}$/.test(record.commitment_nonce)
    ) {
      throw new ForbiddenError('native proof evidence envelope is invalid');
    }
    return record.evidence;
  }
}
