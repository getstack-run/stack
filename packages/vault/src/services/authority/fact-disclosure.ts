/** Selection of the one accepted proof behind each requested fact, and the disclosure it yields. */
import { ForbiddenError, ServiceUnavailableError } from '@stack/shared';
import type {
  AuthorityProofProfileVersionRecord,
  AuthorityProofRecord,
  AuthorityUseRecord,
} from './records.js';
import type { AuthorityProofAdapter, AuthorityServiceDeps } from './contracts.js';
import type { AuthorityRepositoryPort } from './port.js';
import type { AuthorityCore } from './core.js';
import type { AuthorityGuards } from './guards.js';
import type { BindingDisclosureRule } from './disclosure.js';
import { derivePairwiseIdentifier } from './disclosure.js';
import { readFact } from './fact-path.js';
import { sha256 } from './digest.js';

export interface FactDisclosureInput {
  use: AuthorityUseRecord;
  receiverId: string;
  receiverConfig: Record<string, unknown>;
  manifest: Array<{ fact_id: string; mode: string }>;
  bindingRules: Map<string, BindingDisclosureRule>;
  proofRows: AuthorityProofRecord[];
  now: Date;
}

export class FactDisclosure {
  private readonly deps: AuthorityServiceDeps;

  constructor(
    private readonly core: AuthorityCore,
    private readonly guards: AuthorityGuards,
  ) {
    this.deps = core.deps;
  }

  /**
   * Resolves every manifest item to exactly one accepted, usable proof and
   * returns the disclosed fact in the requested mode. Zero or several
   * candidate proofs are refused.
   */
  async discloseFacts(
    repo: AuthorityRepositoryPort,
    input: FactDisclosureInput,
  ): Promise<Array<Record<string, unknown>>> {
    const { use, receiverId, receiverConfig, manifest, bindingRules, proofRows, now } = input;
    const disclosedFacts: Array<Record<string, unknown>> = [];
    for (const item of manifest) {
      const bindingRule = bindingRules.get(item.fact_id)!;
      const acceptedProofRules =
        (receiverConfig.accepted_proofs as Array<Record<string, unknown>>) ?? [];
      const candidates: Array<{
        proof: AuthorityProofRecord;
        profile: AuthorityProofProfileVersionRecord;
        nativePath: string;
        adapter: AuthorityProofAdapter;
      }> = [];
      for (const proof of proofRows) {
        if (
          bindingRule.profile_version_id &&
          proof.profile_version_id !== bindingRule.profile_version_id
        )
          continue;
        const proofProfile = await repo.findProofProfileVersion(
          use.operator_id,
          proof.profile_version_id,
        );
        if (!proofProfile || proofProfile.status !== 'active') continue;
        const fact = (
          (proofProfile.config_json.disclosable_facts as Array<Record<string, unknown>>) ?? []
        ).find(
          (candidate) =>
            candidate.fact_id === item.fact_id &&
            ((candidate.allowed_modes as string[]) ?? []).includes(item.mode),
        );
        if (!fact) continue;
        const receiverAcceptance = acceptedProofRules.find(
          (rule) =>
            rule.proof_kind === proof.proof_kind &&
            ((rule.profile_version_ids as string[]) ?? []).includes(proof.profile_version_id) &&
            (((rule.issuer_ids as string[]) ?? []).length === 0 ||
              ((rule.issuer_ids as string[]) ?? []).includes(proof.issuer_identifier)) &&
            ((rule.evidence_modes as string[]) ?? []).includes(item.mode),
        );
        if (!receiverAcceptance) continue;
        const maximumAge = Number(receiverAcceptance.maximum_age_seconds);
        if (
          !Number.isFinite(maximumAge) ||
          proof.verified_at.getTime() + maximumAge * 1000 < now.getTime()
        )
          continue;
        if (
          receiverAcceptance.live_status_required === true &&
          (proof.last_status_result !== 'valid' ||
            !proof.status_fresh_until ||
            proof.status_fresh_until <= now)
        )
          continue;
        const adapter = this.core.adapters.get(
          `${proofProfile.adapter_key}@${proofProfile.adapter_version}`,
        );
        if (!adapter)
          throw new ServiceUnavailableError('required authority disclosure adapter is unavailable');
        const minimumAssurance = receiverAcceptance.minimum_assurance_uri;
        if (
          typeof minimumAssurance === 'string' &&
          (!adapter.meetsAssurance ||
            !adapter.meetsAssurance(proof.assurance_uri, minimumAssurance))
        )
          continue;
        candidates.push({
          proof,
          profile: proofProfile,
          nativePath: String(fact.native_path),
          adapter,
        });
      }
      if (candidates.length === 0)
        throw new ForbiddenError('no accepted proof supplies the requested fact');
      if (candidates.length > 1)
        throw new ForbiddenError('requested fact has ambiguous proof provenance');
      const { proof, profile: proofProfile, nativePath, adapter } = candidates[0]!;
      await this.guards.assertProofUsable(repo, proof, now);
      const factEnvelope = proof.normalized_facts_encrypted
        ? await this.guards.decryptProofFactEnvelope(proof)
        : undefined;
      const normalizedFacts =
        factEnvelope?.facts ??
        (proof.source_kind === 'legacy_identity_claim' && proof.legacy_identity_claim_id
          ? await this.deps.legacyIdentityResolver
              .resolveFacts({
                operatorId: use.operator_id,
                identityClaimId: proof.legacy_identity_claim_id,
                subjectPrincipalId: proof.subject_principal_id,
              })
              .catch(() => {
                throw new ForbiddenError('legacy identity facts are unavailable');
              })
          : undefined);
      if (item.mode === 'exact_private') {
        if (!normalizedFacts) throw new ForbiddenError('normalized proof facts are unavailable');
        disclosedFacts.push({
          fact_id: item.fact_id,
          mode: item.mode,
          proof_id: proof.id,
          value: readFact(normalizedFacts, nativePath),
          assertion_source: 'stack_derived',
          proof_strength: 'native_stack_attestation',
          provenance: { profile_version_id: proofProfile.id },
        });
      } else if (item.mode === 'status_only') {
        disclosedFacts.push({
          fact_id: item.fact_id,
          mode: item.mode,
          proof_id: proof.id,
          status: proof.last_status_result ?? proof.status,
          assertion_source: 'stack_derived',
          proof_strength: 'native_stack_attestation',
          provenance: { profile_version_id: proofProfile.id },
        });
      } else if (item.mode === 'pairwise') {
        if (!factEnvelope) {
          throw new ForbiddenError('pairwise disclosure requires nonce-bound core proof facts');
        }
        const factValue = readFact(factEnvelope.facts, nativePath);
        const pairwiseValue = derivePairwiseIdentifier({
          commitmentNonce: factEnvelope.commitmentNonce,
          receiverId: receiverId,
          proof,
          factId: item.fact_id,
          value: factValue,
        });
        disclosedFacts.push({
          fact_id: item.fact_id,
          mode: item.mode,
          proof_id: proof.id,
          value: pairwiseValue,
          evidence_digest: sha256(pairwiseValue),
          assertion_source: 'stack_derived',
          proof_strength: 'native_stack_attestation',
          provenance: {
            profile_version_id: proofProfile.id,
            method: 'stack.core.hmac-sha256/v1',
          },
        });
      } else {
        if (!adapter.disclose)
          throw new ServiceUnavailableError('proof adapter does not support selective disclosure');
        if (item.mode !== 'predicate' && item.mode !== 'issuer_evidence') {
          throw new ForbiddenError('unsupported selective disclosure mode');
        }
        const nativeEvidence = proof.native_evidence_encrypted
          ? await this.guards.decryptProofNativeEvidence(proof)
          : undefined;
        const disclosed = await adapter.disclose({
          mode: item.mode,
          factId: item.fact_id,
          nativePath,
          receiverId: receiverId,
          requestHash: use.request_hash,
          proof,
          profile: proofProfile,
          ...(normalizedFacts ? { normalizedFacts } : {}),
          ...(nativeEvidence ? { nativeEvidence } : {}),
        });
        if (disclosed.mode !== item.mode || !disclosed.evidenceDigest.startsWith('sha256:')) {
          throw new ForbiddenError('proof adapter returned mismatched disclosure provenance');
        }
        if (item.mode === 'predicate' && typeof disclosed.value !== 'boolean') {
          throw new ForbiddenError('predicate disclosure must return only a boolean result');
        }
        disclosedFacts.push({
          fact_id: item.fact_id,
          mode: item.mode,
          proof_id: proof.id,
          value: disclosed.value,
          evidence_digest: disclosed.evidenceDigest,
          assertion_source: item.mode === 'issuer_evidence' ? 'issuer_native' : 'adapter_derived',
          proof_strength:
            item.mode === 'issuer_evidence' ? 'native_issuer_evidence' : 'native_stack_attestation',
          provenance: disclosed.provenance,
        });
      }
    }
    return disclosedFacts;
  }
}
