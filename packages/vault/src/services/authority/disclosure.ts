/** Pure helpers for assembling a presentation disclosure. */
import {
  ForbiddenError,
  ServiceUnavailableError,
  canonicalize,
  type AuthorityDisclosurePolicy,
} from '@stack/shared';
import { createHmac } from 'node:crypto';
import type { AuthorityBindingProofRecord, AuthorityProofRecord } from './records.js';
import { sha256 } from './digest.js';

export function deduplicateProofRows(proofs: AuthorityProofRecord[]): AuthorityProofRecord[] {
  const unique = new Map<string, AuthorityProofRecord>();
  for (const proof of proofs) unique.set(`${proof.id}:${proof.version}`, proof);
  return [...unique.values()];
}

export function derivePairwiseIdentifier(input: {
  commitmentNonce: string;
  receiverId: string;
  proof: AuthorityProofRecord;
  factId: string;
  value: unknown;
}): string {
  const message = canonicalize({
    receiver_id: input.receiverId,
    issuer_identifier: input.proof.issuer_identifier,
    subject_principal_id: input.proof.subject_principal_id,
    fact_id: input.factId,
    value: input.value,
  });
  return `hmac-sha256:${createHmac('sha256', Buffer.from(input.commitmentNonce, 'base64url'))
    .update(message)
    .digest('base64url')}`;
}

/** The binding's disclosure rule for one fact, as carried by its decrypted disclosure policy. */
export type BindingDisclosureRule = AuthorityDisclosurePolicy['rules'][number];

/**
 * Validates the receiver's requested facts against both the receiver profile
 * and the binding's disclosure policy, and returns the manifest to disclose.
 */
export function buildDisclosureManifest(
  requestedFacts: unknown[],
  receiverFacts: Map<string, Record<string, unknown>>,
  rules: BindingDisclosureRule[],
): {
  bindingRules: Map<string, BindingDisclosureRule>;
  manifest: Array<{ fact_id: string; mode: string }>;
} {
  const bindingRules = new Map(rules.map((rule) => [rule.fact_id, rule]));
  const manifest: Array<{ fact_id: string; mode: string }> = [];
  const seenFacts = new Set<string>();
  for (const raw of requestedFacts) {
    if (!raw || typeof raw !== 'object')
      throw new ForbiddenError('receiver requested facts are invalid');
    const factId = String((raw as Record<string, unknown>).fact_id ?? '');
    const mode = String((raw as Record<string, unknown>).mode ?? '');
    const receiverRule = receiverFacts.get(factId);
    const bindingRule = bindingRules.get(factId);
    if (
      !receiverRule ||
      !bindingRule ||
      bindingRule.mode !== mode ||
      !((receiverRule.allowed_modes as string[]) ?? []).includes(mode)
    ) {
      throw new ForbiddenError(
        'receiver requested a fact or disclosure mode outside the active policies',
      );
    }
    if (seenFacts.has(factId)) throw new ForbiddenError('receiver requested a fact more than once');
    seenFacts.add(factId);
    manifest.push({ fact_id: factId, mode });
  }
  for (const [factId, receiverRule] of receiverFacts) {
    const disclosed = manifest.find((item) => item.fact_id === factId);
    if (!disclosed || !((receiverRule.allowed_modes as string[]) ?? []).includes(disclosed.mode)) {
      throw new ForbiddenError(
        'receiver challenge omitted a fact required by the active receiver profile',
      );
    }
  }
  for (const rule of rules.filter((candidate) => candidate.required)) {
    if (!manifest.some((item) => item.fact_id === rule.fact_id)) {
      throw new ForbiddenError('receiver challenge omitted a disclosure required by the binding');
    }
  }
  return { bindingRules, manifest };
}

/** Every required proof must have a valid, still-fresh live status check. */
export function assertRequiredProofsLive(
  links: AuthorityBindingProofRecord[],
  proofRows: AuthorityProofRecord[],
  now: Date,
): void {
  for (const link of links.filter((candidate) => candidate.required)) {
    const proof = proofRows.find(
      (candidate) => candidate.id === link.proof_id && candidate.version === link.proof_version,
    );
    if (
      !proof ||
      proof.last_status_result !== 'valid' ||
      !proof.last_status_checked_at ||
      !proof.status_fresh_until ||
      proof.status_fresh_until <= now
    ) {
      throw new ServiceUnavailableError(
        'required authority proof live status is unavailable or stale',
      );
    }
  }
}

/** Provenance of each required proof, listing the modes in which it was disclosed. */
export function buildEvidenceRefs(
  links: AuthorityBindingProofRecord[],
  proofRows: AuthorityProofRecord[],
  disclosedFacts: Array<Record<string, unknown>>,
) {
  return links
    .filter((link) => link.required)
    .map((link) => {
      const proof = proofRows.find(
        (candidate) => candidate.id === link.proof_id && candidate.version === link.proof_version,
      );
      if (!proof) throw new ForbiddenError('required authority proof provenance is unavailable');
      const disclosedModes = [
        ...new Set(
          disclosedFacts
            .filter((fact) => fact.proof_id === proof.id)
            .map((fact) => String(fact.mode)),
        ),
      ];
      return {
        proof_id: proof.id,
        proof_version: proof.version,
        role: link.role,
        authoriser_principal_id: link.authoriser_principal_id,
        group_key_hash: sha256(link.group_key),
        profile_version_id: proof.profile_version_id,
        issuer_identifier: proof.issuer_identifier,
        schema_uri: proof.schema_uri,
        schema_version: proof.schema_version,
        assurance_uri: proof.assurance_uri,
        evidence_digest: proof.native_evidence_hash,
        evidence_modes: disclosedModes.length > 0 ? disclosedModes : ['none'],
        status: proof.last_status_result ?? proof.status,
      };
    });
}
