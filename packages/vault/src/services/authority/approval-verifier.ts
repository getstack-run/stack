/** Pinned verification of approval decisions made through an external approval ceremony. */
import { ForbiddenError, ServiceUnavailableError, type HumanOperatorAuthor } from '@stack/shared';
import type { AuthorityProofAdapter } from './contracts.js';
import type { AuthorityProofProfileVersionRecord, AuthorityProofRecord } from './records.js';
import type { AuthorityRepositoryPort } from './port.js';

export interface ResolvedAuthorityApprovalDecision {
  authoriserPrincipalId: string;
  identityProofId: string;
  identityProofVersion: number;
  capacityProofId?: string;
  capacityProofVersion?: number;
  decisionProofId: string;
  decisionProofVersion: number;
}

export interface AuthorityApprovalVerifierCandidate {
  authoriserPrincipalId: string;
  identityProof: AuthorityProofRecord;
  capacityProof?: AuthorityProofRecord;
  profile: AuthorityProofProfileVersionRecord;
  requestHash: string;
}

/**
 * An adapter throws this only when a well-formed approval ceremony is
 * cryptographically valid input but does not match the pinned authoriser slot.
 * Operational faults must not use this error because they fail the action 503.
 */
export class AuthorityApprovalCeremonyRejectedError extends Error {
  constructor() {
    super('authority approval ceremony did not match the pinned authoriser');
    this.name = 'AuthorityApprovalCeremonyRejectedError';
  }
}

/**
 * Production fail-closed approval verifier. It never decodes an unverified
 * decision in core: the immutable proof-profile adapter verifies the ceremony
 * against one server-resolved authoriser slot. Exactly one adapter result is
 * required, so overlap or ambiguity denies.
 */
export class PinnedAuthorityApprovalDecisionVerifier {
  private readonly adapters: ReadonlyMap<string, AuthorityProofAdapter>;

  constructor(
    private readonly repo: AuthorityRepositoryPort,
    adapters: readonly AuthorityProofAdapter[],
  ) {
    this.adapters = new Map(
      adapters.map((adapter) => [`${adapter.key}@${adapter.version}`, adapter]),
    );
  }

  async verify(input: {
    operatorId: string;
    requestId: string;
    requestHash: string;
    decision: 'approve' | 'reject';
    signedDecision: string;
    authenticatedAuthor: HumanOperatorAuthor;
  }): Promise<ResolvedAuthorityApprovalDecision> {
    const candidates = await this.repo.listApprovalVerifierCandidates(
      input.operatorId,
      input.requestId,
      new Date(),
    );
    const matches: ResolvedAuthorityApprovalDecision[] = [];
    for (const candidate of candidates) {
      if (candidate.requestHash !== input.requestHash) continue;
      const adapter = this.adapters.get(
        `${candidate.profile.adapter_key}@${candidate.profile.adapter_version}`,
      );
      if (!adapter?.verifyApprovalDecision) continue;
      try {
        const decisionProof = await adapter.verifyApprovalDecision({
          requestId: input.requestId,
          requestHash: input.requestHash,
          decision: input.decision,
          signedDecision: input.signedDecision,
          authenticatedAuthor: input.authenticatedAuthor,
          authoriserPrincipalId: candidate.authoriserPrincipalId,
          identityProof: candidate.identityProof,
          ...(candidate.capacityProof ? { capacityProof: candidate.capacityProof } : {}),
          profile: candidate.profile,
        });
        matches.push({
          authoriserPrincipalId: candidate.authoriserPrincipalId,
          identityProofId: candidate.identityProof.id,
          identityProofVersion: candidate.identityProof.version,
          ...(candidate.capacityProof
            ? {
                capacityProofId: candidate.capacityProof.id,
                capacityProofVersion: candidate.capacityProof.version,
              }
            : {}),
          decisionProofId: decisionProof.decisionProofId,
          decisionProofVersion: decisionProof.decisionProofVersion,
        });
      } catch (error) {
        if (error instanceof AuthorityApprovalCeremonyRejectedError) {
          // A non-matching pinned ceremony is expected when several named
          // authorisers are eligible. Only one successful binding is accepted.
          continue;
        }
        if (error instanceof ServiceUnavailableError) throw error;
        throw new ServiceUnavailableError('authority approval verification is unavailable');
      }
    }
    if (matches.length !== 1)
      throw new ForbiddenError('authority approval ceremony is invalid or ambiguous');
    return matches[0]!;
  }
}
