/** Canonical digest of the exact terms a mandate proof covers. */
import { canonicalize, type AuthorityDisclosurePolicy, type AuthorityScope } from '@stack/shared';
import { sha256 } from './digest.js';

export function authorityMandateTermsDigest(input: {
  principalId: string;
  authoriserPrincipalIds: string[];
  agentId: string;
  agentKeyThumbprint: string;
  receiverId: string;
  receiverProfileVersionId: string;
  domainProfileVersionId?: string;
  missionIds: string[];
  purposeCode: string;
  purposeStatement?: string;
  scope: AuthorityScope;
  approvalPolicy: Record<string, unknown>;
  disclosurePolicy: AuthorityDisclosurePolicy;
  delegationPolicy: { allow_further_delegation: boolean; max_delegation_depth: number };
  validFrom: Date;
  expiresAt: Date;
}): string {
  return sha256(
    canonicalize({
      principal_id: input.principalId,
      authoriser_principal_ids: [...new Set(input.authoriserPrincipalIds)].sort(),
      agent_id: input.agentId,
      agent_key_thumbprint: input.agentKeyThumbprint,
      receiver_id: input.receiverId,
      receiver_profile_version_id: input.receiverProfileVersionId,
      domain_profile_version_id: input.domainProfileVersionId ?? null,
      mission_ids: [...new Set(input.missionIds)].sort(),
      purpose_code: input.purposeCode,
      purpose_statement: input.purposeStatement ?? null,
      scope: input.scope,
      approval_policy: input.approvalPolicy,
      disclosure_policy: input.disclosurePolicy,
      delegation_policy: input.delegationPolicy,
      valid_from: input.validFrom.toISOString(),
      expires_at: input.expiresAt.toISOString(),
    }),
  );
}
