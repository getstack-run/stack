import { IdentityRequirementsError, type PassportClaimRef } from '@stack/shared';
import type { PassportContext, PassportJWTPayload } from './types.js';

/** Preserve the signed passport's exact claim selection during refresh. */
export function identityClaimIdsForRefresh(claims: PassportClaimRef[] | undefined): string[] {
  return (claims ?? []).map((claim) => claim.claim_id);
}

/** Delegation can only copy the parent's identity claims. */
export function preserveIdentityClaimsForDelegation(
  claims: PassportClaimRef[] | undefined,
): PassportClaimRef[] {
  return claims ?? [];
}

/** Fail closed when either source says the carried identity claim expired. */
export function identityClaimIsExpired(
  record: { expires_at: Date },
  embedded: { expires_at: number },
  nowMs: number = Date.now(),
): boolean {
  return record.expires_at.getTime() <= nowMs || embedded.expires_at * 1000 <= nowMs;
}

/**
 * The per-service identity requirements gate (humanity / identity /
 * assurance level) for a Passport that has ALREADY been verified on this
 * request. Throws IdentityRequirementsError when a requirement is unmet.
 *
 * `verify(token, { service_id })` runs this as its last step. The proxy
 * learns the service only after verifying, so it calls this directly
 * instead of verifying the same token a second time.
 *
 * The lookup is scoped to the VERIFYING passport's operator so a tenant only
 * ever enforces its OWN requirements. A lookup by service_id alone would let
 * any operator's requirement rows gate every other tenant's passport
 * verification on this hot path.
 */
export async function assertServiceIdentityRequirements(
  ctx: PassportContext,
  claims: PassportJWTPayload,
  serviceId: string,
): Promise<void> {
  const requirements = await ctx.identityRepo.findRequirementsByService(
    claims.stk.operator_id,
    serviceId,
  );
  if (requirements.length === 0) return;
  const result = ctx.claimMatcher.satisfies(
    claims.stk.identity_claims,
    requirements.map((r) => ({
      id: r.id,
      service_id: r.service_id,
      layer: r.layer as 'humanity' | 'identity' | 'delegation',
      requires_claim: r.requires_claim,
      minimum_assurance: r.minimum_assurance as 'low' | 'substantial' | 'high',
      accepted_providers: r.accepted_providers as string[],
      required_scopes: r.required_scopes as string[] | undefined,
      requires_pii: r.requires_pii ?? false,
      lawful_basis: r.lawful_basis,
    })),
  );
  if (!result.satisfied) {
    const unmetNames = result.unmet.map((u) => `${u.layer}:${u.requires_claim}`).join(', ');
    throw new IdentityRequirementsError(unmetNames);
  }
}
