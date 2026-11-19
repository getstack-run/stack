import type { FastifyReply, FastifyRequest } from 'fastify';
import { GrantDelegationInput } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';

/** Safe claim fields that may leave the API. */
export interface PublicIdentityClaim {
  id: string;
  operator_id: string;
  provider_id: string;
  provider_key: string;
  layer: string;
  claim_type: string;
  assurance_level: string;
  verified_at: Date;
  expires_at: Date;
  delegated_scopes: string[] | null;
  revoked_at: Date | null;
  created_at: Date;
  claim_id: string | null;
}

/** Only these safe claim fields may leave the API. */
export function publicIdentityClaim(claim: PublicIdentityClaim): PublicIdentityClaim {
  return {
    id: claim.id,
    operator_id: claim.operator_id,
    provider_id: claim.provider_id,
    provider_key: claim.provider_key,
    layer: claim.layer,
    claim_type: claim.claim_type,
    assurance_level: claim.assurance_level,
    verified_at: claim.verified_at,
    expires_at: claim.expires_at,
    delegated_scopes: claim.delegated_scopes,
    revoked_at: claim.revoked_at,
    created_at: claim.created_at,
    claim_id: claim.claim_id,
  };
}

// ── Layer 3: Delegation consent ───────────────────────────────────

export async function grantDelegation(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const input = GrantDelegationInput.parse(request.body);
  const start = Date.now();

  const claim = await services.identity.grantDelegation(
    request.operatorId,
    input.delegated_scopes,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.delegate',
    outcome: 'success',
    duration_ms: Date.now() - start,
  });

  return reply.status(201).send(claim);
}

// ── Claim management ──────────────────────────────────────────────

export async function listClaims(
  request: FastifyRequest,
  services: Services,
): Promise<PublicIdentityClaim[]> {
  const claims = await services.identity.getAllClaims(request.operatorId);
  return claims.map(publicIdentityClaim);
}

export async function revokeClaim(
  request: FastifyRequest<{ Params: { id: string } }>,
  services: Services,
): Promise<{ success: true }> {
  const start = Date.now();
  await services.identity.revokeClaim(request.params.id, request.operatorId);

  // Smart revoke: only invalidate passports that actually carry this claim.
  // Passports without this claim are unaffected.
  await services.passport.revokeByCarriedClaim(
    request.operatorId,
    request.params.id,
    `Identity claim ${request.params.id} revoked`,
  );

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'identity.claim.revoke',
    outcome: 'success',
    duration_ms: Date.now() - start,
  });

  return { success: true };
}
