import { createHash } from 'node:crypto';
import { ForbiddenError, type AuthorityReference } from '@stack/shared';
import type {
  PassportAuthorityTransaction,
  PassportContext,
  PassportJWTPayload,
} from './types.js';

/** Canonical lowercase SHA-256 thumbprint used by authority bindings. */
export function passportAuthorityAgentKeyThumbprint(jwk: {
  kty: string;
  crv: string;
  x: string;
}): string {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !/^[A-Za-z0-9_-]+$/.test(jwk.x)) {
    throw new ForbiddenError('authority agent keys must be public Ed25519 JWKs');
  }
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

/** Resolve the authority bindings a caller asked an issued Passport to carry. */
export async function resolveRequestedAuthorityRefs(
  ctx: PassportContext,
  input: {
    operatorId: string;
    agentId: string;
    bindingIds: string[];
    missionIds?: string[];
  },
): Promise<AuthorityReference[]> {
  return ctx.authorityLookup().resolvePassportRefs({
    operatorId: input.operatorId,
    agentId: input.agentId,
    bindingIds: input.bindingIds,
    ...(input.missionIds ? { missionIds: input.missionIds } : {}),
  });
}

/**
 * Authority does not flow to a child merely because identity and service
 * scopes do. Each carried parent reference must resolve to an already-active,
 * explicitly narrowed child binding for this exact child key.
 *
 * Returns undefined when neither a fleet root nor the parent carries authority.
 */
export async function resolveDelegatedAuthorityRefs(
  ctx: PassportContext,
  input: {
    operatorId: string;
    parentClaims: PassportJWTPayload;
    childAgent: { id: string; pubkey?: { kty: string; crv: string; x: string } | null };
    allowInternalRoot: boolean;
    fleetAuthorityBindingIds: string[] | undefined;
    ttl: number;
  },
): Promise<AuthorityReference[] | undefined> {
  const { operatorId, parentClaims, childAgent } = input;
  if (input.fleetAuthorityBindingIds?.length) {
    if (!input.allowInternalRoot || !parentClaims.stk.fleet?.internal_root)
      throw new ForbiddenError();
    return ctx.authorityLookup().resolvePassportRefs({
      operatorId,
      agentId: childAgent.id,
      bindingIds: input.fleetAuthorityBindingIds,
      missionIds: parentClaims.stk.mission_ids,
    });
  }
  if (parentClaims.stk.authority_refs && parentClaims.stk.authority_refs.length > 0) {
    if (!childAgent.pubkey) {
      throw new ForbiddenError('Authority delegation is not available for this child agent');
    }
    return ctx.authorityLookup().delegatePassportRefs({
      operatorId,
      parentRefs: parentClaims.stk.authority_refs,
      childAgentId: childAgent.id,
      childAgentKeyThumbprint: passportAuthorityAgentKeyThumbprint(childAgent.pubkey),
      expiresAt: new Date(Date.now() + input.ttl * 1000),
    });
  }
  return undefined;
}

/**
 * A Passport that carries authority references is only as live as the
 * bindings behind them. The authority engine rechecks every reference.
 */
export async function verifyCarriedAuthorityRefs(
  ctx: PassportContext,
  claims: PassportJWTPayload,
): Promise<void> {
  if (!claims.stk.authority_refs?.length) return;
  await ctx.authorityLookup().verifyPassportRefs({
    operatorId: claims.stk.operator_id,
    agentId: claims.stk.agent_id,
    refs: claims.stk.authority_refs,
    ...(claims.stk.mission_ids ? { missionIds: claims.stk.mission_ids } : {}),
  });
}

/** Record which authority references a new Passport carries, in its own transaction. */
export async function linkAuthorityRefs(
  ctx: PassportContext,
  input: { operatorId: string; passportJti: string; refs: AuthorityReference[] },
  tx: PassportAuthorityTransaction,
): Promise<void> {
  await ctx.authorityLookup().linkPassportRefs(input, tx);
}
