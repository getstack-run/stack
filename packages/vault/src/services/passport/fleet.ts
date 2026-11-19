import { PassportExpiredError, PassportRevokedError, type FleetPassportBinding } from '@stack/shared';
import type { PassportContext, PassportJWTPayload } from './types.js';

/** The instant a fleet binding stops authorizing Passports for this agent. */
export async function fleetDeadline(
  ctx: PassportContext,
  operatorId: string,
  agentId: string,
  binding: FleetPassportBinding,
): Promise<number> {
  const { expiresAt } = await ctx.fleetLookup().authorizeIssue(operatorId, binding, agentId);
  const deadline = expiresAt.getTime();
  if (!Number.isFinite(deadline) || deadline <= Date.now()) throw new PassportExpiredError();
  return deadline;
}

/**
 * A fleet-bound token must match its binding exactly; an unbound token is
 * still checked, including tokens minted before enrollment.
 */
export async function validateFleet(
  ctx: PassportContext,
  claims: PassportJWTPayload,
  allowInternalRoot = false,
): Promise<void> {
  const binding = claims.stk.fleet;
  if (binding) {
    if (
      (binding.internal_root && !allowInternalRoot) ||
      claims.stk.mission_ids?.length !== 1 ||
      claims.stk.mission_ids[0] !== binding.mission_id ||
      claims.stk.accountability !== 'enforced' ||
      claims.stk.platform_intent
    ) {
      throw new PassportRevokedError();
    }
  }
  await ctx.fleetLookup().validate(claims);
}
