import { safeErrorSummary } from '@stack/shared';
import type { Services } from '../../config/services.js';

/**
 * Controls were switched on for a customer (their controls subscription began,
 * or they chose STACK's hosted controls): give every account's agent that has
 * grants a policy equal to them. For a partner that includes the agents of its
 * white-label tenants, whose controls follow the partner's. It changes no
 * outcome until the customer tightens it. Idempotent, and never fails what
 * switched controls on: the customer can start a policy from the Console or the
 * API at any time.
 */
export async function startPoliciesWhenControlsOn(
  services: Pick<Services, 'entitlements' | 'controlPolicies'>,
  operatorId: string,
  actor: string,
): Promise<string[]> {
  try {
    if (!(await services.entitlements.controlsEnabled(operatorId))) return [];
    return await services.controlPolicies.ensureStartingPoliciesWithTenants(operatorId, actor);
  } catch (error) {
    console.error('[CONTROL] starting policies from current access failed', safeErrorSummary(error));
    return [];
  }
}
