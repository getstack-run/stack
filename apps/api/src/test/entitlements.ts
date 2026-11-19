import { CONTRACT_PLAN_LIMITS, type ControlsStatus, type LimitOverrides } from '@stack/shared';
import type { EntitlementAccount, EntitlementResolver } from '@stack/vault';

/**
 * Test double for `services.entitlements` on an engine install: every operator is on the contract plan (enterprise),
 * which has no allowance, no charge and every control, and a tenant bills to its partner when a mapping is given. It
 * mirrors ContractPlanEntitlements without a database. STACK's own plans have their own double in the hosted tests.
 */
export function fakeEntitlements(
  options: {
    partners?: Record<string, string>;
    /** The billing account's controls status; off unless given (the contract plan has every control regardless). */
    controls?: ControlsStatus | ((billingOperatorId: string) => ControlsStatus);
    overrides?: LimitOverrides | null;
  } = {},
): EntitlementResolver {
  const controls = options.controls;
  const controlsFor = typeof controls === 'function' ? controls : (): ControlsStatus => controls ?? 'off';
  const resolve = async (operatorId: string): Promise<EntitlementAccount> => {
    const billingOperatorId = options.partners?.[operatorId] ?? operatorId;
    return {
      actingOperatorId: operatorId,
      billingOperatorId,
      planOperatorId: billingOperatorId,
      pooled: billingOperatorId !== operatorId,
      tier: 'enterprise',
      plan: 'contract',
      limits: { ...CONTRACT_PLAN_LIMITS, maxTenants: Infinity, overage: 'wallet' },
      isTenant: billingOperatorId !== operatorId,
      controlsStatus: controlsFor(billingOperatorId),
      platformStatus: 'none',
    };
  };
  return {
    resolve,
    controlsEnabled: async (operatorId) => {
      await resolve(operatorId);
      return true;
    },
    evict: () => {},
    invalidate: async () => {},
  };
}
