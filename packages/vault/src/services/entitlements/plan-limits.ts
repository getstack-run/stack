import {
  CONTRACT_PLAN_LIMITS,
  type LimitOverrides,
  type OperatorTier,
  type OverageMode,
  type PlanLimits,
} from '@stack/shared';

/** The limits of one tier, with a deal's overrides, as an engine service that enforces a count reads them. */
export type ResolvedPlanLimits = PlanLimits & { maxTenants: number; overage: OverageMode };

/**
 * How the engine services that refuse past a count (agents, service connections, team seats, tenants) learn that
 * count. A deployment with plans names its own; an engine alone is on the contract plan, which caps nothing.
 */
export type PlanLimitsReader = (tier: OperatorTier, overrides?: LimitOverrides | null) => ResolvedPlanLimits;

/** The plan of an install that has none: no count is capped. */
export const contractPlanLimits: PlanLimitsReader = () => ({
  ...CONTRACT_PLAN_LIMITS,
  maxTenants: Infinity,
  overage: 'wallet',
});
