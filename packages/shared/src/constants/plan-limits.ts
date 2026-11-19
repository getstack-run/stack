/**
 * The limits a plan sets, as numbers (`Infinity` for no limit). The engine knows
 * one plan, the contract plan below. STACK's hosted tiers are other rows of the
 * same shape, kept with the hosted pricing.
 */
export interface PlanLimits {
  /** Count caps. Every plan leaves these ungated. */
  agents: number;
  services: number;
  publishedSkills: number;
  inboundWebhooks: number;
  /** The recorded-action allowance per calendar month. */
  actionsPerMonth: number;
  smsPerMonth: number;
  emailPerMonth: number;
  l3CallsPerMonth: number;
  inboundWebhookReceivesPerMonth: number;
  inboundWebhookBlocksPerMonth: number;
}

/**
 * How long every account's record is kept: the audit log, the security events and
 * the signed claims, 365 days, on every plan and every install. Reading the record
 * needs controls; keeping it does not. A longer window agreed for one account is its
 * `audit_retention_days_override`, which the prunes honour first.
 */
export const AUDIT_RETENTION_DAYS = 365;

/**
 * The contract plan: nothing is capped, metered or charged. A self-managed
 * install runs every operator on it.
 */
export const CONTRACT_PLAN_LIMITS: PlanLimits = {
  agents: Infinity,
  services: Infinity,
  publishedSkills: Infinity,
  inboundWebhooks: Infinity,
  actionsPerMonth: Infinity,
  smsPerMonth: Infinity,
  emailPerMonth: Infinity,
  l3CallsPerMonth: Infinity,
  inboundWebhookReceivesPerMonth: Infinity,
  inboundWebhookBlocksPerMonth: Infinity,
};
