import { z } from 'zod';

/**
 * Per-deal limit overrides, set by STACK staff on a billing account
 * (a normal operator or a white-label partner). Tenants never carry
 * overrides; they inherit their partner's resolved limits.
 *
 * Only the monthly meters are overridable. Count caps (agents, services,
 * webhooks) are Infinity on every tier by design, so there is nothing to
 * negotiate there.
 *
 * A value of `null` means explicitly unlimited (JSON cannot hold Infinity).
 * An absent key means "use the tier default".
 */
// Capped below 2^31 so a limit always fits the integer allowance snapshot
// (usage_monthly_allowances.actions_limit). Larger means unlimited: use null.
const LimitValue = z.number().int().nonnegative().max(2_000_000_000).nullable();

export const OVERRIDABLE_LIMIT_KEYS = [
  'actionsPerMonth',
  'smsPerMonth',
  'emailPerMonth',
  'l3CallsPerMonth',
  'memoryEntries',
  'memoryEntriesPerDay',
  'memoryEntities',
  'memoryFacts',
] as const;
export type OverridableLimitKey = (typeof OVERRIDABLE_LIMIT_KEYS)[number];

/**
 * What happens when a billing account reaches a capped allowance:
 * - `wallet` (default, same as every account today): overage is charged
 *   to the account's prepaid wallet; refused when the wallet cannot pay.
 * - `block`: refused at the cap, the wallet is never touched.
 */
export const OverageMode = z.enum(['wallet', 'block']);
export type OverageMode = z.infer<typeof OverageMode>;

export const LimitOverrides = z
  .object({
    actionsPerMonth: LimitValue.optional(),
    smsPerMonth: LimitValue.optional(),
    emailPerMonth: LimitValue.optional(),
    l3CallsPerMonth: LimitValue.optional(),
    /** What an account's memory may hold: ledger entries, writes a day, and people, organisations and facts in the graph. */
    memoryEntries: LimitValue.optional(),
    memoryEntriesPerDay: LimitValue.optional(),
    memoryEntities: LimitValue.optional(),
    memoryFacts: LimitValue.optional(),
    /** Limits nothing any more (a customer's workspaces have no plan ceiling); named so a deal stored before still reads. */
    workspacesPerAccount: LimitValue.optional(),
    /** White-label partners only: how many tenants may exist at once. */
    maxTenants: LimitValue.optional(),
    overage: OverageMode.optional(),
  })
  .strict();
export type LimitOverrides = z.infer<typeof LimitOverrides>;
