import { z } from 'zod';

export const OperatorTier = z.enum(['free', 'developer', 'pro', 'business', 'enterprise']);
export type OperatorTier = z.infer<typeof OperatorTier>;

/**
 * The plan an account is on, as every customer readout names it. STACK has one plan, the platform subscription.
 * `platform`: it is live (trialing, active or past due), or a live grant stands in for it. `internal`: STACK's own account.
 * `contract`: a self-managed engine install, where every operator is on the contract plan. `none`: no live plan (lapsed,
 * cancelled or never started). Read through the billing account, never from `operators.tier`.
 */
export const ACCOUNT_PLANS = ['platform', 'internal', 'contract', 'none'] as const;
export const AccountPlan = z.enum(ACCOUNT_PLANS);
export type AccountPlan = z.infer<typeof AccountPlan>;

/**
 * The operator's controls subscription (`operators.controls_status`), written
 * from Stripe. Controls are on only while `trialing` or `active`; read the
 * decision through the billing account's controls decision, never this field.
 */
export const CONTROLS_STATUSES = ['off', 'trialing', 'active', 'lapsed'] as const;
export const ControlsStatus = z.enum(CONTROLS_STATUSES);
export type ControlsStatus = z.infer<typeof ControlsStatus>;

export const Operator = z.object({
  id: z.string(),
  email: z.string().email(),
  tier: OperatorTier,
  api_key_hash: z.string(),
  created_at: z.date(),
  updated_at: z.date(),
});
export type Operator = z.infer<typeof Operator>;

export const IdentityClaimTtl = z.enum(['30d', '90d', '180d', '1y']);
export type IdentityClaimTtl = z.infer<typeof IdentityClaimTtl>;

export const IdentityClaimInheritance = z.enum(['auto', 'opt_in']);
export type IdentityClaimInheritance = z.infer<typeof IdentityClaimInheritance>;

export const UpdateIdentitySettingsInput = z.object({
  identity_claim_ttl: IdentityClaimTtl.optional(),
  identity_claim_inheritance: IdentityClaimInheritance.optional(),
  identity_auto_revoke: z.boolean().optional(),
});
export type UpdateIdentitySettingsInput = z.infer<typeof UpdateIdentitySettingsInput>;
