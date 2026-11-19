// Partner-managed accounts: the wire shapes of the partner API (`/v1/partner/accounts`,
// spec/partner/SPEC.md). A partner opens an account for each of its customers under its own
// reference. The partner pays for the account from its wallet (`billing` is always `partner`): the account has its own
// plan, free amounts and usage like any customer's. It holds no email of the customer, and moves to the customer when
// the partner releases it.

import { z } from 'zod';
import { PARTNER_RELEASE_REQUESTERS, PARTNER_RELEASE_STATUSES } from '../constants/index.js';

/**
 * What a partner sends to open an account. `external_ref` is the partner's own reference for its customer, unique
 * per partner and the idempotency key of the call. The partner does not choose an account's plan, so `tier` is not a
 * member: the route accepts it only to refuse it by name (`TENANT_TIER_NOT_ALLOWED`).
 */
export const PartnerAccountCreateInput = z
  .object({
    external_ref: z.string().min(1).max(256),
    /**
     * Switch the account's hosted controls on as it opens: the controls' first month is taken from the partner's wallet with the
     * plan's, and a wallet that cannot pay both refuses the open. Off when absent, as for any customer account.
     */
    controls: z.boolean().optional(),
  })
  .strict();
export type PartnerAccountCreateInput = z.infer<typeof PartnerAccountCreateInput>;

/** The answer to a create: the account's API key is in it once, on the call that created the account. */
export const PartnerAccountCreateResult = z.object({
  account_id: z.string(),
  external_ref: z.string(),
  billing: z.literal('partner'),
  status: z.string(),
  /** False when the partner already had an account under this reference: nothing was made and no key is returned. */
  created: z.boolean(),
  created_at: z.string(),
  api_key: z.string().optional(),
});
export type PartnerAccountCreateResult = z.infer<typeof PartnerAccountCreateResult>;

/** Whether the customer has been invited to see the account, and whether they have accepted. */
export const PartnerAccountInviteState = z.enum(['none', 'invited', 'active']);
export type PartnerAccountInviteState = z.infer<typeof PartnerAccountInviteState>;

/**
 * What a partner pays for one account, and where it stands. `status` `active`: paid to its renewal. `paused`: the wallet
 * did not cover a renewal and the account waits for it. `controls` is off unless the partner switched them on for it.
 */
export const PartnerAccountPlan = z.object({
  monthly_cents: z.number().int().positive(),
  status: z.enum(['active', 'paused']),
  renews_on: z.string().nullable(),
  controls: z.object({
    monthly_cents: z.number().int().positive(),
    status: z.enum(['off', 'active', 'paused']),
    renews_on: z.string().nullable(),
  }),
});
export type PartnerAccountPlan = z.infer<typeof PartnerAccountPlan>;

/** An account as the partner reads it: metadata, its own usage and its plan, never its audit content. */
export const PartnerAccountView = z.object({
  account_id: z.string(),
  external_ref: z.string().nullable(),
  billing: z.literal('partner'),
  status: z.string(),
  created_at: z.string(),
  deleted_at: z.string().nullable(),
  invite: z.object({ status: PartnerAccountInviteState }),
  /** Its own month-to-date metered actions. Absent when the readout is unavailable. */
  usage: z.object({ period: z.string(), actions: z.number().int().nonnegative() }).optional(),
  /** Its own plan, paid by the partner. Absent where STACK does not bill accounts. */
  plan: PartnerAccountPlan.optional(),
});
export type PartnerAccountView = z.infer<typeof PartnerAccountView>;

/** The answer to closing an account: what the cascade closed. A retry answers `transitioned: false`. */
export const PartnerAccountRevokeResult = z.object({
  transitioned: z.boolean(),
  webhooks_revoked: z.number().int().nonnegative(),
  passports_revoked: z.number().int().nonnegative(),
});
export type PartnerAccountRevokeResult = z.infer<typeof PartnerAccountRevokeResult>;

/** A new API key for an account, shown once; the one it replaces stops working at once. */
export const PartnerAccountRotateKeyResult = z.object({
  account_id: z.string(),
  api_key: z.string(),
});
export type PartnerAccountRotateKeyResult = z.infer<typeof PartnerAccountRotateKeyResult>;

/** Switching hosted controls on or off for one account. On costs the account's controls price a month, from the partner's wallet. */
export const PartnerAccountControlsInput = z.object({ enabled: z.boolean() }).strict();
export type PartnerAccountControlsInput = z.infer<typeof PartnerAccountControlsInput>;

/** The account's plan after the change; absent where STACK does not bill the partner for its accounts one by one. */
export const PartnerAccountControlsResult = z.object({
  account_id: z.string(),
  plan: PartnerAccountPlan.optional(),
});
export type PartnerAccountControlsResult = z.infer<typeof PartnerAccountControlsResult>;

const CustomerEmail = z.string().trim().toLowerCase().email().max(254);

/** The customer the partner invites to see an account. The address is the customer's only when they accept. */
export const PartnerAccountInviteInput = z
  .object({
    email: CustomerEmail,
    name: z.string().trim().min(1).max(100).optional(),
  })
  .strict();
export type PartnerAccountInviteInput = z.infer<typeof PartnerAccountInviteInput>;

export const PartnerAccountInviteResult = z.object({
  status: z.literal('invited'),
  expires_at: z.string(),
});
export type PartnerAccountInviteResult = z.infer<typeof PartnerAccountInviteResult>;

/**
 * Releasing an account to its customer. The address the claim link goes to is the invited customer's when there is
 * exactly one, or the one the partner gives here.
 */
export const PartnerReleaseInput = z.object({ email: CustomerEmail.optional() }).strict();
export type PartnerReleaseInput = z.infer<typeof PartnerReleaseInput>;

/**
 * A release as the partner reads it. `pending`: the claim link is out. `completed`: the customer claimed the account
 * and it is theirs. `returned`: the claim did not complete (the link lapsed, or the check or the checkout did not
 * pass) and the account is still the partner's; the reason is never given. `cancelled`: the partner or the customer
 * withdrew it.
 */
export const PartnerReleaseRecord = z.object({
  account_id: z.string(),
  external_ref: z.string().nullable(),
  status: z.enum(PARTNER_RELEASE_STATUSES),
  requested_by: z.enum(PARTNER_RELEASE_REQUESTERS),
  requested_at: z.string(),
  expires_at: z.string(),
  completed_at: z.string().nullable(),
});
export type PartnerReleaseRecord = z.infer<typeof PartnerReleaseRecord>;
