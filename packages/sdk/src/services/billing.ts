import type { HttpClient } from '../client.js';

// The two card subscriptions of agent accounts: the platform subscription and
// hosted controls, each through Stripe Checkout with a card always required
// and a free trial the first time. Starting one returns a Checkout URL; the
// subscription itself is written from Stripe's own events, never by these
// calls, and is managed and cancelled in the Stripe billing portal.
//
// Starting a subscription is an owner or admin call and needs no approval: the
// person pays on Stripe's own page. An account on a contract plan, or already
// on the subscription, is refused with a 409 (`SUBSCRIPTION_CONFLICT`).

export type PlatformSubscriptionStatus = 'none' | 'incomplete' | 'trialing' | 'active' | 'past_due' | 'lapsed' | 'canceled';
export type ControlsSubscriptionStatus = 'off' | 'trialing' | 'active' | 'lapsed';

export interface BillingSubscriptions {
  platform: {
    status: PlatformSubscriptionStatus;
    /** Whether paid features (opening accounts, metered account actions) are on. */
    active: boolean;
    /** Billed by contract, never by the platform subscription. */
    contract: boolean;
    /** The day the free trial ends, as Stripe states it (ISO 8601); null when no trial is running. */
    trial_ends_at: string | null;
  };
  controls: {
    status: ControlsSubscriptionStatus;
    /** The day the controls trial ends, as Stripe states it (ISO 8601); null when no trial is running. */
    trial_ends_at: string | null;
  };
  /** This month's usage of the billing account. */
  this_month: { account_actions: number; control_checks: number };
}

export interface SubscriptionCheckout {
  /** The Stripe Checkout page to open. */
  checkout_url: string;
  session_id: string;
  /** Whether the checkout starts with the free trial. */
  trial: boolean;
}

/** Accepted for compatibility with earlier versions: starting a checkout needs no approval, so it is ignored. */
export interface BillingGovernedOptions {
  /** Ignored. */
  governanceApprovalId?: string;
}

function governed(options?: BillingGovernedOptions): { headers: Record<string, string> } | undefined {
  return options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined;
}

/**
 * Platform and controls subscriptions of agent accounts.
 *
 * @example
 * ```ts
 * const { checkout_url, trial } = await stack.billing.subscribePlatform();
 * // Open checkout_url, then read the state back:
 * const { platform, controls } = await stack.billing.subscriptions();
 * ```
 */
export class BillingService {
  constructor(private readonly client: HttpClient) {}

  /** The platform and controls state, and this month's account actions and control checks. */
  async subscriptions(): Promise<BillingSubscriptions> {
    return this.client.get<BillingSubscriptions>('/v1/billing/subscriptions');
  }

  /**
   * Start the platform subscription: the Stripe Checkout URL, with the free
   * trial when it has not been used. Owner or admin, not a white-label tenant.
   * A 409 `SUBSCRIPTION_CONFLICT` means it is already on, or the account is on
   * a contract plan; a 503 `BILLING_NOT_CONFIGURED` means it is not offered yet.
   */
  async subscribePlatform(options?: BillingGovernedOptions): Promise<SubscriptionCheckout> {
    return this.client.post<SubscriptionCheckout>('/v1/billing/platform/subscribe', undefined, governed(options));
  }

  /**
   * Switch on hosted controls: the Stripe Checkout URL, with the free trial
   * when it has not been used. Needs the platform subscription
   * (`PLATFORM_SUBSCRIPTION_REQUIRED` otherwise). Same 409/503 rules as
   * `subscribePlatform`.
   */
  async subscribeControls(options?: BillingGovernedOptions): Promise<SubscriptionCheckout> {
    return this.client.post<SubscriptionCheckout>('/v1/billing/controls/subscribe', undefined, governed(options));
  }
}
