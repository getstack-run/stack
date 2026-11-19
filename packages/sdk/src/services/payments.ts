import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions } from './accounts.js';

// Getting paid: the customer connects their own Stripe with a restricted key,
// and the account's agent then asks to be paid with payment links and checkout
// sessions. The money goes from the buyer to the customer's own Stripe account;
// STACK never holds it. Payments for priced site paths arrive in USDC on the
// agent's own wallet and are listed with the card ones.
//
// The restricted key is never typed into a chat, a call or this SDK: the
// customer pastes it, with the webhook signing secret, into the connect page
// that `startStripe` returns the address of. Calls the agent makes
// (`createLink`, `createCheckoutSession`, `deactivateLink`) require its
// Passport as `passportToken`, sent as `X-Passport-Token`; reads take it
// optionally. Disconnecting is the owner's alone.

export type StripeConnectionState = 'awaiting_key' | 'active' | 'disconnected';
export type PaymentRail = 'stripe' | 'x402';
export type PaymentState = 'pending' | 'succeeded' | 'failed' | 'refunded' | 'disputed';
export type PaymentLinkKind = 'payment_link' | 'checkout_session';
export type PaymentLinkState = 'active' | 'deactivated' | 'completed' | 'expired';

export interface StripeConnection {
  id: string;
  account_id: string;
  state: StripeConnectionState;
  mode: 'live' | 'test' | null;
  /** The last four characters of the restricted key. */
  key_hint: string | null;
  /** Where the customer's Stripe sends payment events. One address per connection. */
  webhook_url: string;
  webhook_events: string[];
  /**
   * The page the customer opens to paste the restricted key and the signing
   * secret: a single-use link `startStripe` makes for the owner while the
   * connection awaits its key. An agent's call gets none: ask the owner to
   * start the connection.
   */
  connect_url: string | null;
  created_at: string;
}

export interface CreatePaymentLinkInput {
  name: string;
  /** In the currency's smallest unit (cents for usd). */
  amount_minor: number;
  /** A three-letter code; `usd` when omitted. */
  currency?: string;
  /** The agent's own label, returned on each payment. */
  item?: string;
  /** Where the buyer lands afterwards. Must be on the agent's own site. */
  after_payment_url?: string;
}

export interface CreateCheckoutSessionInput {
  name: string;
  amount_minor: number;
  currency?: string;
  item?: string;
  /** Both addresses must be on the agent's own site. */
  success_url: string;
  cancel_url?: string;
}

export interface PaymentLink {
  id: string;
  kind: PaymentLinkKind;
  /** What the buyer opens. */
  url: string;
  name: string;
  amount_minor: number;
  currency: string;
  item: string | null;
  state: PaymentLinkState;
  created_at: string;
}

export interface Payment {
  id: string;
  rail: PaymentRail;
  state: PaymentState;
  /** Smallest unit of the currency; for usdc, millionths. */
  amount_minor: number;
  refunded_minor: number;
  currency: string;
  /** A decimal string a person can read, such as `12.50`. */
  amount: string;
  item: string | null;
  link_id: string | null;
  /** x402: the paying wallet and the Base transaction. Public chain data. */
  payer: string | null;
  tx_hash: string | null;
  created_at: string;
  settled_at: string | null;
}

export interface ListPaymentLinksQuery {
  /** 1 to 100, default 50. */
  limit?: number;
}

export interface ListPaymentsQuery {
  rail?: PaymentRail;
  /** 1 to 100, default 50. */
  limit?: number;
  /** `next_cursor` of the previous page. */
  cursor?: string;
}

export interface ListPaymentsResult {
  payments: Payment[];
  next_cursor: string | null;
}

const seg = encodeURIComponent;

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

/** The account's agent asks to be paid; the owner's credential alone is refused, so refuse before sending. */
function agentPassport(options: AccountAgentCallOptions | undefined): { headers: Record<string, string> } {
  if (!options?.passportToken) {
    throw new TypeError("passportToken is required: the account's agent does this, under its Passport");
  }
  return { headers: { 'X-Passport-Token': options.passportToken } };
}

export class PaymentsService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Start the customer's Stripe connection, or return the open one. It is
   * `awaiting_key`: the customer opens `connect_url`, adds `webhook_url` with
   * `webhook_events` as an endpoint in their Stripe, and pastes a restricted
   * key and that endpoint's signing secret on the page. Called by an agent it
   * returns the connection without a `connect_url`.
   */
  async startStripe(accountId: string, options?: AccountAgentCallOptions): Promise<StripeConnection> {
    return this.client.post<StripeConnection>(`/v1/accounts/${seg(accountId)}/payments/stripe`, {}, passport(options));
  }

  /** The connection, or null when there is none. */
  async getStripe(accountId: string, options?: AccountAgentCallOptions): Promise<{ connection: StripeConnection | null }> {
    return this.client.get<{ connection: StripeConnection | null }>(`/v1/accounts/${seg(accountId)}/payments/stripe`, undefined, passport(options));
  }

  /** Erase the key and signing secret and turn off the active links. Owner or admin only. */
  async disconnectStripe(accountId: string): Promise<void> {
    await this.client.delete<void>(`/v1/accounts/${seg(accountId)}/payments/stripe`);
  }

  /**
   * A reusable link for one fixed price. One metered action, and a decision
   * for the customer's controls. Throws `PaymentConnectionRequiredError` when
   * there is no active connection.
   */
  async createLink(accountId: string, input: CreatePaymentLinkInput, options: AccountAgentCallOptions): Promise<PaymentLink> {
    return this.client.post<PaymentLink>(`/v1/accounts/${seg(accountId)}/payments/links`, input, agentPassport(options));
  }

  /** A one-off checkout session for one fixed price. Metered and decided like `createLink`. */
  async createCheckoutSession(accountId: string, input: CreateCheckoutSessionInput, options: AccountAgentCallOptions): Promise<PaymentLink> {
    return this.client.post<PaymentLink>(`/v1/accounts/${seg(accountId)}/payments/checkout-sessions`, input, agentPassport(options));
  }

  async listLinks(accountId: string, query: ListPaymentLinksQuery = {}, options?: AccountAgentCallOptions): Promise<{ links: PaymentLink[] }> {
    return this.client.get<{ links: PaymentLink[] }>(
      `/v1/accounts/${seg(accountId)}/payments/links`,
      { limit: query.limit !== undefined ? String(query.limit) : undefined },
      passport(options),
    );
  }

  /** Turn a link off so it can no longer be paid. */
  async deactivateLink(accountId: string, linkId: string, options: AccountAgentCallOptions): Promise<PaymentLink> {
    return this.client.post<PaymentLink>(`/v1/accounts/${seg(accountId)}/payments/links/${seg(linkId)}/deactivate`, undefined, agentPassport(options));
  }

  /** Payments received on either rail, newest first. */
  async listPayments(accountId: string, query: ListPaymentsQuery = {}, options?: AccountAgentCallOptions): Promise<ListPaymentsResult> {
    return this.client.get<ListPaymentsResult>(
      `/v1/accounts/${seg(accountId)}/payments`,
      {
        rail: query.rail,
        limit: query.limit !== undefined ? String(query.limit) : undefined,
        cursor: query.cursor,
      },
      passport(options),
    );
  }

  async getPayment(accountId: string, paymentId: string, options?: AccountAgentCallOptions): Promise<Payment> {
    return this.client.get<Payment>(`/v1/accounts/${seg(accountId)}/payments/${seg(paymentId)}`, undefined, passport(options));
  }
}
