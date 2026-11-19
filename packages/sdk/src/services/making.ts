import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions, AccountGovernedOptions } from './accounts.js';

// Making: the account's agent uploads a design (a 3D model, a CNC part, print
// artwork), gets quotes from manufacturing and print-on-demand suppliers,
// orders and tracks. STACK is the plumbing: which files and destinations a
// supplier accepts is the supplier's answer, passed back as it gives it (a
// supplier that declines is in the quote's `unavailable` list with its reason).
//
// Two ways an order is paid, by supplier:
//   - `checkout_page` (afn, craftcloud): the order answers with a hosted
//     checkout page (`order.checkout`). The agent pays on it with the account's
//     card checkout (`accounts.browser.checkout`), which the customer approves
//     on their own device.
//   - `customer_account` (gelato, prodigi, printful, lulu): the supplier charges
//     the customer's own account there. The order is held (`awaiting_approval`)
//     until the customer approves it (`approveOrder`). STACK's own money never
//     pays a supplier.
//
// Refusals and failures surface as a `StackError` whose `code` to branch on is
// one of MAKING_SUPPLIER_ACCOUNT_REQUIRED (409), MAKING_SUPPLIER_REJECTED
// (422), MAKING_QUOTE_EXPIRED (409), MAKING_ORDER_STATE (409) and
// MAKING_UNAVAILABLE (503; nothing was ordered or charged, retry later).

export type MakingSupplier = 'afn' | 'craftcloud' | 'gelato' | 'prodigi' | 'printful' | 'lulu';
export type MakingPaymentModel = 'checkout_page' | 'customer_account';
export type MakingOrderState =
  | 'awaiting_approval' | 'awaiting_payment' | 'placed' | 'in_production' | 'shipped'
  | 'delivered' | 'cancelled' | 'rejected' | 'expired' | 'failed'
  /** Still on its way 90 days after it was placed: STACK stopped following it, and the agent was told. */
  | 'tracking_stopped';

/**
 * The design file: its bytes as base64 or an https address STACK fetches it from (up to 20 MB, what one request carries), or
 * a file already on the agent's drive by its id (any size the drive holds; nothing is copied and the file is streamed to the
 * supplier). Exactly one.
 */
export type MakingUploadDesignInput = {
  /** What the part or artwork is, up to 500 characters. */
  description?: string;
} & (
  | {
      /** With an extension, such as part.stl; the extension is the format, and each supplier says which formats it takes. */
      file_name: string;
      content_base64: string;
      source_url?: never;
      drive_file_id?: never;
    }
  | { file_name: string; source_url: string; content_base64?: never; drive_file_id?: never }
  | {
      /** A drive file's own name is used when this is left out, and it needs an extension. */
      file_name?: string;
      drive_file_id: string;
      content_base64?: never;
      source_url?: never;
    }
);

/** Where the order goes. Whether a supplier ships there is the supplier's answer. */
export interface MakingRecipient {
  name: string;
  company?: string;
  email: string;
  phone: string;
  address1: string;
  address2?: string;
  city: string;
  /** The state, province or region code, where the country has one. */
  state?: string;
  postal_code: string;
  /** Two-letter ISO 3166-1 country code. */
  country: string;
}

/** What to make. Which fields a supplier reads depends on the supplier; the others ignore the rest. */
export interface MakingSpec {
  /** 1 to 1000, default 1. */
  quantity?: number;
  /** Agentic Fabrication Network process: fdm_print, resin_print, cnc, sheetmetal, laser_cut. */
  process?: string;
  material?: string;
  finish?: string;
  color?: string;
  /** The unit of a mesh file that carries none (STL). */
  unit?: 'mm' | 'cm' | 'in';
  /** Print on demand: the supplier's own product id (Gelato productUid, Prodigi sku, Printful catalog variant id, Lulu pod package id). */
  product?: string;
  /** Print on demand: the product's attributes, as the supplier names them, at most 12 (Prodigi). */
  attributes?: Record<string, string>;
  /** Print on demand: where the artwork goes (Printful placement). */
  placement?: string;
  /** Lulu: pages in the interior file. */
  page_count?: number;
  /** The shipping speed preferred; the cheapest offer is returned when unset. */
  shipping?: 'cheapest' | 'fastest';
}

export interface MakingQuoteInput {
  design_id: string;
  /** One supplier, or every supplier that is set up when omitted. */
  supplier?: MakingSupplier;
  spec?: MakingSpec;
  recipient: MakingRecipient;
}

/** The customer's own account at a print-on-demand supplier. The owner enters it, and it is never shown again. */
export interface MakingSupplierCredentialInput {
  api_key: string;
  /** Lulu: the API secret that goes with the key. */
  api_secret?: string;
  /** Printful: the store the orders belong to, when the token spans several. */
  store_id?: string;
}

export interface MakingDesign {
  id: string;
  account_id: string;
  file_name: string;
  format: string;
  size_bytes: number;
  /** SHA-256 of the file: the same value is in the record of every quote and order. */
  sha256: string;
  /** The drive file the design was made from; null for a design sent as bytes. */
  drive_file_id: string | null;
  created_at: string;
}

export interface MakingQuote {
  id: string;
  account_id: string;
  design_id: string;
  design_sha256: string;
  supplier: MakingSupplier;
  payment: MakingPaymentModel;
  /** What the offer is, in the supplier's words (vendor, material, process, shipping). */
  summary: string;
  quantity: number;
  currency: string;
  item_minor: number;
  shipping_minor: number;
  /** Null when the supplier stated no tax. */
  tax_minor: number | null;
  total_minor: number;
  /** The total in US cents. */
  total_cents: number;
  lead_days: { min: number; max: number } | null;
  destination: { country: string; state: string; postal_code: string };
  state: 'open' | 'ordered' | 'expired';
  /** When the supplier stops honouring the price; null when it states no end. */
  expires_at: string | null;
  created_at: string;
}

export interface MakingQuoteResult {
  quotes: MakingQuote[];
  /** Suppliers that gave no offer, and why, in the supplier's own words where it gave one (not connected, unavailable, unsupported file or destination). */
  unavailable: Array<{ supplier: MakingSupplier; code: string }>;
}

export interface MakingTracking {
  carrier: string | null;
  number: string | null;
  url: string | null;
}

export interface MakingOrder {
  id: string;
  account_id: string;
  quote_id: string;
  design_id: string;
  design_sha256: string;
  supplier: MakingSupplier;
  payment: MakingPaymentModel;
  state: MakingOrderState;
  /** The supplier's own status word, as last read. */
  supplier_status: string | null;
  currency: string;
  total_minor: number;
  total_cents: number;
  /** A checkout page to pay on with the account's card checkout; present while the order awaits payment. */
  checkout: { url: string; origin: string; amount_minor: number; currency: string } | null;
  /** True while the customer has not yet approved a held order. */
  needs_approval: boolean;
  tracking: MakingTracking[];
  eta: string | null;
  failure_code: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export interface MakingSupplierAccount {
  supplier: MakingSupplier;
  payment: MakingPaymentModel;
  /** Whether the supplier can be used at all: STACK's own access for a checkout supplier, the customer's own account for the others. */
  available: boolean;
  /** Customer-account suppliers only: whether this customer connected their own. */
  connected: boolean | null;
}

export interface ListMakingQuery {
  /** 1 to 200, default 50. */
  limit?: number;
}

const seg = encodeURIComponent;

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

function governed(options?: AccountGovernedOptions): { headers: Record<string, string> } | undefined {
  return options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined;
}

function limitQuery(query: ListMakingQuery): Record<string, string | undefined> {
  return { limit: query.limit !== undefined ? String(query.limit) : undefined };
}

/**
 * Making on an agent account (`/v1/accounts/:id/making/*`). Uploading,
 * quoting and ordering are the account's agent acting under its Passport
 * (`passportToken`, required), each one metered action and asked of the
 * customer's controls first; a refusal is never charged. Reads and `cancelOrder`
 * work for the agent (with its Passport) or its operator. `approveOrder`,
 * `rejectOrder` and the supplier accounts are the customer's own decisions:
 * operator only, an agent context is refused.
 */
export class MakingService {
  constructor(private readonly client: HttpClient) {}

  private base(accountId: string): string {
    return `/v1/accounts/${seg(accountId)}/making`;
  }

  /**
   * Make a design from bytes (up to 20 MB, which is what one request carries) or from a file on the agent's drive, by its id
   * (any size; the file is read from the drive and streamed to the supplier). The same file again returns the same design.
   */
  async uploadDesign(accountId: string, input: MakingUploadDesignInput, options: AccountAgentCallOptions): Promise<MakingDesign> {
    return this.client.post<MakingDesign>(`${this.base(accountId)}/designs`, input, passport(options));
  }

  async getDesign(accountId: string, designId: string, options?: AccountAgentCallOptions): Promise<MakingDesign> {
    return this.client.get<MakingDesign>(`${this.base(accountId)}/designs/${seg(designId)}`, undefined, passport(options));
  }

  async listDesigns(accountId: string, query: ListMakingQuery = {}, options?: AccountAgentCallOptions): Promise<{ designs: MakingDesign[] }> {
    return this.client.get<{ designs: MakingDesign[] }>(`${this.base(accountId)}/designs`, limitQuery(query), passport(options));
  }

  /**
   * Ask the suppliers. `quotes` is the offers, cheapest first; `unavailable`
   * names a supplier that gave none, with its reason. A request that produced
   * no offer is not charged.
   */
  async quote(accountId: string, input: MakingQuoteInput, options: AccountAgentCallOptions): Promise<MakingQuoteResult> {
    return this.client.post<MakingQuoteResult>(`${this.base(accountId)}/quotes`, input, passport(options));
  }

  async getQuote(accountId: string, quoteId: string, options?: AccountAgentCallOptions): Promise<MakingQuote> {
    return this.client.get<MakingQuote>(`${this.base(accountId)}/quotes/${seg(quoteId)}`, undefined, passport(options));
  }

  /**
   * Order a quote. A `customer_account` supplier's order comes back
   * `awaiting_approval` (202) and waits for the customer's `approveOrder`; a
   * `checkout_page` supplier's order comes back with `checkout`, a page to pay
   * on with `accounts.browser.checkout`. Ordering the same quote again returns
   * the same order.
   */
  async order(accountId: string, quoteId: string, options: AccountAgentCallOptions): Promise<MakingOrder> {
    return this.client.post<MakingOrder>(`${this.base(accountId)}/orders`, { quote_id: quoteId }, passport(options));
  }

  /** The order as last known; a read refreshes it from the supplier first. */
  async getOrder(accountId: string, orderId: string, options?: AccountAgentCallOptions): Promise<MakingOrder> {
    return this.client.get<MakingOrder>(`${this.base(accountId)}/orders/${seg(orderId)}`, undefined, passport(options));
  }

  async listOrders(accountId: string, query: ListMakingQuery = {}, options?: AccountAgentCallOptions): Promise<{ orders: MakingOrder[] }> {
    return this.client.get<{ orders: MakingOrder[] }>(`${this.base(accountId)}/orders`, limitQuery(query), passport(options));
  }

  /** Stop an order while the supplier still can. It only narrows what happens, so the agent may do it as well as the operator. */
  async cancelOrder(accountId: string, orderId: string, options?: AccountAgentCallOptions): Promise<MakingOrder> {
    return this.client.post<MakingOrder>(`${this.base(accountId)}/orders/${seg(orderId)}/cancel`, undefined, passport(options));
  }

  /**
   * Place a held order on the customer's own supplier account. Operator only,
   * and a governance action: without a dashboard session this throws
   * `GovernanceApprovalRequiredError`; a person approves at its `approvalUrl`,
   * then retry with its `approvalId`.
   */
  async approveOrder(accountId: string, orderId: string, options?: AccountGovernedOptions): Promise<MakingOrder> {
    return this.client.post<MakingOrder>(`${this.base(accountId)}/orders/${seg(orderId)}/approve`, undefined, governed(options));
  }

  /** Decline a held order. Operator only. */
  async rejectOrder(accountId: string, orderId: string): Promise<MakingOrder> {
    return this.client.post<MakingOrder>(`${this.base(accountId)}/orders/${seg(orderId)}/reject`);
  }

  /** Every supplier, with whether it is usable and, for print on demand, whether the customer connected their own account. Operator only. */
  async listSuppliers(): Promise<{ suppliers: MakingSupplierAccount[] }> {
    return this.client.get<{ suppliers: MakingSupplierAccount[] }>('/v1/accounts/making/suppliers');
  }

  /**
   * Connect the customer's own account at a print-on-demand supplier (gelato,
   * prodigi, printful or lulu). Operator owner or admin only; the key is
   * encrypted at rest and never read back. An agent never sets this up, so
   * keep the key out of any chat.
   */
  async connectSupplier(supplier: MakingSupplier, credential: MakingSupplierCredentialInput): Promise<MakingSupplierAccount> {
    return this.client.put<MakingSupplierAccount>(`/v1/accounts/making/suppliers/${seg(supplier)}`, credential);
  }

  /**
   * Connect the customer's own Printful account by signing in at Printful instead of pasting a token: returns
   * `authorize_url`, which the owner opens in a browser, signing in or up at Printful and approving on Printful's own
   * screen. STACK then stores the tokens sealed for the customer and renews them; no token passes through this program or a
   * chat. Owner or admin only. 503 `PRINTFUL_APP_NOT_REGISTERED` where STACK has not registered its Printful app (paste a
   * token with `connectSupplier` instead).
   */
  async connectPrintful(): Promise<{ authorize_url: string; expires_in_seconds: number }> {
    return this.client.post<{ authorize_url: string; expires_in_seconds: number }>('/v1/accounts/making/suppliers/printful/connect');
  }

  /** Remove the customer's account at a supplier. Owner or admin only. */
  async disconnectSupplier(supplier: MakingSupplier): Promise<void> {
    await this.client.delete<void>(`/v1/accounts/making/suppliers/${seg(supplier)}`);
  }
}
