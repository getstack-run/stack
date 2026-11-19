import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions } from './accounts.js';

// Post for agent accounts: one US street address per customer that receives
// and scans post (mailbox.bot), and letters and postcards out (Lob or PostGrid).
//
// The address is the customer's own. The customer signs up at the supplier,
// completes USPS Form 1583 there (two IDs and a short notary video call; STACK
// never sees the documents), creates an agent key there and gives it to
// `post.connectAddress`. Each agent has its own ATTN line on the shared
// address, and post is routed to the agent whose line is on the envelope.
// Received post and scans arrive as account messages of channel `post`.
//
// A scan, forward or shred is proposed at the supplier by the agent's key and
// approved by the owner there; the supplier bills the owner's own account for
// it. A letter or postcard is held and charged on the account's credit at the
// provider's cost, from the customer's own identified address.

export type PostalAddressStatus = 'pending_identity' | 'active' | 'suspended' | 'closed';
export type PostalSuspendReason = 'supplier' | 'owner' | 'unpaid';
export type PostalItemKind = 'letter' | 'flat' | 'parcel';
export type PostalItemCustodyStatus =
  | 'received' | 'stored' | 'held' | 'forwarding' | 'forwarded' | 'returning' | 'returned' | 'shredded' | 'disposed' | 'exception';
export type PostalRouting = 'routed' | 'pending' | 'unassigned';
/** How an agent reads an item: `offered` names no agent and any agent of the account may take it; `taken` was taken by `taken_by_agent_id`. */
export type PostalItemRouting = PostalRouting | 'offered' | 'taken';
export type PostalItemAction = 'scan' | 'forward' | 'shred';
export type PostalActionStatus = 'requested' | 'requires_approval' | 'approved' | 'in_progress' | 'done' | 'rejected' | 'failed' | 'cancelled';
/** `tracking_stopped`: still on its way 60 days after it was sent; STACK stopped following it, and the agent was told. */
export type LetterState = 'submitting' | 'sent' | 'in_transit' | 'delivered' | 'returned' | 'failed' | 'cancelled' | 'tracking_stopped';

/** A recipient or a forwarding destination. A US address needs a two-letter state. */
export interface PostalRecipientAddress {
  name?: string;
  company?: string;
  line1: string;
  line2?: string;
  city: string;
  state?: string;
  postal_code: string;
  /** ISO 3166-1 alpha-2, default US. */
  country?: string;
}

export interface PostalAddress {
  id: string;
  supplier: 'mailbox_bot';
  status: PostalAddressStatus;
  suspend_reason: PostalSuspendReason | null;
  /** The supplier's own pages, where the customer signs up and completes Form 1583. Null once active. */
  identity: { url: string | null; note: string | null };
  address: { street: string; suite: string | null; city: string | null; state: string | null; postal_code: string | null; country: 'US' } | null;
  /** Where the supplier's webhook for this address points, and whether STACK holds a secret to check it. */
  webhook: { url: string; signed: boolean };
  /** What STACK charges monthly; null while the supplier bills the customer directly. */
  monthly_fee_cents: number | null;
  last_error_code: string | null;
  activated_at: string | null;
  created_at: string;
}

export interface ConnectPostalAddressInput {
  /** The agent-scoped key created at the supplier. A sandbox key and the account-wide key are refused. */
  api_key: string;
  /** The `whsec_` secret of the webhook endpoint created at the supplier, for faster delivery. Optional. */
  webhook_secret?: string;
}

/** What an agent prints on a form: its own line on the shared address. */
export interface AccountPostalAddress {
  status: PostalAddressStatus;
  mailing: {
    attn: string;
    street: string;
    suite: string | null;
    city: string | null;
    state: string | null;
    postal_code: string | null;
    country: 'US';
  } | null;
  note: string;
}

export interface PostalItemActionView {
  id: string;
  action: PostalItemAction;
  status: PostalActionStatus;
  /** What the supplier quoted, in US cents. The supplier charges the owner's own account. */
  quote_cents: number | null;
  /** The message holding a scan's text, once it arrived. */
  message_id: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface PostalItem {
  id: string;
  reference_code: string | null;
  kind: PostalItemKind;
  custody_status: PostalItemCustodyStatus;
  routing: PostalItemRouting;
  account_id: string | null;
  /** Set when `routing` is `taken`: the agent that took the item first. */
  taken_by_agent_id: string | null;
  /** The message that told the agent the item arrived. Its text is untrusted third-party content. */
  message_id: string | null;
  received_at: string;
  actions: PostalItemActionView[];
}

export interface ListPostalItemsQuery {
  /** 1 to 50, default 20. */
  limit?: number;
  cursor?: string;
  /** The owner's list only. */
  routing?: PostalRouting;
}

export interface ListPostalItemsResult {
  items: PostalItem[];
  next_cursor: string | null;
}

export interface AddressCheck {
  deliverability: 'deliverable' | 'undeliverable';
  provider_deliverability: string | null;
  standardized: PostalRecipientAddress | null;
  notes: string[];
}

interface SendCommon {
  to: PostalRecipientAddress;
  /** Who the post is from: the name on the return address, above the agent's line. Required, up to 40 characters. */
  sender_name: string;
  /** The sender address printed on the letter. Without it, the account's street address is used. Returned post goes to this address. A US address, checked like the recipient's. */
  return_address?: PostalRecipientAddress;
  /** 8 to 128 characters. Name each of two identical letters; the request itself is the default. */
  idempotency_key?: string;
  description?: string;
  /** Promotion is `marketing`; the providers treat the two differently. Required. */
  use_type: 'operational' | 'marketing';
}

export interface SendLetterInput extends SendCommon {
  kind?: 'letter';
  /** Plain text, or a PDF as base64 (4 MiB decoded; pages are the provider's own limit: Lob's 60 single-sided or 120 double-sided, 6 or 12 for a letter abroad). */
  content: { text: string } | { pdf_base64: string };
  color?: boolean;
  double_sided?: boolean;
  mail_class?: 'first_class' | 'standard';
  /** Certified mail goes first class. */
  extra_service?: 'certified' | 'certified_return_receipt';
}

export interface SendPostcardInput extends SendCommon {
  kind: 'postcard';
  size?: '4x6' | '6x9';
  /** Text only: a postcard from a PDF is not offered. */
  front: { text: string };
  back: { text: string };
}

export interface Letter {
  id: string;
  account_id: string;
  kind: 'letter' | 'postcard';
  provider: 'lob' | 'postgrid';
  /** `submitting` means the provider has not answered yet; STACK retries under the same key. */
  state: LetterState;
  /** SHA-256 of the content the provider was given; also in the signed record. */
  content_sha256: string;
  page_count: number | null;
  recipient_country: string;
  held_cents: number;
  charged_cents: number | null;
  expected_delivery: string | null;
  preview_url: string | null;
  events: Array<{ name: string; occurred_at: string; location: string | null }>;
  last_error_code: string | null;
  created_at: string;
  sent_at: string | null;
}

export interface ListLettersQuery {
  limit?: number;
  cursor?: string;
}

export interface ListLettersResult {
  letters: Letter[];
  next_cursor: string | null;
}

export interface PostAgentCallOptions extends AccountAgentCallOptions {
  /** Names one action; a retry with the same key and input is the same action. */
  idempotencyKey?: string;
}

const seg = encodeURIComponent;

function headers(options?: PostAgentCallOptions): { headers: Record<string, string> } | undefined {
  const out: Record<string, string> = {};
  if (options?.passportToken) out['X-Passport-Token'] = options.passportToken;
  if (options?.idempotencyKey) out['Idempotency-Key'] = options.idempotencyKey;
  return Object.keys(out).length > 0 ? { headers: out } : undefined;
}

function query(q: { limit?: number; cursor?: string; routing?: string }): Record<string, string | undefined> {
  return { limit: q.limit !== undefined ? String(q.limit) : undefined, cursor: q.cursor, routing: q.routing };
}

export class PostService {
  constructor(private readonly client: HttpClient) {}

  // ─── the customer's street address (owner or admin) ───────────────

  /** What the address is and what it waits for. 404 before the owner starts one. */
  async getAddress(): Promise<PostalAddress> {
    return this.client.get<PostalAddress>('/v1/post/address');
  }

  /** Start the address: the customer's own steps at the supplier come next (`identity.url`). */
  async startAddress(): Promise<PostalAddress> {
    return this.client.post<PostalAddress>('/v1/post/address');
  }

  /** Hand over the agent key the customer created at the supplier. Never returned; never through a chat tool. */
  async connectAddress(input: ConnectPostalAddressInput): Promise<PostalAddress> {
    return this.client.post<PostalAddress>('/v1/post/address/connect', input);
  }

  /** Look at the supplier again now. */
  async refreshAddress(): Promise<PostalAddress> {
    return this.client.post<PostalAddress>('/v1/post/address/refresh');
  }

  async pauseAddress(): Promise<PostalAddress> {
    return this.client.post<PostalAddress>('/v1/post/address/pause');
  }

  /** Lifts the owner's own pause; an unpaid or supplier suspension is not the owner's to lift. */
  async resumeAddress(): Promise<PostalAddress> {
    return this.client.post<PostalAddress>('/v1/post/address/resume');
  }

  /** Disconnect: STACK forgets the supplier key and the mailbox's own details (its address, private mailbox number and ids). The mailbox at the supplier is untouched, and every item and scan already received stays. */
  async closeAddress(): Promise<PostalAddress> {
    return this.client.delete<PostalAddress>('/v1/post/address');
  }

  /** Every item at the address, including those no agent has taken yet (`routing: 'unassigned'`: offered to every agent of the account). */
  async listItems(q: ListPostalItemsQuery = {}): Promise<ListPostalItemsResult> {
    return this.client.get<ListPostalItemsResult>('/v1/post/items', query(q));
  }

  /** Give an item that no agent has taken to an account. */
  async assignItem(itemId: string, accountId: string): Promise<PostalItem> {
    return this.client.post<PostalItem>(`/v1/post/items/${seg(itemId)}/assign`, { account_id: accountId });
  }

  // ─── an account's post ────────────────────────────────────────────

  /** The agent's own line on the address, to print on a form. */
  async accountAddress(accountId: string, options?: PostAgentCallOptions): Promise<AccountPostalAddress> {
    return this.client.get<AccountPostalAddress>(`/v1/accounts/${seg(accountId)}/post/address`, undefined, headers(options));
  }

  async listAccountItems(accountId: string, q: ListPostalItemsQuery = {}, options?: PostAgentCallOptions): Promise<ListPostalItemsResult> {
    return this.client.get<ListPostalItemsResult>(`/v1/accounts/${seg(accountId)}/post/items`, query(q), headers(options));
  }

  async getAccountItem(accountId: string, itemId: string, options?: PostAgentCallOptions): Promise<PostalItem> {
    return this.client.get<PostalItem>(`/v1/accounts/${seg(accountId)}/post/items/${seg(itemId)}`, undefined, headers(options));
  }

  /** Ask the supplier to open and scan an item. The owner approves at the supplier; the text then arrives as a message. */
  async scanItem(accountId: string, itemId: string, input: { capture?: 'document_pdf' | 'contents_photos' | 'both' } = {}, options?: PostAgentCallOptions): Promise<PostalItem> {
    return this.client.post<PostalItem>(`/v1/accounts/${seg(accountId)}/post/items/${seg(itemId)}/scan`, input, headers(options));
  }

  /** Ask the supplier to forward an item inside the US. */
  async forwardItem(accountId: string, itemId: string, input: { destination: PostalRecipientAddress; mail_class?: string }, options?: PostAgentCallOptions): Promise<PostalItem> {
    return this.client.post<PostalItem>(`/v1/accounts/${seg(accountId)}/post/items/${seg(itemId)}/forward`, input, headers(options));
  }

  /** Ask the supplier to shred an item. It cannot be undone, so the request says it knows. */
  async shredItem(accountId: string, itemId: string, options?: PostAgentCallOptions): Promise<PostalItem> {
    return this.client.post<PostalItem>(`/v1/accounts/${seg(accountId)}/post/items/${seg(itemId)}/shred`, { confirm: true }, headers(options));
  }

  /** Whether an address is deliverable, and the address as the provider standardises it. */
  async checkAddress(accountId: string, address: PostalRecipientAddress, options?: PostAgentCallOptions): Promise<AddressCheck> {
    return this.client.post<AddressCheck>(`/v1/accounts/${seg(accountId)}/post/address-check`, { address }, headers(options));
  }

  /**
   * Send a letter (text or PDF) or a postcard (text). 201 when the provider
   * took it, 202 while it has not answered yet (`state: 'submitting'`; STACK
   * retries under the same key), 200 for a repeat of a request already made.
   * Refused, with nothing held: prohibited content, an undeliverable address,
   * no live street address.
   */
  async send(accountId: string, input: SendLetterInput | SendPostcardInput, options?: PostAgentCallOptions): Promise<Letter> {
    return this.client.post<Letter>(`/v1/accounts/${seg(accountId)}/post/letters`, input, headers(options));
  }

  async listLetters(accountId: string, q: ListLettersQuery = {}, options?: PostAgentCallOptions): Promise<ListLettersResult> {
    return this.client.get<ListLettersResult>(`/v1/accounts/${seg(accountId)}/post/letters`, query(q), headers(options));
  }

  /** One letter with its tracking events. */
  async getLetter(accountId: string, letterId: string, options?: PostAgentCallOptions): Promise<Letter> {
    return this.client.get<Letter>(`/v1/accounts/${seg(accountId)}/post/letters/${seg(letterId)}`, undefined, headers(options));
  }
}
