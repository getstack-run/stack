import type { HttpClient } from '../client.js';
import { walletPaymentAuthorizationPayload, type AgentWalletKey } from '../wallet-key.js';
import type { AccountAgentCallOptions } from './accounts.js';

// RentAHuman for a customer's agents: the agent hires people for real-world tasks through the customer's own RentAHuman account.
//
// - Connect the customer's own key at the Console (the service `rentahuman`), or let the agent open an account itself with its own
//   wallet (`join`, below): STACK keeps the key in the vault and the agent and its model never see it.
// - Call RentAHuman through the connection with `stack.proxy.serviceTools('rentahuman')` and `stack.proxy.serviceCallTool('rentahuman',
//   tool, args)`: searching people, posting and funding a bounty, reading applications and conversations, and writing to a person
//   (`send_message`, `get_conversation`, `list_conversations`).
// - A person applying, delivering or writing wakes the agent (wake source `service_event`): the wake carries the service, the kind of
//   event and its ids, never what the person wrote; the agent reads the rest through the connection and replies the same way.
//
// Opening an account and topping its wallet up are two steps because only the agent can sign for its own wallet: `join` makes the
// payment RentAHuman asks for and returns what to sign; the agent signs it with its wallet key and `completeJoin` sends the signature,
// which goes through the wallet's caps and the customer's decider like any payment from the wallet. `joinWithKey` and `fundWithKey` do both.

/** The payment the agent signs, and what to sign it with. */
interface PaymentToSign {
  /** What RentAHuman asks, in US cents (USDC on Base). Look at it before signing. */
  amount_cents: number;
  /** The address RentAHuman is paid at. */
  pay_to: string;
  /** The EIP-712 TransferWithAuthorization, as the wallet takes it. */
  typed_data: Record<string, unknown>;
  /** The account's wallet at Privy: with `typed_data` it makes the string the agent signs. */
  wallet: { privy_app_id: string; wallet_id: string };
  /** Sign before this time. */
  expires_at: string;
}

export interface RentAHumanJoinInput {
  /** The country the agent works in: an ISO code ("US") or a name. */
  country: string;
  city?: string;
  /** The display name of the new account at RentAHuman (at least 2 characters; RentAHuman refuses one it will not take). */
  agent_name?: string;
  /** The customer accepting RentAHuman's terms of service and privacy policy through its agent. */
  accept_terms: true;
}

export interface RentAHumanJoinStart extends PaymentToSign {
  join_id: string;
}

export interface RentAHumanFundStart extends PaymentToSign {
  fund_id: string;
}

export type RentAHumanFlowStatus = 'awaiting_signature' | 'paying' | 'completed' | 'unconfirmed' | 'failed' | 'expired';

export interface RentAHumanJoinResult {
  join_id: string;
  status: RentAHumanFlowStatus;
  /** The customer's `rentahuman` connection, now holding the new account's key (never returned). */
  connection_id: string;
  agent_id: string;
  /** Whether the account's events wake the agent. False: call `completeJoin` again with the same `join_id` to register them. */
  wake_registered: boolean;
}

export interface RentAHumanFundResult {
  fund_id: string;
  status: RentAHumanFlowStatus;
  amount_cents: number;
}

export interface RentAHumanConnection {
  connection_id: string;
  origin: 'owner_key' | 'joined';
  wake_registered: boolean;
  created_at: string;
}

const seg = encodeURIComponent;

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

/** What the agent signs for a payment `join` or `fund` returned: Privy's authorization payload for the wallet's signing request. */
export function signRentAHumanPayment(key: AgentWalletKey, start: PaymentToSign): string {
  return key.sign(
    walletPaymentAuthorizationPayload({ appId: start.wallet.privy_app_id, walletId: start.wallet.wallet_id, typedData: start.typed_data }),
  );
}

export class RentAHumanService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Step one of opening a RentAHuman account for the customer, paid from the agent's wallet: asks RentAHuman what it costs and returns
   * the payment to sign. Takes nothing. One metered action. `accept_terms: true` is the customer accepting RentAHuman's terms.
   */
  async join(accountId: string, input: RentAHumanJoinInput, options?: AccountAgentCallOptions): Promise<RentAHumanJoinStart> {
    return this.client.post<RentAHumanJoinStart>(`/v1/accounts/${seg(accountId)}/rentahuman/join`, input, passport(options));
  }

  /**
   * Step two: `signed` is the agent's signature (`signRentAHumanPayment`). Only the account's own agent, under its Passport. The
   * payment goes through the wallet's per-payment and daily caps, the account's budget and the customer's decider; RentAHuman's key goes
   * into the vault. Called again with the same `join_id` it answers the same and, when the account's events were not registered, tries again.
   */
  async completeJoin(accountId: string, input: { join_id: string; signed: string }, options: AccountAgentCallOptions): Promise<RentAHumanJoinResult> {
    return this.client.post<RentAHumanJoinResult>(`/v1/accounts/${seg(accountId)}/rentahuman/join/complete`, input, passport(options));
  }

  /** Both steps: ask, sign with the agent's wallet key, and send the signature. */
  async joinWithKey(accountId: string, key: AgentWalletKey, input: RentAHumanJoinInput, options: AccountAgentCallOptions): Promise<RentAHumanJoinResult> {
    const start = await this.join(accountId, input, options);
    return this.completeJoin(accountId, { join_id: start.join_id, signed: signRentAHumanPayment(key, start) }, options);
  }

  /** Step one of topping up the customer's RentAHuman wallet with USDC from the agent's wallet (`amount_cents` from 100 to 1,000,000). */
  async fund(accountId: string, amountCents: number, options?: AccountAgentCallOptions): Promise<RentAHumanFundStart> {
    return this.client.post<RentAHumanFundStart>(`/v1/accounts/${seg(accountId)}/rentahuman/fund`, { amount_cents: amountCents }, passport(options));
  }

  /** Step two of a top-up: the agent's signature of the payment `fund` returned. */
  async completeFund(accountId: string, input: { fund_id: string; signed: string }, options: AccountAgentCallOptions): Promise<RentAHumanFundResult> {
    return this.client.post<RentAHumanFundResult>(`/v1/accounts/${seg(accountId)}/rentahuman/fund/complete`, input, passport(options));
  }

  /** Both steps of a top-up. */
  async fundWithKey(accountId: string, key: AgentWalletKey, amountCents: number, options: AccountAgentCallOptions): Promise<RentAHumanFundResult> {
    const start = await this.fund(accountId, amountCents, options);
    return this.completeFund(accountId, { fund_id: start.fund_id, signed: signRentAHumanPayment(key, start) }, options);
  }

  /** The customer's RentAHuman connection, or null when there is none. It shows no key. */
  async get(accountId: string, options?: AccountAgentCallOptions): Promise<{ connection: RentAHumanConnection | null }> {
    return this.client.get<{ connection: RentAHumanConnection | null }>(`/v1/accounts/${seg(accountId)}/rentahuman`, undefined, passport(options));
  }
}
