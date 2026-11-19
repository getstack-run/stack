// Paying an x402 seller from an agent account's wallet in one step: ask the URL, and when the answer is a 402, make the
// payment the seller asks for, sign it with the agent's own wallet key, let STACK check it and pass it to the wallet
// (`POST /v1/accounts/:id/wallet/payments`), and ask again with the payment attached. What the seller answers then is
// what was bought: there is no order and no checkout page.
//
// The wallet signs one kind of payment, an EIP-3009 TransferWithAuthorization of USDC on Base, which is x402's `exact`
// scheme. Both versions of x402 are read: version 2 (`PAYMENT-REQUIRED` and `PAYMENT-SIGNATURE`, the shape of STACK's
// own spec/agent-site-payments) and version 1 (the requirements in the body, the payment in `X-PAYMENT`). A seller that
// asks for anything else is refused here, before STACK is asked. A seller that wants the buyer to send the transfer
// itself and post its hash cannot be paid: the wallet signs, it never sends.
//
// The key never leaves this process and STACK never sees it. The seller's address must be https (localhost aside), and
// the paid request follows no redirect, so the signed payment goes to the one address that asked for it.

import { randomBytes } from 'node:crypto';
import { signWalletPayment, type AgentWalletKey } from './wallet-key.js';

export const BASE_CHAIN_ID = 8453;
export const BASE_CAIP2 = `eip155:${BASE_CHAIN_ID}`;
export const BASE_USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const BASE_USDC_DOMAIN_NAME = 'USD Coin';
const BASE_USDC_DOMAIN_VERSION = '2';
/** STACK refuses an authorization that lasts longer than ten minutes; this stays a minute inside it. */
const MAX_AUTHORIZATION_SECONDS = 540;
const MIN_AUTHORIZATION_SECONDS = 60;
const USDC_ATOMIC_PER_CENT = 10_000n;
const TRANSFER_FIELDS = [
  { name: 'from', type: 'address' },
  { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' },
  { name: 'validBefore', type: 'uint256' },
  { name: 'nonce', type: 'bytes32' },
] as const;

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const UINT = /^(0|[1-9][0-9]{0,77})$/;

export type X402PaymentErrorCode =
  | 'insecure_url'
  | 'unreadable_requirements'
  | 'not_payable'
  | 'over_max'
  | 'wallet_not_ready';

/** The payment was not made: nothing was signed and STACK was not asked. */
export class X402PaymentError extends Error {
  constructor(readonly code: X402PaymentErrorCode, message: string) {
    super(message);
    this.name = 'X402PaymentError';
  }
}

/** One way of paying that a seller offers, read the same for both versions. */
export interface X402Requirement {
  scheme: string;
  /** CAIP-2 (`eip155:8453`); a version 1 `base` is read as Base. */
  network: string;
  /** Atomic units of the asset, a decimal string. */
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  extra?: { name?: string; version?: string };
}

/** What a 402 asks for. `accepted` is the entry as the seller sent it, which a version 2 payment echoes back. */
export interface X402Ask {
  version: 1 | 2;
  requirement: X402Requirement;
  accepted: Record<string, unknown>;
  resource?: unknown;
}

/** The typed data as the wallet signs it (Privy's `eth_signTypedData_v4`). */
export interface TransferTypedData {
  domain: { name: string; version: string; chainId: number; verifyingContract: string };
  types: { TransferWithAuthorization: Array<{ name: string; type: string }> };
  primary_type: 'TransferWithAuthorization';
  message: { from: string; to: string; value: string; validAfter: string; validBefore: string; nonce: string };
}

/** What STACK answers for a payment it passed on (`WalletPayment`). */
export interface X402StackPayment {
  payment_id: string;
  signature: string;
  amount_atomic: string;
  amount_cents: number;
}

/** The account's wallet, from its `wallet` piece details. */
export interface X402Wallet {
  address: string;
  walletId: string;
  appId: string;
}

export interface PayX402Options {
  /** The agent's wallet key (`loadAgentWalletKey`). It signs here and is never sent anywhere. */
  key: AgentWalletKey;
  /** The most this one purchase may cost, in cents. The wallet's own caps apply whatever this says. */
  maxCents?: number;
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

export interface X402Result {
  /** False when the seller answered without asking for payment: nothing was paid. */
  paid: boolean;
  /** The seller's answer: what was bought when `paid` and `response.ok`. */
  response: Response;
  /** STACK's record of the payment. */
  payment?: X402StackPayment;
  /** The seller's settlement receipt (`PAYMENT-RESPONSE`, or `X-PAYMENT-RESPONSE` in version 1), decoded when it sent one. */
  settlement?: unknown;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeBase64Json(value: string): unknown {
  return JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
}

/** Only https carries a payment, except to this machine. */
export function assertPayableUrl(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new X402PaymentError('insecure_url', `Not a URL: ${url}`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) {
    throw new X402PaymentError('insecure_url', 'A payment is sent only over https (http only to localhost).');
  }
  return parsed;
}

function requirementOf(entry: unknown, version: 1 | 2): X402Requirement | null {
  if (!isObject(entry)) return null;
  const amount = version === 2 ? entry['amount'] : entry['maxAmountRequired'];
  const network = entry['network'] === 'base' && version === 1 ? BASE_CAIP2 : entry['network'];
  if (
    typeof entry['scheme'] !== 'string' ||
    typeof network !== 'string' ||
    typeof amount !== 'string' ||
    typeof entry['asset'] !== 'string' ||
    typeof entry['payTo'] !== 'string'
  ) {
    return null;
  }
  const extra = isObject(entry['extra']) ? entry['extra'] : undefined;
  return {
    scheme: entry['scheme'],
    network,
    amount,
    asset: entry['asset'],
    payTo: entry['payTo'],
    ...(typeof entry['maxTimeoutSeconds'] === 'number' ? { maxTimeoutSeconds: entry['maxTimeoutSeconds'] } : {}),
    ...(extra
      ? {
          extra: {
            ...(typeof extra['name'] === 'string' ? { name: extra['name'] } : {}),
            ...(typeof extra['version'] === 'string' ? { version: extra['version'] } : {}),
          },
        }
      : {}),
  };
}

function payable(requirement: X402Requirement): boolean {
  return (
    requirement.scheme === 'exact' &&
    requirement.network === BASE_CAIP2 &&
    requirement.asset.toLowerCase() === BASE_USDC_ADDRESS.toLowerCase() &&
    ADDRESS.test(requirement.payTo) &&
    !/^0x0{40}$/.test(requirement.payTo) &&
    UINT.test(requirement.amount) &&
    BigInt(requirement.amount) > 0n &&
    (requirement.extra?.name === undefined || requirement.extra.name === BASE_USDC_DOMAIN_NAME) &&
    (requirement.extra?.version === undefined || requirement.extra.version === BASE_USDC_DOMAIN_VERSION)
  );
}

/**
 * Read what a 402 asks for and pick the entry the wallet can pay: `exact`, on Base, in USDC. Version 2 is read from the
 * `PAYMENT-REQUIRED` header, version 1 from the body.
 */
export function readX402Ask(input: { paymentRequiredHeader?: string | null; bodyText?: string }): X402Ask {
  let document: unknown;
  let version: 1 | 2;
  if (input.paymentRequiredHeader) {
    try {
      document = decodeBase64Json(input.paymentRequiredHeader);
    } catch {
      throw new X402PaymentError('unreadable_requirements', 'The PAYMENT-REQUIRED header is not readable.');
    }
    version = 2;
  } else {
    try {
      document = JSON.parse(input.bodyText ?? '');
    } catch {
      throw new X402PaymentError('unreadable_requirements', 'The 402 carries no payment requirements x402 can read.');
    }
    version = 1;
  }
  if (!isObject(document) || document['x402Version'] !== version || !Array.isArray(document['accepts'])) {
    throw new X402PaymentError('unreadable_requirements', `The payment requirements are not x402 version ${version}.`);
  }
  for (const entry of document['accepts']) {
    const requirement = requirementOf(entry, version);
    if (requirement && payable(requirement)) {
      const resource = version === 2 ? document['resource'] : (entry as Record<string, unknown>)['resource'];
      return { version, requirement, accepted: entry as Record<string, unknown>, ...(resource === undefined ? {} : { resource }) };
    }
  }
  throw new X402PaymentError('not_payable', 'The seller asks for a payment the wallet cannot make: only USDC on Base with the exact scheme.');
}

/** Cents of an atomic USDC amount, rounded up (as STACK's budget counts it). */
export function centsOfAtomic(atomic: string): number {
  return Number((BigInt(atomic) + USDC_ATOMIC_PER_CENT - 1n) / USDC_ATOMIC_PER_CENT);
}

/** The authorization the wallet signs: from the wallet, to and value exactly as the seller asked. */
export function x402TransferTypedData(input: {
  requirement: X402Requirement;
  from: string;
  /** Seconds since the epoch. */
  nowSeconds: number;
  nonce?: string;
}): TransferTypedData {
  const lifetime = Math.min(Math.max(input.requirement.maxTimeoutSeconds ?? 300, MIN_AUTHORIZATION_SECONDS), MAX_AUTHORIZATION_SECONDS);
  return {
    domain: { name: BASE_USDC_DOMAIN_NAME, version: BASE_USDC_DOMAIN_VERSION, chainId: BASE_CHAIN_ID, verifyingContract: BASE_USDC_ADDRESS },
    types: { TransferWithAuthorization: TRANSFER_FIELDS.map((field) => ({ ...field })) },
    primary_type: 'TransferWithAuthorization',
    message: {
      from: input.from,
      to: input.requirement.payTo,
      value: input.requirement.amount,
      validAfter: '0',
      validBefore: String(Math.floor(input.nowSeconds) + lifetime),
      nonce: input.nonce ?? `0x${randomBytes(32).toString('hex')}`,
    },
  };
}

/** The header that carries the signed payment on the repeated request. */
export function x402PaymentHeader(input: { ask: X402Ask; typedData: TransferTypedData; signature: string }): { name: string; value: string } {
  const payload = { signature: input.signature, authorization: input.typedData.message };
  const body =
    input.ask.version === 2
      ? { x402Version: 2, ...(input.ask.resource === undefined ? {} : { resource: input.ask.resource }), accepted: input.ask.accepted, payload }
      : { x402Version: 1, scheme: 'exact', network: input.ask.accepted['network'], payload };
  return {
    name: input.ask.version === 2 ? 'PAYMENT-SIGNATURE' : 'X-PAYMENT',
    value: Buffer.from(JSON.stringify(body), 'utf8').toString('base64'),
  };
}

/** The account's wallet from its `wallet` piece; throws when the piece is not ready or lacks what a payment needs. */
export function x402WalletOf(pieces: ReadonlyArray<{ kind: string; state: string; details: Record<string, unknown> }>): X402Wallet {
  const piece = pieces.find((candidate) => candidate.kind === 'wallet');
  const details = piece?.details ?? {};
  const address = details['address'];
  const walletId = details['wallet_id'];
  const appId = details['privy_app_id'];
  if (!piece || piece.state !== 'ready' || typeof address !== 'string' || typeof walletId !== 'string' || typeof appId !== 'string') {
    throw new X402PaymentError('wallet_not_ready', 'The account has no ready wallet to pay from.');
  }
  return { address, walletId, appId };
}

/**
 * Ask `url`, and when the seller answers 402, pay it from the wallet and ask again. `pay` is STACK's payment route
 * for the account (it checks the caps, the budget and the customer's controls, and refuses or passes the payment on).
 * Throws `X402PaymentError` when nothing was paid because the ask cannot be paid; any error from `pay` (a STACK refusal)
 * is thrown as it came. Once STACK has passed the payment on, the result is returned whatever the seller answers.
 */
export async function payX402(
  url: string,
  options: PayX402Options & {
    wallet: X402Wallet;
    pay: (input: { typed_data: Record<string, unknown>; agent_signature: string }) => Promise<X402StackPayment>;
    fetch?: typeof fetch;
    nowSeconds?: () => number;
  },
): Promise<X402Result> {
  const target = assertPayableUrl(url);
  const fetchImpl = options.fetch ?? fetch;
  const method = (options.method ?? 'GET').toUpperCase();
  const init = (extra: Record<string, string>, redirect: 'follow' | 'manual'): RequestInit => ({
    method,
    headers: { ...(options.headers ?? {}), ...extra },
    ...(options.body === undefined ? {} : { body: options.body }),
    redirect,
  });

  const first = await fetchImpl(target.href, init({}, 'follow'));
  if (first.status !== 402) return { paid: false, response: first };
  // A redirect before the 402 leaves the payment for the address that asked for it, which must still be https.
  const resource = assertPayableUrl(first.url || target.href);

  const ask = readX402Ask({ paymentRequiredHeader: first.headers.get('payment-required'), bodyText: await first.text() });
  const cents = centsOfAtomic(ask.requirement.amount);
  if (options.maxCents !== undefined && cents > options.maxCents) {
    throw new X402PaymentError('over_max', `The seller asks ${cents} cents, over the most allowed (${options.maxCents}).`);
  }

  const nowSeconds = options.nowSeconds?.() ?? Math.floor(Date.now() / 1000);
  const typedData = x402TransferTypedData({ requirement: ask.requirement, from: options.wallet.address, nowSeconds });
  const signed = signWalletPayment(options.key, {
    appId: options.wallet.appId,
    walletId: options.wallet.walletId,
    typedData: typedData as unknown as Record<string, unknown>,
  });
  const payment = await options.pay(signed);

  const header = x402PaymentHeader({ ask, typedData, signature: payment.signature });
  const response = await fetchImpl(resource.href, init({ [header.name]: header.value }, 'manual'));
  const receipt = response.headers.get(ask.version === 2 ? 'payment-response' : 'x-payment-response');
  let settlement: unknown;
  if (receipt) {
    try {
      settlement = decodeBase64Json(receipt);
    } catch {
      settlement = receipt;
    }
  }
  return { paid: true, response, payment, ...(settlement === undefined ? {} : { settlement }) };
}
