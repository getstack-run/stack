// The agent's wallet key: the wallet's only signer. The key pair is generated
// and kept on the agent's side; only the public half goes into the open
// request. To pay, the agent signs Privy's signing request with this key and
// sends the signature to STACK, which checks its controls and then passes the
// request to Privy. STACK holds no key to any wallet.
//
// The key must never exist inside STACK's sandbox: STACK runs that machine,
// and no machine of STACK may make or keep it. Every entry point refuses
// when STACK_SANDBOX is set (the sandbox sets it).

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

const AUTHORIZATION_KEY_PREFIX = 'wallet-auth:';
const PRIVY_API_BASE = 'https://api.privy.io';

export class WalletKeyInSandboxError extends Error {
  constructor() {
    super(
      'Refusing to load or create a wallet key inside the STACK sandbox. The agent wallet key stays on your own machine; no machine of STACK may make or keep it.',
    );
    this.name = 'WalletKeyInSandboxError';
  }
}

function assertOutsideSandbox(): void {
  const flag = process.env['STACK_SANDBOX'];
  // Fail closed: any value other than empty or "0" counts as inside.
  if (flag !== undefined && flag !== '' && flag !== '0') throw new WalletKeyInSandboxError();
}

export interface AgentWalletKey {
  /** Base64 uncompressed P-256 point: the `wallet.agent_public_key` of the open request. */
  readonly publicKey: string;
  /** Sign a Privy authorization payload; base64 DER ECDSA P-256 SHA-256. */
  sign(payload: string): string;
  /** The private key in Privy's `wallet-auth:` form, for your own secret store. */
  exportPrivateKey(): string;
}

function wrap(privateKey: KeyObject): AgentWalletKey {
  if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new TypeError('wallet key must be P-256');
  }
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  const publicKey = Buffer.concat([
    Buffer.of(0x04),
    Buffer.from(jwk.x ?? '', 'base64url'),
    Buffer.from(jwk.y ?? '', 'base64url'),
  ]).toString('base64');
  const redacted = '[AgentWalletKey]';
  return {
    publicKey,
    sign(payload: string) {
      assertOutsideSandbox();
      return sign('sha256', Buffer.from(payload), { key: privateKey, dsaEncoding: 'der' }).toString('base64');
    },
    exportPrivateKey() {
      assertOutsideSandbox();
      return `${AUTHORIZATION_KEY_PREFIX}${privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64')}`;
    },
    toJSON: () => ({ publicKey }),
    toString: () => redacted,
  } as AgentWalletKey;
}

/** Create a new agent wallet key pair on this machine. */
export function generateAgentWalletKey(): AgentWalletKey {
  assertOutsideSandbox();
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return wrap(privateKey);
}

/** Load a key saved with `exportPrivateKey()`. */
export function loadAgentWalletKey(privateKey: string): AgentWalletKey {
  assertOutsideSandbox();
  if (!privateKey.startsWith(AUTHORIZATION_KEY_PREFIX)) throw new TypeError('wallet key must be in wallet-auth: form');
  let key: KeyObject;
  try {
    key = createPrivateKey({
      key: Buffer.from(privateKey.slice(AUTHORIZATION_KEY_PREFIX.length), 'base64'),
      format: 'der',
      type: 'pkcs8',
    });
  } catch {
    throw new TypeError('wallet key is not a valid PKCS#8 key');
  }
  return wrap(key);
}

/** RFC 8785 canonical JSON for the strings, integers, arrays and objects a payment carries. */
function canonicalize(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('only integers are supported in a wallet payment');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
  }
  throw new TypeError('unsupported value in a wallet payment');
}

export interface WalletPaymentTarget {
  /** From the account's wallet piece details: `privy_app_id` and `wallet_id`. */
  appId: string;
  walletId: string;
  /** The EIP-712 TransferWithAuthorization (x402 style) as Privy takes it: domain, types, primary_type, message. */
  typedData: Record<string, unknown>;
}

/** The exact string the agent signs: Privy's authorization payload for the signing request. */
export function walletPaymentAuthorizationPayload(target: WalletPaymentTarget): string {
  return canonicalize({
    version: 1,
    method: 'POST',
    url: `${PRIVY_API_BASE}/v1/wallets/${encodeURIComponent(target.walletId)}/rpc`,
    body: { method: 'eth_signTypedData_v4', params: { typed_data: target.typedData } },
    headers: { 'privy-app-id': target.appId },
  });
}

/** The body for `POST /v1/accounts/:id/wallet/payments`. */
export function signWalletPayment(
  key: AgentWalletKey,
  target: WalletPaymentTarget,
): { typed_data: Record<string, unknown>; agent_signature: string } {
  assertOutsideSandbox();
  return { typed_data: target.typedData, agent_signature: key.sign(walletPaymentAuthorizationPayload(target)) };
}
