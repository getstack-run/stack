import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPublicKey, verify } from 'node:crypto';
import {
  generateAgentWalletKey,
  loadAgentWalletKey,
  signWalletPayment,
  walletPaymentAuthorizationPayload,
  WalletKeyInSandboxError,
} from './wallet-key.js';

// The same literal is pinned where the signature is checked: the agent and
// the service that checks it must sign byte-identical payloads.
const GOLDEN_PAYLOAD =
  '{"body":{"method":"eth_signTypedData_v4","params":{"typed_data":{"domain":{"chainId":8453,"name":"USD Coin","verifyingContract":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","version":"2"},"message":{"from":"0x1111111111111111111111111111111111111111","nonce":"0xabababababababababababababababababababababababababababababababab","to":"0x2222222222222222222222222222222222222222","validAfter":"0","validBefore":"1900000300","value":"1000000"},"primary_type":"TransferWithAuthorization","types":{"TransferWithAuthorization":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"validAfter","type":"uint256"},{"name":"validBefore","type":"uint256"},{"name":"nonce","type":"bytes32"}]}}}},"headers":{"privy-app-id":"privy_app_fixture"},"method":"POST","url":"https://api.privy.io/v1/wallets/wal_fixture/rpc","version":1}';

const typedData = {
  primary_type: 'TransferWithAuthorization',
  message: {
    to: '0x2222222222222222222222222222222222222222',
    from: '0x1111111111111111111111111111111111111111',
    value: '1000000',
    validAfter: '0',
    validBefore: '1900000300',
    nonce: `0x${'ab'.repeat(32)}`,
  },
  types: {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ],
  },
  domain: { verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', chainId: 8453, version: '2', name: 'USD Coin' },
};

const target = { appId: 'privy_app_fixture', walletId: 'wal_fixture', typedData };

function publicKeyOf(sec1: string) {
  const point = Buffer.from(sec1, 'base64');
  return createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') },
    format: 'jwk',
  });
}

describe('agent wallet key', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('exports only an uncompressed P-256 public key in the open request format', () => {
    const key = generateAgentWalletKey();
    const point = Buffer.from(key.publicKey, 'base64');
    expect(point).toHaveLength(65);
    expect(point[0]).toBe(0x04);
    expect(key.publicKey).toMatch(/^[A-Za-z0-9+/]{86,90}={0,2}$/);
    expect(JSON.stringify(key)).toBe(JSON.stringify({ publicKey: key.publicKey }));
    expect(String(key)).toBe('[AgentWalletKey]');
  });

  it('builds the same payload STACK verifies, whatever the key order of the typed data', () => {
    expect(walletPaymentAuthorizationPayload(target)).toBe(GOLDEN_PAYLOAD);
  });

  it('signs the payload verifiably and round-trips through export and load', () => {
    const key = generateAgentWalletKey();
    const body = signWalletPayment(key, target);
    expect(
      verify('sha256', Buffer.from(GOLDEN_PAYLOAD), { key: publicKeyOf(key.publicKey), dsaEncoding: 'der' }, Buffer.from(body.agent_signature, 'base64')),
    ).toBe(true);
    const reloaded = loadAgentWalletKey(key.exportPrivateKey());
    expect(reloaded.publicKey).toBe(key.publicKey);
    expect(() => loadAgentWalletKey('wallet-auth:AAAA')).toThrow('not a valid PKCS#8 key');
  });

  it('refuses to generate, load, sign or export inside the STACK sandbox', () => {
    const key = generateAgentWalletKey();
    const saved = key.exportPrivateKey();
    for (const value of ['1', 'true', 'yes']) {
      vi.stubEnv('STACK_SANDBOX', value);
      expect(() => generateAgentWalletKey()).toThrow(WalletKeyInSandboxError);
      expect(() => loadAgentWalletKey(saved)).toThrow(WalletKeyInSandboxError);
      expect(() => key.sign(GOLDEN_PAYLOAD)).toThrow(WalletKeyInSandboxError);
      expect(() => key.exportPrivateKey()).toThrow(WalletKeyInSandboxError);
      expect(() => signWalletPayment(key, target)).toThrow(WalletKeyInSandboxError);
    }
    vi.stubEnv('STACK_SANDBOX', '0');
    expect(() => generateAgentWalletKey()).not.toThrow();
  });
});
