// The reference wallet client and relay must pass the wallet suite, and the
// suite must fail clients and relays that each have one deliberate defect.

import { describe, expect, it } from 'vitest';
import { formatReport, runWalletRelaySuite, walletKeyPair } from '../src/index.mjs';
import { keccak256, transferAuthorizationDigest } from '../src/keccak.mjs';
import { build } from './wallet-client.mjs';
import { createReferenceRelay, serveReferenceRelay } from './wallet-relay-server.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const failedIds = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);

const WALLET = {
  address: '0x1111111111111111111111111111111111111111',
  walletId: 'wallet_conformance',
  appId: 'app_conformance',
  perPaymentCapAtomic: 5_000_000n,
  dailyCapAtomic: 12_000_000n,
};

describe('keccak and the payload hash', () => {
  it('is Keccak-256, not SHA3-256, and matches the example of the specification', () => {
    expect(keccak256('').toString('hex')).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    expect(keccak256('abc').toString('hex')).toBe('4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
    expect(transferAuthorizationDigest(
      { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
      { from: '0x1111111111111111111111111111111111111111', to: '0x2222222222222222222222222222222222222222', value: '1000000', validAfter: '0', validBefore: '1790000300', nonce: `0x${'ab'.repeat(32)}` },
    )).toBe('0x291e5b9cfec26046187f836fe4ef54a9b2192553443d4ed33d39a3ca876083fc');
  });
});

describe('wallet suite', () => {
  it('passes the reference client', async () => {
    const report = await runWalletRelaySuite({ build });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBe(7);
  });

  it('passes the reference relay, and nothing refused reached the key service', async () => {
    const key = walletKeyPair();
    const relay = await serveReferenceRelay({ ...WALLET, agentPublicKey: key.publicKey });
    try {
      const report = await runWalletRelaySuite({
        url: relay.url, wallet: WALLET, key, provider: { sentCount: relay.sentCount }, timeoutMs: 3000,
      });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.skipped).toBe(7);
      expect(report.passed + report.skipped).toBe(report.results.length);
    } finally {
      await relay.close();
    }
  });

  describe('fails a client with one defect', () => {
    const run = (client) => runWalletRelaySuite({ build: client });

    it('one that signs a different string than the one of section 4', async () => {
      const ids = mustFailedIds(await run((input) => {
        const built = build(input);
        return { ...built, agent_signature: input.sign(JSON.stringify(built.typed_data)) };
      }));
      expect(ids).toEqual(['WC04', 'WC05']);
    });

    it('one that sends chainId as a string and amounts as numbers', async () => {
      const ids = mustFailedIds(await run((input) => {
        const built = build({ ...input, sign: () => input.sign('x') });
        built.typed_data.domain.chainId = '8453';
        built.typed_data.message.value = Number(built.typed_data.message.value);
        return built;
      }));
      expect(ids).toEqual(expect.arrayContaining(['WC01', 'WC03', 'WC04']));
    });

    it('one that leaves out the EIP712Domain-less types rule (adds the entry)', async () => {
      const ids = mustFailedIds(await run((input) => {
        const built = build({ ...input, sign: () => input.sign('x') });
        built.typed_data.types = { EIP712Domain: [{ name: 'name', type: 'string' }], ...built.typed_data.types };
        return built;
      }));
      expect(ids).toContain('WC02');
    });

    it('one that does not percent-encode the wallet identifier', async () => {
      const ids = mustFailedIds(await run((input) => {
        const built = build({ ...input, walletId: input.walletId, sign: () => input.sign('x') });
        return { ...built, agent_signature: input.sign(`{"url":"https://api.privy.io/v1/wallets/${input.walletId}/rpc"}`) };
      }));
      expect(ids).toContain('WC06');
    });

    it('one that builds an hour-long authorisation (a SHOULD)', async () => {
      const report = await run((input) => {
        const built = { typed_data: build({ ...input, validBefore: String(Math.floor(Date.now() / 1000) + 300), sign: () => 'x' }).typed_data };
        built.typed_data.message.validBefore = input.validBefore;
        return { ...built, agent_signature: input.sign(walletPaymentString(input, built.typed_data)) };
      });
      expect(failedIds(report)).toEqual(['WC07']);
    });
  });

  describe('fails a relay with one defect', () => {
    const key = walletKeyPair();
    const start = () => serveReferenceRelay({ ...WALLET, agentPublicKey: key.publicKey });
    const run = async (mutate) => {
      const relay = await start();
      try {
        return await runWalletRelaySuite({ url: relay.url, wallet: mutate?.wallet ?? WALLET, key: mutate?.key ?? key, provider: { sentCount: relay.sentCount }, timeoutMs: 3000 });
      } finally {
        await relay.close();
      }
    };

    it('one that does not hold the agent key the kit signs with', async () => {
      const report = await run({ key: walletKeyPair() });
      expect(mustFailedIds(report)).toContain('WR01');
    });

    it('a relay that allows more per payment than the wallet it was described as is caught at the cap', async () => {
      const report = await run({ wallet: { ...WALLET, perPaymentCapAtomic: 4_000_000n } });
      expect(mustFailedIds(report)).toContain('WR06');
    });
  });

  it('a reference relay behaves the same in process', () => {
    const key = walletKeyPair();
    const relay = createReferenceRelay({ ...WALLET, agentPublicKey: key.publicKey });
    expect(relay.relay(null).status).toBe(400);
    expect(relay.sentCount()).toBe(0);
  });
});

function walletPaymentString({ appId, walletId }, typedData) {
  const canonical = (value) => {
    if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
    return JSON.stringify(value);
  };
  return canonical({
    version: 1, method: 'POST', url: `https://api.privy.io/v1/wallets/${encodeURIComponent(walletId)}/rpc`,
    body: { method: 'eth_signTypedData_v4', params: { typed_data: typedData } }, headers: { 'privy-app-id': appId },
  });
}
