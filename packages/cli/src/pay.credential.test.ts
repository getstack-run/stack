import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateAgentWalletKey } from '@getstackrun/sdk';
import { getAccessToken } from './auth.js';
import { cmdPay } from './pay.js';

// The wallet payment route accepts only an agent. These tests run `pay` through the real API helper, with no stored
// sign-in at all, and read what reaches the wire.

vi.mock('./auth.js', async (importOriginal) => ({ ...(await importOriginal<object>()), getAccessToken: vi.fn(async () => undefined) }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'agent-passport-value') }));

const ACCOUNT = 'acct_abcdefgh1234';
const SELLER = 'https://seller.example/reports/42';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x5555555555555555555555555555555555555555';
const KEY = generateAgentWalletKey();
const encode = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');

const seller = (async (_url: string, init: RequestInit) => {
  if ((init.headers as Record<string, string>)['PAYMENT-SIGNATURE']) {
    return new Response('the report', { status: 200, headers: { 'payment-response': encode({ success: true }) } });
  }
  return new Response('{}', {
    status: 402,
    headers: {
      'payment-required': encode({
        x402Version: 2,
        accepts: [{ scheme: 'exact', network: 'eip155:8453', amount: '250000', asset: USDC, payTo: PAY_TO, maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' } }],
      }),
    },
  });
}) as unknown as typeof fetch;

let printed: string[];
let calls: Array<{ method: string; url: string; headers: Record<string, string> }>;

beforeEach(() => {
  printed = [];
  calls = [];
  vi.stubEnv('STACK_AGENT_WALLET_KEY', KEY.exportPrivateKey());
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => { printed.push(Buffer.from(chunk).toString()); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => { printed.push(Buffer.from(chunk).toString()); return true; });
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ method: init.method ?? 'GET', url, headers: init.headers as Record<string, string> });
    if (init.method === 'POST') {
      return new Response(JSON.stringify({ payment_id: 'wpay_1', signature: `0x${'ab'.repeat(65)}`, amount_atomic: '250000', amount_cents: 25 }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({ id: ACCOUNT, pieces: [{ kind: 'wallet', state: 'ready', details: { address: '0x1111111111111111111111111111111111111111', wallet_id: 'wal_1', privy_app_id: 'app_1' } }] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }));
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('stack pay credential', () => {
  it('sends the Passport as the bearer and the header on both calls, and needs no sign-in', async () => {
    await cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller });
    expect(calls.map((call) => `${call.method} ${new URL(call.url).pathname}`)).toEqual([
      `GET /v1/accounts/${ACCOUNT}`,
      `POST /v1/accounts/${ACCOUNT}/wallet/payments`,
    ]);
    for (const call of calls) {
      expect(call.headers['Authorization']).toBe('Bearer agent-passport-value');
      expect(call.headers['X-Passport-Token']).toBe('agent-passport-value');
    }
    expect(getAccessToken).not.toHaveBeenCalled();
  });

  it('never prints the Passport', async () => {
    await cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller });
    expect(printed.join('')).not.toContain('agent-passport-value');
  });
});
