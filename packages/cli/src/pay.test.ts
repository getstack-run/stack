import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateAgentWalletKey } from '@getstackrun/sdk';
import { api } from './api.js';
import { cmdPay } from './pay.js';

vi.mock('./api.js', async (importOriginal) => ({ ...(await importOriginal<object>()), api: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));

const ACCOUNT = 'acct_abcdefgh1234';
const SELLER = 'https://seller.example/reports/42';
const PAY_TO = '0x5555555555555555555555555555555555555555';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const SIGNATURE = `0x${'ab'.repeat(65)}`;
const KEY = generateAgentWalletKey();
const PRIVATE = KEY.exportPrivateKey();
const PASSPORT = { 'X-Passport-Token': 'passport-from-stdin' };

const encode = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');

function seller(afterPayment?: Response): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    if ((init.headers as Record<string, string>)['PAYMENT-SIGNATURE']) {
      return afterPayment ?? new Response('the report', { status: 200, headers: { 'payment-response': encode({ success: true }) } });
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
}

let out: string[];
let err: string[];

beforeEach(() => {
  vi.clearAllMocks();
  out = [];
  err = [];
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => { out.push(Buffer.from(chunk).toString()); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => { err.push(Buffer.from(chunk).toString()); return true; });
  vi.mocked(api).mockImplementation(async (method: string) => {
    if (method === 'POST') return { payment_id: 'wpay_1', signature: SIGNATURE, amount_atomic: '250000', amount_cents: 25 };
    return { id: ACCOUNT, pieces: [{ kind: 'wallet', state: 'ready', details: { address: '0x1111111111111111111111111111111111111111', wallet_id: 'wal_1', privy_app_id: 'app_1' } }] };
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe('stack pay', () => {
  it('buys in one command: the goods on stdout, the payment on stderr, paid through STACK as the agent', async () => {
    vi.stubEnv('STACK_AGENT_WALLET_KEY', PRIVATE);
    await cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller() });
    expect(out.join('')).toBe('the report');
    expect(JSON.parse(err.join(''))).toEqual({ paid: true, status: 200, payment_id: 'wpay_1', amount_cents: 25, settlement: { success: true } });
    expect(vi.mocked(api).mock.calls.map(([method, path]) => `${method} ${path}`)).toEqual([
      `GET /v1/accounts/${ACCOUNT}`,
      `POST /v1/accounts/${ACCOUNT}/wallet/payments`,
    ]);
    expect(vi.mocked(api).mock.calls.every(([, , options]) => JSON.stringify((options as { headers: unknown }).headers) === JSON.stringify(PASSPORT))).toBe(true);
  });

  it('reads the key from --wallet-key-file and writes what was bought to --out', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'stack-pay-'));
    writeFileSync(join(dir, 'wallet.key'), `${PRIVATE}\n`);
    await cmdPay([ACCOUNT, SELLER, '--wallet-key-file', join(dir, 'wallet.key'), '--out', join(dir, 'report.txt'), '--passport-stdin'], { fetch: seller() });
    expect(readFileSync(join(dir, 'report.txt'), 'utf8')).toBe('the report');
    expect(out).toEqual([]);
  });

  it('never prints the key', async () => {
    vi.stubEnv('STACK_AGENT_WALLET_KEY', PRIVATE);
    await cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller() });
    const printed = [...out, ...err].join('');
    expect(printed).not.toContain(PRIVATE.slice('wallet-auth:'.length, 60));
    expect(JSON.stringify(vi.mocked(api).mock.calls)).not.toContain(PRIVATE.slice('wallet-auth:'.length, 60));
  });

  it('refuses with no key, a key in argv, no Passport, a plain http URL and a price over --max-cents, before paying', async () => {
    await expect(cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller() })).rejects.toThrow(/wallet key/);
    await expect(cmdPay([ACCOUNT, SELLER, '--wallet-key', PRIVATE, '--passport-stdin'])).rejects.toThrow(/must not be placed in argv/);
    vi.stubEnv('STACK_AGENT_WALLET_KEY', PRIVATE);
    await expect(cmdPay([ACCOUNT, SELLER])).rejects.toThrow(/--passport-stdin/);
    await expect(cmdPay([ACCOUNT, 'http://seller.example/x', '--passport-stdin'])).rejects.toThrow(/https/);
    await expect(cmdPay([ACCOUNT, SELLER, '--max-cents', '24', '--passport-stdin'], { fetch: seller() })).rejects.toThrow(/over the most allowed/);
    expect(vi.mocked(api).mock.calls.filter(([method]) => method === 'POST')).toHaveLength(0);
  });

  it('refuses inside STACK\'s sandbox', async () => {
    vi.stubEnv('STACK_AGENT_WALLET_KEY', PRIVATE);
    vi.stubEnv('STACK_SANDBOX', '1');
    await expect(cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller() })).rejects.toThrow(/sandbox/);
    expect(api).not.toHaveBeenCalled();
  });

  it('says when it paid but the seller did not deliver', async () => {
    vi.stubEnv('STACK_AGENT_WALLET_KEY', PRIVATE);
    await expect(cmdPay([ACCOUNT, SELLER, '--passport-stdin'], { fetch: seller(new Response('down', { status: 503 })) })).rejects.toThrow(/Paid \(wpay_1\), but the seller answered 503/);
  });
});
