import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from './index.js';
import { generateAgentWalletKey } from './wallet-key.js';
import {
  BASE_USDC_ADDRESS,
  X402PaymentError,
  payX402,
  readX402Ask,
  type X402StackPayment,
} from './x402-pay.js';

const SELLER = 'https://seller.example/reports/42';
const PAY_TO = '0x5555555555555555555555555555555555555555';
const WALLET = { address: '0x1111111111111111111111111111111111111111', walletId: 'wal_1', appId: 'app_1' };
const SIGNATURE = `0x${'ab'.repeat(65)}`;
const NOW = 1_800_000_000;
const encode = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
const decode = (value: string) => JSON.parse(Buffer.from(value, 'base64').toString('utf8')) as Record<string, unknown>;

const v2Entry = (over: Record<string, unknown> = {}) => ({
  scheme: 'exact', network: 'eip155:8453', amount: '250000', asset: BASE_USDC_ADDRESS, payTo: PAY_TO, maxTimeoutSeconds: 60,
  extra: { name: 'USD Coin', version: '2' }, ...over,
});
const v1Entry = (over: Record<string, unknown> = {}) => ({
  scheme: 'exact', network: 'base', maxAmountRequired: '10000', resource: SELLER, description: 'A report', mimeType: 'text/plain',
  asset: BASE_USDC_ADDRESS, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: 'USD Coin', version: '2' }, ...over,
});

interface Seen { url: string; init: RequestInit }

/** A seller: 402 until a payment header comes, then the goods. */
function seller(options: { version: 1 | 2; accepts?: unknown[]; afterPayment?: Response }) {
  const seen: Seen[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    const headers = init.headers as Record<string, string>;
    const paidWith = options.version === 2 ? headers['PAYMENT-SIGNATURE'] : headers['X-PAYMENT'];
    if (paidWith) {
      if (options.afterPayment) return options.afterPayment;
      return new Response('the report', {
        status: 200,
        headers: { [options.version === 2 ? 'payment-response' : 'x-payment-response']: encode({ success: true, transaction: '0xfeed' }) },
      });
    }
    const accepts = options.accepts ?? [options.version === 2 ? v2Entry() : v1Entry()];
    if (options.version === 2) {
      return new Response('{}', { status: 402, headers: { 'payment-required': encode({ x402Version: 2, resource: { url: SELLER }, accepts }) } });
    }
    return new Response(JSON.stringify({ x402Version: 1, error: 'X-PAYMENT header is required', accepts }), { status: 402 });
  }) as unknown as typeof fetch;
  return { fetchImpl, seen };
}

function stackPay() {
  const calls: Array<{ typed_data: Record<string, unknown>; agent_signature: string }> = [];
  const pay = async (input: { typed_data: Record<string, unknown>; agent_signature: string }): Promise<X402StackPayment> => {
    calls.push(input);
    return { payment_id: 'wpay_1', signature: SIGNATURE, amount_atomic: '250000', amount_cents: 25 };
  };
  return { pay, calls };
}

const key = generateAgentWalletKey();

describe('payX402', () => {
  it('pays a version 2 seller once, exactly what it asked, and returns the goods and the receipt', async () => {
    const shop = seller({ version: 2 });
    const stack = stackPay();
    const result = await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: shop.fetchImpl, nowSeconds: () => NOW });

    expect(result.paid).toBe(true);
    expect(await result.response.text()).toBe('the report');
    expect(result.settlement).toEqual({ success: true, transaction: '0xfeed' });
    expect(stack.calls).toHaveLength(1);
    const typed = stack.calls[0]!.typed_data as { domain: unknown; primary_type: string; message: Record<string, string> };
    expect(typed.domain).toEqual({ name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: BASE_USDC_ADDRESS });
    expect(typed.primary_type).toBe('TransferWithAuthorization');
    expect(typed.message).toMatchObject({ from: WALLET.address, to: PAY_TO, value: '250000', validAfter: '0', validBefore: String(NOW + 60) });
    expect(stack.calls[0]!.agent_signature).toMatch(/^[A-Za-z0-9+/=]+$/);

    // The paid request carries the payment the wallet signed, against the entry the seller sent, and follows no redirect.
    const paid = shop.seen[1]!;
    expect(paid.init.redirect).toBe('manual');
    const header = decode((paid.init.headers as Record<string, string>)['PAYMENT-SIGNATURE']!);
    expect(header).toMatchObject({ x402Version: 2, accepted: v2Entry(), payload: { signature: SIGNATURE, authorization: typed.message } });
    expect(header['resource']).toEqual({ url: SELLER });
  });

  it('pays a version 1 seller with X-PAYMENT', async () => {
    const shop = seller({ version: 1 });
    const stack = stackPay();
    const result = await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: shop.fetchImpl, nowSeconds: () => NOW });
    expect(result.paid).toBe(true);
    expect(await result.response.text()).toBe('the report');
    const typed = stack.calls[0]!.typed_data as { message: Record<string, string> };
    expect(typed.message).toMatchObject({ to: PAY_TO, value: '10000', validBefore: String(NOW + 120) });
    const header = decode((shop.seen[1]!.init.headers as Record<string, string>)['X-PAYMENT']!);
    expect(header).toEqual({ x402Version: 1, scheme: 'exact', network: 'base', payload: { signature: SIGNATURE, authorization: typed.message } });
    expect(result.settlement).toEqual({ success: true, transaction: '0xfeed' });
  });

  it('picks the entry the wallet can pay out of several', async () => {
    const shop = seller({ version: 2, accepts: [v2Entry({ network: 'eip155:1' }), v2Entry({ scheme: 'upto' }), v2Entry({ amount: '5000' })] });
    const stack = stackPay();
    await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: shop.fetchImpl, nowSeconds: () => NOW });
    expect((stack.calls[0]!.typed_data as { message: { value: string } }).message.value).toBe('5000');
  });

  it('returns an answer that is not a 402 unpaid', async () => {
    const stack = stackPay();
    const free = (async () => new Response('free', { status: 200 })) as unknown as typeof fetch;
    const result = await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: free });
    expect(result.paid).toBe(false);
    expect(await result.response.text()).toBe('free');
    expect(stack.calls).toHaveLength(0);
  });

  const refusals: Array<[string, Parameters<typeof seller>[0], { url?: string; maxCents?: number }, string]> = [
    ['another chain', { version: 2, accepts: [v2Entry({ network: 'eip155:1' })] }, {}, 'not_payable'],
    ['another token', { version: 2, accepts: [v2Entry({ asset: '0x2222222222222222222222222222222222222222' })] }, {}, 'not_payable'],
    ['another scheme', { version: 2, accepts: [v2Entry({ scheme: 'upto' })] }, {}, 'not_payable'],
    ['a token that names another domain', { version: 2, accepts: [v2Entry({ extra: { name: 'Fake USD', version: '2' } })] }, {}, 'not_payable'],
    ['a price over the most allowed', { version: 2 }, { maxCents: 24 }, 'over_max'],
    ['a plain http address', { version: 2 }, { url: 'http://seller.example/reports/42' }, 'insecure_url'],
  ];
  for (const [what, shopOptions, call, code] of refusals) {
    it(`refuses ${what} before STACK is asked`, async () => {
      const shop = seller(shopOptions);
      const stack = stackPay();
      const attempt = payX402(call.url ?? SELLER, {
        key, wallet: WALLET, pay: stack.pay, fetch: shop.fetchImpl, ...(call.maxCents === undefined ? {} : { maxCents: call.maxCents }),
      });
      await expect(attempt).rejects.toMatchObject({ name: 'X402PaymentError', code });
      expect(stack.calls).toHaveLength(0);
      expect(shop.seen.filter((s) => (s.init.headers as Record<string, string>)['PAYMENT-SIGNATURE'])).toHaveLength(0);
    });
  }

  it('lets a price at the most allowed through', async () => {
    const stack = stackPay();
    const result = await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: seller({ version: 2 }).fetchImpl, maxCents: 25 });
    expect(result.paid).toBe(true);
  });

  it('returns the payment and the failure when the seller fails after it was paid', async () => {
    const stack = stackPay();
    const shop = seller({ version: 2, afterPayment: new Response('down', { status: 503 }) });
    const result = await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: shop.fetchImpl });
    expect(result.paid).toBe(true);
    expect(result.payment).toMatchObject({ payment_id: 'wpay_1' });
    expect(result.response.status).toBe(503);
  });

  it('does not follow a redirect of the paid request', async () => {
    const stack = stackPay();
    const shop = seller({ version: 2, afterPayment: new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/' } }) });
    const result = await payX402(SELLER, { key, wallet: WALLET, pay: stack.pay, fetch: shop.fetchImpl });
    expect(result.response.status).toBe(302);
    expect(shop.seen).toHaveLength(2);
  });

  it('passes a STACK refusal on as it came, with nothing sent to the seller', async () => {
    const shop = seller({ version: 2 });
    const refused = new Error('WALLET_DAILY_CAP');
    await expect(payX402(SELLER, { key, wallet: WALLET, pay: async () => { throw refused; }, fetch: shop.fetchImpl })).rejects.toBe(refused);
    expect(shop.seen).toHaveLength(1);
  });

  it('refuses requirements it cannot read', () => {
    expect(() => readX402Ask({ paymentRequiredHeader: 'not base64 json' })).toThrow(X402PaymentError);
    expect(() => readX402Ask({ bodyText: '<html>pay us</html>' })).toThrow(X402PaymentError);
    expect(() => readX402Ask({ bodyText: JSON.stringify({ x402Version: 2, accepts: [] }) })).toThrow(/version 1/);
  });
});

describe('stack.accounts.wallet.payUrl', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';

  function stubStack(walletPiece: Record<string, unknown> | null) {
    const calls: Array<{ method: string; path: string; headers: Record<string, string>; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({ method: init.method ?? 'GET', path: parsed.pathname, headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : undefined });
      if (init.method === 'POST') {
        return new Response(JSON.stringify({ payment_id: 'wpay_1', payload_hash: '0x', signature: SIGNATURE, from: WALLET.address, to: PAY_TO, amount_atomic: '250000', amount_cents: 25, valid_before: '' }), { status: 201, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ id: ACCOUNT, pieces: walletPiece ? [walletPiece] : [] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }));
    return calls;
  }

  it('reads the wallet from the account and pays through STACK under the agent Passport', async () => {
    const calls = stubStack({ kind: 'wallet', state: 'ready', details: { address: WALLET.address, wallet_id: 'wal_1', privy_app_id: 'app_1' } });
    const shop = seller({ version: 2 });
    const stack = new Stack({ apiKey: 'sk_live_wallet_test', baseUrl: 'http://api.fixture' });
    const result = await stack.accounts.wallet.payUrl(ACCOUNT, SELLER, { key, passportToken: 'passport-token', fetch: shop.fetchImpl });
    expect(await result.response.text()).toBe('the report');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([`GET /v1/accounts/${ACCOUNT}`, `POST /v1/accounts/${ACCOUNT}/wallet/payments`]);
    expect(calls.every((c) => c.headers['X-Passport-Token'] === 'passport-token')).toBe(true);
    expect(JSON.stringify(calls)).not.toContain(key.exportPrivateKey().slice(14, 60));
  });

  it('refuses an account whose wallet is not ready, before paying', async () => {
    const calls = stubStack({ kind: 'wallet', state: 'pending', details: {} });
    const stack = new Stack({ apiKey: 'sk_live_wallet_test', baseUrl: 'http://api.fixture' });
    await expect(stack.accounts.wallet.payUrl(ACCOUNT, SELLER, { key, fetch: seller({ version: 2 }).fetchImpl })).rejects.toMatchObject({ code: 'wallet_not_ready' });
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(0);
  });
});
