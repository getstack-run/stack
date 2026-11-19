// Conformance suite for the WALLET PAYMENT RELAY (spec/wallet-relay/SPEC.md):
// the one request an agent sends to pay from its owner's wallet, and the relay
// that checks it before it passes it on. Two parts, either alone or both:
//
//   { build }   a CLIENT: a function that builds the request body and signs the
//               signing request of section 4 with a key the kit holds
//                 build({ appId, walletId, from, to, valueAtomic, validAfter, validBefore, nonce, sign })
//                   -> { typed_data, agent_signature }
//               `sign(string)` is the kit's: it signs with the kit's P-256 key,
//               returns the base64 DER signature and records what it was given.
//   { url, ... } a RELAY: the endpoint of a test instance (a wallet with a test
//               provider), given the wallet's address and identifiers, its
//               per-payment cap and the kit's public key (section 10). The kit
//               sends correct payments and payments with one thing wrong.
//
// Nothing here moves money: the relay under test must pass a request on only to
// a double or a test network.

import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { assert, post, runChecks, skip } from './harness.mjs';
import { canonicalize } from './canonical.mjs';
import { transferAuthorizationDigest } from './keccak.mjs';

export const BASE_USDC = Object.freeze({
  name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
});
const TWA_FIELDS = [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
];
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const PAYEE = '0x2222222222222222222222222222222222222222';

/**
 * A P-256 key for the kit: the public half as the base64 uncompressed SEC1 point an account is opened with. With a PKCS#8
 * private key (base64 DER, a test key whose public half the instance under test was given) the kit signs with that key.
 */
export function walletKeyPair(pkcs8Base64) {
  const generated = pkcs8Base64 ? undefined : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privateKey = pkcs8Base64 ? createPrivateKey({ key: Buffer.from(pkcs8Base64, 'base64'), format: 'der', type: 'pkcs8' }) : generated.privateKey;
  const publicKey = pkcs8Base64 ? createPublicKey(privateKey) : generated.publicKey;
  const jwk = publicKey.export({ format: 'jwk' });
  const point = Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  return {
    publicKey: point.toString('base64'),
    publicKeyObject: publicKey,
    sign: (payload) => nodeSign('sha256', Buffer.from(payload), { key: privateKey, dsaEncoding: 'der' }).toString('base64'),
  };
}

/** The typed data of section 5.1. */
export function typedDataFor({ from, to, valueAtomic, validAfter, validBefore, nonce }) {
  return {
    domain: { ...BASE_USDC },
    types: { TransferWithAuthorization: TWA_FIELDS.map((field) => ({ ...field })) },
    primary_type: 'TransferWithAuthorization',
    message: { from, to, value: String(valueAtomic), validAfter: String(validAfter), validBefore: String(validBefore), nonce },
  };
}

/** The string the agent signs (section 4), written out independently of any client library. */
export function signingString({ appId, walletId, typedData }) {
  return canonicalize({
    version: 1,
    method: 'POST',
    url: `https://api.privy.io/v1/wallets/${encodeURIComponent(walletId)}/rpc`,
    body: { method: 'eth_signTypedData_v4', params: { typed_data: typedData } },
    headers: { 'privy-app-id': appId },
  });
}

const freshNonce = () => `0x${randomBytes(32).toString('hex')}`;
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const sameKeys = (value, keys) => isObject(value) && Object.keys(value).length === keys.length && keys.every((key) => key in value);

/**
 * @param {{
 *   build?: (input: object) => { typed_data: object, agent_signature: string } | Promise<{ typed_data: object, agent_signature: string }>,
 *   url?: string,
 *   headers?: Record<string, string>,
 *   wallet?: { address: string, walletId: string, appId: string, perPaymentCapAtomic: string | bigint, dailyCapAtomic?: string | bigint },
 *   key?: ReturnType<typeof walletKeyPair>,
 *   provider?: { sentCount: () => number | Promise<number> },
 *   now?: () => number,
 *   timeoutMs?: number,
 *   fetchImpl?: typeof fetch,
 * }} options
 */
export async function runWalletRelaySuite(options) {
  const { build, url, headers = {}, timeoutMs = 10_000, fetchImpl } = options;
  if (!build && !url) throw new Error('give the wallet suite a build function, a url, or both');
  const key = options.key ?? walletKeyPair();
  const nowSeconds = () => Math.floor((options.now ?? Date.now)() / 1000);
  const checks = [];

  // ─── A client ─────────────────────────────────────────────────────
  const clientInput = (over = {}) => {
    const t = nowSeconds();
    return { appId: 'app_conformance', walletId: 'wallet_conformance', from: '0x1111111111111111111111111111111111111111', to: PAYEE, valueAtomic: '250000', validAfter: '0', validBefore: String(t + 300), nonce: freshNonce(), ...over };
  };
  const built = async (over) => {
    const input = clientInput(over);
    const signed = [];
    const signatures = [];
    const sign = (payload) => { signed.push(payload); const signature = key.sign(payload); signatures.push(signature); return signature; };
    const result = await build({ ...input, sign });
    return { input, signed, signatures, result };
  };

  checks.push(
    {
      id: 'WC01', level: 'MUST', title: 'the typed data has exactly domain, types, primary_type and message, and the domain of USDC on Base with a numeric chainId',
      async run() {
        if (!build) return skip('needs a build function');
        const { result } = await built();
        const td = result.typed_data;
        assert(sameKeys(td, ['domain', 'types', 'primary_type', 'message']), `typed_data has ${isObject(td) ? Object.keys(td).join(', ') : typeof td}`);
        assert(td.primary_type === 'TransferWithAuthorization', `primary_type is ${JSON.stringify(td.primary_type)}`);
        assert(sameKeys(td.domain, ['name', 'version', 'chainId', 'verifyingContract']), 'the domain must have exactly name, version, chainId and verifyingContract');
        for (const [name, value] of Object.entries(BASE_USDC)) assert(td.domain[name] === value, `domain.${name} is ${JSON.stringify(td.domain[name])}, expected ${JSON.stringify(value)} (chainId is the number 8453)`);
      },
    },
    {
      id: 'WC02', level: 'MUST', title: 'types declares only TransferWithAuthorization, with the six fields in order and no EIP712Domain entry',
      async run() {
        if (!build) return skip('needs a build function');
        const { result } = await built();
        const { types } = result.typed_data;
        assert(sameKeys(types, ['TransferWithAuthorization']), `types has ${isObject(types) ? Object.keys(types).join(', ') : typeof types}`);
        assert(canonicalize(types.TransferWithAuthorization) === canonicalize(TWA_FIELDS) && JSON.stringify(types.TransferWithAuthorization) === JSON.stringify(TWA_FIELDS), 'the fields differ from EIP-3009 or are not in its order');
      },
    },
    {
      id: 'WC03', level: 'MUST', title: 'the message has exactly the six fields, the numbers as decimal strings, the nonce as 32 bytes of hex',
      async run() {
        if (!build) return skip('needs a build function');
        const { input, result } = await built();
        const { message } = result.typed_data;
        assert(sameKeys(message, TWA_FIELDS.map((f) => f.name)), `message has ${isObject(message) ? Object.keys(message).join(', ') : typeof message}`);
        const expected = { from: input.from, to: input.to, value: input.valueAtomic, validAfter: input.validAfter, validBefore: input.validBefore, nonce: input.nonce };
        for (const [name, value] of Object.entries(expected)) assert(message[name] === value, `message.${name} is ${JSON.stringify(message[name])}, expected the string ${JSON.stringify(value)}`);
      },
    },
    {
      id: 'WC04', level: 'MUST', title: 'it signs exactly the signing string of section 4, once',
      async run() {
        if (!build) return skip('needs a build function');
        const { input, signed, result } = await built();
        assert(signed.length === 1, `sign was called ${signed.length} times: a payment carries exactly one signature`);
        const expected = signingString({ appId: input.appId, walletId: input.walletId, typedData: result.typed_data });
        assert(signed[0] === expected, `the string signed differs from the one of section 4:\n  signed:   ${signed[0]}\n  expected: ${expected}`);
      },
    },
    {
      id: 'WC05', level: 'MUST', title: 'agent_signature is the signature it was given, one signature, and it verifies',
      async run() {
        if (!build) return skip('needs a build function');
        const { signed, signatures, result } = await built();
        assert(typeof result.agent_signature === 'string' && !result.agent_signature.includes(','), 'agent_signature must be one base64 signature');
        assert(result.agent_signature === signatures[0], 'agent_signature is not the signature the key gave for the signing string');
        assert(nodeVerify('sha256', Buffer.from(signed[0]), { key: key.publicKeyObject, dsaEncoding: 'der' }, Buffer.from(result.agent_signature, 'base64')), 'agent_signature does not verify over the string it signed');
        assert(/^[A-Za-z0-9+/]{60,120}={0,2}$/.test(result.agent_signature), 'agent_signature is not 60 to 120 base64 characters');
      },
    },
    {
      id: 'WC06', level: 'MUST', title: 'the wallet identifier is percent-encoded in the signed URL',
      async run() {
        if (!build) return skip('needs a build function');
        const { signed } = await built({ walletId: 'wallet id/with spaces' });
        assert(signed[0]?.includes('/v1/wallets/wallet%20id%2Fwith%20spaces/rpc'), `the signed URL is ${JSON.stringify((signed[0] ?? '').match(/"url":"[^"]*"/)?.[0])}`);
      },
    },
    {
      id: 'WC07', level: 'SHOULD', title: 'it does not build a payment the relay would refuse: an authorisation good for more than ten minutes',
      async run() {
        if (!build) return skip('needs a build function');
        let refused = false;
        try {
          await built({ validBefore: String(nowSeconds() + 3600) });
        } catch {
          refused = true;
        }
        assert(refused, 'a payment good for an hour was built; the relay refuses it (authorization_window)');
      },
    },
  );

  // ─── A relay ───────────────────────────────────────────────────────
  const wallet = options.wallet;
  const needRelay = () => (url && wallet ? undefined : skip('needs a url and the test wallet'));
  const cap = () => BigInt(wallet.perPaymentCapAtomic);
  const send = async (body) => {
    const r = await post(url, { headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), timeoutMs, fetchImpl });
    let json = null;
    try { json = JSON.parse(r.text); } catch { /* not JSON */ }
    return { status: r.status, json };
  };
  /** A payment body signed correctly for the test wallet, with `over` applied to the typed data's message (and `domainOver` to its domain). */
  const payment = ({ over = {}, mutate, sign = true, signWith } = {}) => {
    const t = nowSeconds();
    const small = cap() < 10_000n ? cap() : 10_000n;
    const typedData = typedDataFor({ from: wallet.address, to: PAYEE, valueAtomic: small, validAfter: 0, validBefore: t + 300, nonce: freshNonce(), ...over });
    const changed = mutate ? mutate(typedData) ?? typedData : typedData;
    const toSign = signWith ?? changed;
    const signature = sign ? key.sign(signingString({ appId: wallet.appId, walletId: wallet.walletId, typedData: toSign })) : 'A'.repeat(70);
    return { typed_data: changed, agent_signature: signature };
  };
  const sentBefore = async () => (options.provider ? options.provider.sentCount() : null);
  const refusal = async (body, status, reason, why) => {
    const before = await sentBefore();
    const { status: got, json } = await send(body);
    assert(got === status, `${why}: expected ${status}, got ${got}${json?.error ? ` ${json.error.code}${json.error.details?.reason ? `/${json.error.details.reason}` : ''}` : ''}`);
    if (reason) {
      assert(json?.error?.code === 'WALLET_PAYMENT_REFUSED', `${why}: the code is ${JSON.stringify(json?.error?.code)}, expected WALLET_PAYMENT_REFUSED`);
      assert(json.error.details?.reason === reason, `${why}: the reason is ${JSON.stringify(json.error.details?.reason)}, expected ${reason}`);
    }
    if (options.provider) assert((await options.provider.sentCount()) === before, `${why}: the refused payment reached the key service`);
  };

  checks.push(
    {
      id: 'WR01', level: 'MUST', title: 'passes on a correct payment: 201 with the payment id, payload hash, signature, parties and amounts',
      async run() {
        const early = needRelay();
        if (early) return early;
        const body = payment();
        const { status, json } = await send(body);
        assert(status === 201, `expected 201, got ${status}${json?.error ? ` ${json.error.code}` : ''}`);
        const { message } = body.typed_data;
        assert(typeof json.payment_id === 'string' && json.payment_id !== '', 'payment_id is missing');
        const digest = transferAuthorizationDigest(body.typed_data.domain, body.typed_data.message);
        assert(json.payload_hash === digest, `payload_hash is ${JSON.stringify(json.payload_hash)}, expected the EIP-712 digest ${digest}`);
        assert(/^0x[0-9a-fA-F]{130}$/.test(json.signature), `signature is ${JSON.stringify(json.signature)}`);
        assert(json.from?.toLowerCase() === message.from.toLowerCase() && json.to?.toLowerCase() === message.to.toLowerCase(), 'from and to are not the payment\'s');
        assert(json.amount_atomic === message.value, `amount_atomic is ${JSON.stringify(json.amount_atomic)}`);
        assert(Number.isInteger(json.amount_cents) && json.amount_cents >= 1, `amount_cents is ${JSON.stringify(json.amount_cents)}`);
        assert(json.valid_before === message.validBefore, `valid_before is ${JSON.stringify(json.valid_before)}`);
      },
    },
    {
      id: 'WR02', level: 'MUST', title: 'refuses a body with another member, and a signature that is not base64 of the right length',
      async run() {
        const early = needRelay();
        if (early) return early;
        for (const [why, body] of [
          ['an extra member', { ...payment(), memo: 'x' }],
          ['a short signature', { ...payment(), agent_signature: 'AAAA' }],
          ['no typed data', { agent_signature: payment().agent_signature }],
        ]) {
          const { status, json } = await send(body);
          assert(status === 400, `${why}: expected 400, got ${status}`);
          assert(json?.error?.code === 'VALIDATION_ERROR', `${why}: the code is ${JSON.stringify(json?.error?.code)}`);
        }
      },
    },
    {
      id: 'WR03', level: 'MUST', title: 'refuses typed data of another shape: an extra key, an EIP712Domain type, a missing field (unsupported_typed_data)',
      async run() {
        const early = needRelay();
        if (early) return early;
        await refusal(payment({ mutate: (td) => ({ ...td, extra: true }) }), 400, 'unsupported_typed_data', 'an extra key in typed_data');
        await refusal(payment({ mutate: (td) => ({ ...td, types: { EIP712Domain: [{ name: 'name', type: 'string' }], ...td.types } }) }), 400, 'unsupported_typed_data', 'an EIP712Domain entry');
        await refusal(payment({ mutate: (td) => { const { nonce: _nonce, ...rest } = td.message; return { ...td, message: rest }; } }), 400, 'unsupported_typed_data', 'a message without a nonce');
        await refusal(payment({ mutate: (td) => ({ ...td, primary_type: 'Permit' }) }), 400, 'unsupported_typed_data', 'another primary type');
      },
    },
    {
      id: 'WR04', level: 'MUST', title: 'refuses another chain or another token (not_base_usdc)',
      async run() {
        const early = needRelay();
        if (early) return early;
        await refusal(payment({ mutate: (td) => ({ ...td, domain: { ...td.domain, chainId: 1 } }) }), 400, 'not_base_usdc', 'chain 1');
        await refusal(payment({ mutate: (td) => ({ ...td, domain: { ...td.domain, chainId: '8453' } }) }), 400, 'not_base_usdc', 'a chainId that is a string');
        await refusal(payment({ mutate: (td) => ({ ...td, domain: { ...td.domain, verifyingContract: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' } }) }), 400, 'not_base_usdc', 'another token contract');
      },
    },
    {
      id: 'WR05', level: 'MUST', title: 'refuses a payment from another wallet (wrong_payer) and a value of zero or to the zero address (unsupported_typed_data)',
      async run() {
        const early = needRelay();
        if (early) return early;
        await refusal(payment({ over: { from: '0x3333333333333333333333333333333333333333' } }), 400, 'wrong_payer', 'another payer');
        await refusal(payment({ over: { valueAtomic: 0 } }), 400, 'unsupported_typed_data', 'a value of zero');
        await refusal(payment({ over: { to: ZERO_ADDRESS } }), 400, 'unsupported_typed_data', 'the zero address as payee');
      },
    },
    {
      id: 'WR06', level: 'MUST', title: 'refuses an amount over the per-payment cap (over_per_payment_cap)',
      async run() {
        const early = needRelay();
        if (early) return early;
        await refusal(payment({ over: { valueAtomic: cap() + 1n } }), 403, 'over_per_payment_cap', 'one atomic unit over the cap');
      },
    },
    {
      id: 'WR07', level: 'MUST', title: 'refuses an expired authorisation, one good for more than ten minutes, and validAfter after validBefore (authorization_window)',
      async run() {
        const early = needRelay();
        if (early) return early;
        const t = nowSeconds();
        await refusal(payment({ over: { validBefore: t - 60 } }), 400, 'authorization_window', 'an expired authorisation');
        await refusal(payment({ over: { validBefore: t + 3600 } }), 400, 'authorization_window', 'an authorisation good for an hour');
        await refusal(payment({ over: { validAfter: t + 200, validBefore: t + 100 } }), 400, 'authorization_window', 'validAfter after validBefore');
      },
    },
    {
      id: 'WR08', level: 'MUST', title: 'refuses a signature that is not the key\'s over this typed data (agent_signature_invalid)',
      async run() {
        const early = needRelay();
        if (early) return early;
        const other = typedDataFor({ from: wallet.address, to: PAYEE, valueAtomic: 1, validAfter: 0, validBefore: nowSeconds() + 300, nonce: freshNonce() });
        await refusal(payment({ signWith: other }), 403, 'agent_signature_invalid', 'a signature over other typed data');
        await refusal(payment({ sign: false }), 403, 'agent_signature_invalid', 'a signature that is not one');
        const stranger = walletKeyPair();
        const typedData = typedDataFor({ from: wallet.address, to: PAYEE, valueAtomic: 1, validAfter: 0, validBefore: nowSeconds() + 300, nonce: freshNonce() });
        await refusal({ typed_data: typedData, agent_signature: stranger.sign(signingString({ appId: wallet.appId, walletId: wallet.walletId, typedData })) }, 403, 'agent_signature_invalid', 'a signature of another key');
      },
    },
    {
      id: 'WR09', level: 'MUST', title: 'passes an authorisation on once: the same payment again is refused (replayed, 409), however its JSON is ordered',
      async run() {
        const early = needRelay();
        if (early) return early;
        const body = payment();
        const first = await send(body);
        assert(first.status === 201, `the first payment was refused (${first.status})`);
        await refusal(body, 409, 'replayed', 'the same payment again');
        const message = Object.fromEntries(Object.entries(body.typed_data.message).reverse());
        await refusal({ typed_data: { ...body.typed_data, message }, agent_signature: body.agent_signature }, 409, 'replayed', 'the same payment with its message written in another order');
      },
    },
    {
      id: 'WR10', level: 'MUST', title: 'answers a refusal as { error: { code, message, details } }',
      async run() {
        const early = needRelay();
        if (early) return early;
        const { json } = await send(payment({ over: { valueAtomic: cap() + 1n } }));
        assert(isObject(json?.error) && typeof json.error.code === 'string' && typeof json.error.message === 'string', 'the error is not { code, message, details }');
        assert(isObject(json.error.details) && typeof json.error.details.reason === 'string', 'details.reason is missing');
      },
    },
    {
      id: 'WR11', level: 'MUST', title: 'stops at the daily cap: payments that together pass it are refused (over_daily_cap)',
      async run() {
        const early = needRelay();
        if (early) return early;
        if (wallet.dailyCapAtomic === undefined) return skip('give the wallet\'s dailyCapAtomic to test the daily cap');
        const daily = BigInt(wallet.dailyCapAtomic);
        let spent = 0n;
        let guard = 0;
        while (spent + cap() <= daily && guard < 1000) {
          const r = await send(payment({ over: { valueAtomic: cap() } }));
          if (r.status !== 201) break;
          spent += cap();
          guard += 1;
        }
        await refusal(payment({ over: { valueAtomic: daily - spent + 1n > cap() ? cap() : daily - spent + 1n } }), 403, 'over_daily_cap', 'a payment past the daily cap');
      },
    },
  );

  return runChecks('wallet payment relay', checks);
}

