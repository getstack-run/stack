// Conformance suite for x402 on AGENT SITES (spec/agent-site-payments/SPEC.md):
// the HTTP 402 exchange a site offers on a priced path. Two parts, either alone
// or both:
//
//   { url }   a SITE: the URL of a priced path on a test instance. The kit asks
//             for it without paying and reads the requirements as a client
//             would; it then sends payments that are wrong in one way each and
//             requires a 402 with a reason and never the page. With
//             `acceptsTestPayments: true` (the instance's facilitator takes the
//             kit's test payments: any well-formed authorisation) it also runs
//             the whole exchange.
//   { pay }   a CLIENT: a function pay({ paymentRequired, paymentRequiredHeader, payer, sign, now })
//             that returns the value of the PAYMENT-SIGNATURE header for the
//             requirements the kit gives it. `sign(typedData)` is the kit's.
//
// Nothing here moves money: a facilitator that settles for real must not be
// behind the instance under test.

import { randomBytes } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';

const TWA_FIELDS = [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
];
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const BUYER = '0x4444444444444444444444444444444444444444';
const b64 = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
const fromB64 = (text) => JSON.parse(Buffer.from(text, 'base64').toString('utf8'));
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const hex = (bytes) => `0x${randomBytes(bytes).toString('hex')}`;

/** The authorisation and payment a client sends for one entry of `accepts` (section 4), with `over` applied to the authorisation. */
export function paymentFor(entry, { now, payer = BUYER, over = {}, acceptedOver = {}, version = 2 } = {}) {
  return {
    x402Version: version,
    accepted: { ...entry, ...acceptedOver },
    payload: {
      signature: hex(65),
      authorization: {
        from: payer, to: entry.payTo, value: entry.amount, validAfter: '0', validBefore: String(now + 60), nonce: hex(32), ...over,
      },
    },
  };
}

/** Read the requirements out of the 402 the way a client does. */
export function readRequirements(response) {
  const header = response.headers.get('payment-required');
  if (!header) return { problem: 'there is no PAYMENT-REQUIRED header' };
  try {
    return { header, requirements: fromB64(header) };
  } catch {
    return { header, problem: 'PAYMENT-REQUIRED is not base64 of JSON' };
  }
}

/**
 * @param {{
 *   url?: string,
 *   headers?: Record<string, string>,
 *   acceptsTestPayments?: boolean,
 *   pay?: (input: object) => string | Promise<string>,
 *   now?: () => number,
 *   timeoutMs?: number,
 *   fetchImpl?: typeof fetch,
 * }} options
 */
export async function runX402Suite(options) {
  const { url, headers = {}, acceptsTestPayments = false, pay, timeoutMs = 10_000, fetchImpl = fetch } = options;
  if (!url && !pay) throw new Error('give the x402 suite a url, a pay function, or both');
  const nowSeconds = () => Math.floor((options.now ?? Date.now)() / 1000);
  const checks = [];

  const get = async (extra = {}) => {
    const response = await fetchImpl(url, { method: 'GET', headers: { accept: 'application/json', ...headers, ...extra }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    const text = await response.text();
    return { status: response.status, headers: response.headers, text, response };
  };
  const need = () => (url ? undefined : skip('needs a url'));
  /** The requirements the site issues now. */
  const issued = async () => {
    const r = await get();
    assert(r.status === 402, `an unpaid request got ${r.status}, expected 402`);
    const read = readRequirements(r);
    assert(!read.problem, read.problem);
    assert(Array.isArray(read.requirements?.accepts) && read.requirements.accepts.length > 0, 'accepts is missing or empty');
    return { entry: read.requirements.accepts[0], requirements: read.requirements, response: r };
  };
  const headerOf = (payment) => b64(payment);
  /** The site must answer a 402, carrying fresh requirements, and not the page. */
  const refused = async (value, why, expectReason) => {
    const r = await get({ 'payment-signature': value });
    assert(!(r.status >= 200 && r.status < 300), `${why}: the page was served (${r.status})`);
    assert(r.status === 402 || r.status === 400 || r.status === 413 || r.status === 431, `${why}: expected a refusal, got ${r.status}`);
    if (r.status === 402) {
      const read = readRequirements(r);
      assert(!read.problem, `${why}: ${read.problem}`);
      if (expectReason) assert(typeof read.requirements.error === 'string' && read.requirements.error !== '', `${why}: the 402 carries no error reason`);
    }
  };

  checks.push(
    {
      id: 'X01', level: 'MUST', title: 'an unpaid request is answered 402 with PAYMENT-REQUIRED (base64 of JSON), cache-control no-store and a JSON body',
      async run() {
        const early = need();
        if (early) return early;
        const r = await get();
        assert(r.status === 402, `expected 402, got ${r.status}`);
        const read = readRequirements(r);
        assert(!read.problem, read.problem);
        assert(/no-store/i.test(r.headers.get('cache-control') ?? ''), `cache-control is ${JSON.stringify(r.headers.get('cache-control'))}, expected no-store`);
        assert(/application\/json/i.test(r.headers.get('content-type') ?? ''), `content-type is ${JSON.stringify(r.headers.get('content-type'))}`);
        try { JSON.parse(r.text); } catch { assert(false, 'the body is not JSON'); }
      },
    },
    {
      id: 'X02', level: 'MUST', title: 'the requirements are x402 version 2, one exact-scheme entry with network, amount, asset, payTo, maxTimeoutSeconds and the asset\'s domain',
      async run() {
        const early = need();
        if (early) return early;
        const { requirements } = await issued();
        assert(requirements.x402Version === 2, `x402Version is ${JSON.stringify(requirements.x402Version)}`);
        assert(requirements.accepts.length === 1, `accepts has ${requirements.accepts.length} entries, expected one`);
        const e = requirements.accepts[0];
        assert(e.scheme === 'exact', `scheme is ${JSON.stringify(e.scheme)}`);
        assert(typeof e.network === 'string' && /^eip155:[0-9]+$/.test(e.network), `network is ${JSON.stringify(e.network)}, expected a CAIP-2 eip155 identifier`);
        assert(typeof e.amount === 'string' && /^[1-9][0-9]*$/.test(e.amount), `amount is ${JSON.stringify(e.amount)}, expected a decimal string of atomic units`);
        assert(BigInt(e.amount) <= 1_000n * 1_000_000n, 'amount is over 1,000 USDC');
        assert(typeof e.asset === 'string' && ADDRESS.test(e.asset), `asset is ${JSON.stringify(e.asset)}`);
        assert(typeof e.payTo === 'string' && ADDRESS.test(e.payTo), `payTo is ${JSON.stringify(e.payTo)}`);
        assert(Number.isInteger(e.maxTimeoutSeconds) && e.maxTimeoutSeconds > 0, `maxTimeoutSeconds is ${JSON.stringify(e.maxTimeoutSeconds)}`);
        assert(isObject(e.extra) && typeof e.extra.name === 'string' && typeof e.extra.version === 'string', 'extra must carry the asset\'s EIP-712 name and version');
      },
    },
    {
      id: 'X03', level: 'MUST', title: 'resource.url is the https URL of the path asked for, without the query',
      async run() {
        const early = need();
        if (early) return early;
        const { requirements } = await issued();
        const asked = new URL(url);
        const expected = `https://${asked.host}${asked.pathname}`;
        assert(isObject(requirements.resource) && requirements.resource.url === expected, `resource.url is ${JSON.stringify(requirements.resource?.url)}, expected ${expected}`);
      },
    },
    {
      id: 'X04', level: 'SHOULD', title: 'the first answer says why: error is "PAYMENT-SIGNATURE header is required"',
      async run() {
        const early = need();
        if (early) return early;
        const { requirements } = await issued();
        assert(requirements.error === 'PAYMENT-SIGNATURE header is required', `error is ${JSON.stringify(requirements.error)}`);
      },
    },
    {
      id: 'X05', level: 'SHOULD', title: 'the same path asked again gives the same requirements',
      async run() {
        const early = need();
        if (early) return early;
        const a = (await issued()).entry;
        const b = (await issued()).entry;
        assert(JSON.stringify(a) === JSON.stringify(b), 'the requirements changed between two requests with no payment in between');
      },
    },
    {
      id: 'X10', level: 'MUST', title: 'a payment header that is not a payment is answered 402 with a reason, never the page',
      async run() {
        const early = need();
        if (early) return early;
        await refused('not base64 at all !!', 'garbage', true);
        await refused(Buffer.from('not json', 'utf8').toString('base64'), 'base64 of text', true);
        await refused(b64({ hello: 'world' }), 'JSON that is not a payment', true);
      },
    },
    {
      id: 'X11', level: 'MUST', title: 'a payment of another x402 version, or with a malformed authorisation, is refused',
      async run() {
        const early = need();
        if (early) return early;
        const { entry } = await issued();
        const now = nowSeconds();
        await refused(headerOf(paymentFor(entry, { now, version: 1 })), 'version 1', true);
        await refused(headerOf(paymentFor(entry, { now, over: { from: 'not-an-address' } })), 'a payer that is not an address', true);
        await refused(headerOf(paymentFor(entry, { now, over: { nonce: '0x1234' } })), 'a nonce that is not 32 bytes', true);
        await refused(headerOf(paymentFor(entry, { now, over: { value: 'lots' } })), 'a value that is not a number', true);
        const noSignature = paymentFor(entry, { now });
        noSignature.payload.signature = '0x12';
        await refused(headerOf(noSignature), 'a signature that is too short', true);
      },
    },
    {
      id: 'X12', level: 'MUST', title: 'a payment that does not match the requirements (amount, payee, network, asset) is refused',
      async run() {
        const early = need();
        if (early) return early;
        const { entry } = await issued();
        const now = nowSeconds();
        const cheaper = (BigInt(entry.amount) - 1n).toString();
        await refused(headerOf(paymentFor(entry, { now, acceptedOver: { amount: cheaper }, over: { value: cheaper } })), 'a smaller amount than asked', true);
        await refused(headerOf(paymentFor(entry, { now, acceptedOver: { payTo: BUYER }, over: { to: BUYER } })), 'another payee', true);
        await refused(headerOf(paymentFor(entry, { now, acceptedOver: { network: 'eip155:1' } })), 'another network', true);
        await refused(headerOf(paymentFor(entry, { now, acceptedOver: { asset: BUYER } })), 'another asset', true);
        await refused(headerOf(paymentFor(entry, { now, acceptedOver: { scheme: 'upto' } })), 'another scheme', true);
      },
    },
    {
      id: 'X13', level: 'MUST', title: 'an authorisation that pays someone else, or less than it says it pays, is refused',
      async run() {
        const early = need();
        if (early) return early;
        const { entry } = await issued();
        const now = nowSeconds();
        await refused(headerOf(paymentFor(entry, { now, over: { to: BUYER } })), 'an authorisation to another payee', true);
        await refused(headerOf(paymentFor(entry, { now, over: { value: (BigInt(entry.amount) - 1n).toString() } })), 'an authorisation for less than the price', true);
      },
    },
    {
      id: 'X14', level: 'MUST', title: 'a payment header over 8,192 characters is refused, never the page',
      async run() {
        const early = need();
        if (early) return early;
        const r = await get({ 'payment-signature': 'A'.repeat(9000) });
        assert(!(r.status >= 200 && r.status < 300), `the page was served (${r.status})`);
        assert(r.status >= 400 && r.status < 500, `expected a 4xx refusal, got ${r.status}`);
      },
    },
    {
      id: 'X15', level: 'MUST', title: 'every answer that depends on a payment is no-store',
      async run() {
        const early = need();
        if (early) return early;
        const { entry } = await issued();
        const r = await get({ 'payment-signature': headerOf(paymentFor(entry, { now: nowSeconds(), over: { to: BUYER } })) });
        assert(/no-store/i.test(r.headers.get('cache-control') ?? ''), `cache-control is ${JSON.stringify(r.headers.get('cache-control'))}`);
      },
    },
    {
      id: 'X20', level: 'MUST', title: 'a correct payment is served the page with PAYMENT-RESPONSE { success: true, transaction, network, payer }',
      async run() {
        const early = need();
        if (early) return early;
        if (!acceptsTestPayments) return skip('the instance must accept the kit\'s test payments (acceptsTestPayments)');
        const { entry } = await issued();
        const r = await get({ 'payment-signature': headerOf(paymentFor(entry, { now: nowSeconds() })) });
        assert(r.status >= 200 && r.status < 300, `a correct payment got ${r.status}`);
        const header = r.headers.get('payment-response');
        assert(header, 'there is no PAYMENT-RESPONSE header');
        const settled = fromB64(header);
        assert(settled.success === true, `success is ${JSON.stringify(settled.success)}`);
        assert(typeof settled.transaction === 'string' && settled.transaction !== '', 'transaction is missing');
        assert(settled.network === entry.network, `network is ${JSON.stringify(settled.network)}`);
        assert(typeof settled.payer === 'string' && settled.payer.toLowerCase() === BUYER, `payer is ${JSON.stringify(settled.payer)}`);
        assert(/no-store/i.test(r.headers.get('cache-control') ?? ''), 'the paid answer is cacheable');
      },
    },
    {
      id: 'X21', level: 'MUST', title: 'an authorisation settled once is not accepted again for a different amount or another payee',
      async run() {
        const early = need();
        if (early) return early;
        if (!acceptsTestPayments) return skip('the instance must accept the kit\'s test payments (acceptsTestPayments)');
        const { entry } = await issued();
        const now = nowSeconds();
        const payment = paymentFor(entry, { now });
        const first = await get({ 'payment-signature': headerOf(payment) });
        assert(first.status >= 200 && first.status < 300, `the first payment got ${first.status}`);
        const altered = { ...payment, payload: { ...payment.payload, authorization: { ...payment.payload.authorization, to: BUYER } } };
        await refused(headerOf(altered), 'the settled authorisation with another payee', true);
      },
    },
  );

  // ─── A client ─────────────────────────────────────────────────────
  const requirementsFor = (entries) => ({
    x402Version: 2,
    resource: { url: 'https://agent.stack-conformance.test/reports/42' },
    accepts: entries,
  });
  const baseEntry = (over = {}) => ({
    scheme: 'exact', network: 'eip155:8453', amount: '250000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    payTo: '0x5555555555555555555555555555555555555555', maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' }, ...over,
  });
  const paid = async (entries, over = {}) => {
    const typed = [];
    const signatures = [];
    const sign = (typedData) => { typed.push(typedData); const signature = hex(65); signatures.push(signature); return signature; };
    const requirements = requirementsFor(entries);
    const now = nowSeconds();
    const header = await pay({ paymentRequired: requirements, paymentRequiredHeader: b64(requirements), payer: BUYER, sign, now, ...over });
    assert(typeof header === 'string' && header !== '', 'pay returned no header value');
    return { header, payment: fromB64(header), typed, signatures, now, entries };
  };

  checks.push(
    {
      id: 'XC01', level: 'MUST', title: 'the payment is base64 of JSON, x402 version 2, with the chosen entry of accepts unchanged',
      async run() {
        if (!pay) return skip('needs a pay function');
        const entry = baseEntry();
        const { payment } = await paid([entry]);
        assert(payment.x402Version === 2, `x402Version is ${JSON.stringify(payment.x402Version)}`);
        assert(JSON.stringify(sortKeys(payment.accepted)) === JSON.stringify(sortKeys(entry)), `accepted differs from the entry: ${JSON.stringify(payment.accepted)}`);
      },
    },
    {
      id: 'XC02', level: 'MUST', title: 'the authorisation pays exactly the amount to payTo from the payer, with decimal-string values',
      async run() {
        if (!pay) return skip('needs a pay function');
        const entry = baseEntry();
        const { payment, now } = await paid([entry]);
        const a = payment.payload?.authorization;
        assert(isObject(a), 'payload.authorization is missing');
        assert(a.from?.toLowerCase() === BUYER && a.to?.toLowerCase() === entry.payTo, `from and to are ${JSON.stringify(a.from)} and ${JSON.stringify(a.to)}`);
        assert(a.value === entry.amount, `value is ${JSON.stringify(a.value)}, expected the string ${entry.amount}`);
        for (const name of ['validAfter', 'validBefore']) assert(typeof a[name] === 'string' && /^[0-9]+$/.test(a[name]), `${name} is ${JSON.stringify(a[name])}, expected a decimal string`);
        assert(Number(a.validAfter) <= now && Number(a.validBefore) > now, 'the authorisation is not good now');
      },
    },
    {
      id: 'XC03', level: 'SHOULD', title: 'validBefore is no later than maxTimeoutSeconds after the request',
      async run() {
        if (!pay) return skip('needs a pay function');
        const entry = baseEntry();
        const { payment, now } = await paid([entry]);
        assert(Number(payment.payload.authorization.validBefore) <= now + entry.maxTimeoutSeconds + 5, `validBefore ${payment.payload.authorization.validBefore} is more than ${entry.maxTimeoutSeconds} s after ${now}`);
      },
    },
    {
      id: 'XC04', level: 'MUST', title: 'every payment has a new 32-byte nonce',
      async run() {
        if (!pay) return skip('needs a pay function');
        const seen = new Set();
        for (let i = 0; i < 3; i += 1) {
          const { payment } = await paid([baseEntry()]);
          const nonce = payment.payload.authorization.nonce;
          assert(typeof nonce === 'string' && /^0x[0-9a-fA-F]{64}$/.test(nonce), `nonce is ${JSON.stringify(nonce)}`);
          assert(!seen.has(nonce.toLowerCase()), 'a nonce was used twice');
          seen.add(nonce.toLowerCase());
        }
      },
    },
    {
      id: 'XC05', level: 'MUST', title: 'it signs the EIP-3009 typed data of the asset\'s domain, and sends the signature it was given',
      async run() {
        if (!pay) return skip('needs a pay function');
        const entry = baseEntry({ network: 'eip155:84532', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', extra: { name: 'USDC', version: '2' } });
        const { payment, typed, signatures } = await paid([entry]);
        assert(typed.length === 1, `sign was called ${typed.length} times`);
        const [td] = typed;
        const domain = td.domain;
        assert(isObject(domain) && domain.name === 'USDC' && domain.version === '2' && Number(domain.chainId) === 84532 && String(domain.verifyingContract).toLowerCase() === entry.asset.toLowerCase(), `the domain is ${JSON.stringify(domain)}: it must be { name: extra.name, version: extra.version, chainId: the number of network, verifyingContract: asset }`);
        assert((td.primaryType ?? td.primary_type) === 'TransferWithAuthorization', `primaryType is ${JSON.stringify(td.primaryType ?? td.primary_type)}`);
        assert(JSON.stringify(td.types?.TransferWithAuthorization) === JSON.stringify(TWA_FIELDS), 'the TransferWithAuthorization fields differ from EIP-3009');
        const a = payment.payload.authorization;
        for (const name of ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce']) assert(String(td.message?.[name]).toLowerCase() === String(a[name]).toLowerCase(), `message.${name} is not the authorisation's`);
        assert(payment.payload.signature === signatures[0], 'payload.signature is not the signature it was given');
      },
    },
    {
      id: 'XC06', level: 'MUST', title: 'it chooses an entry it can pay (scheme exact) from several, and refuses when there is none',
      async run() {
        if (!pay) return skip('needs a pay function');
        const exact = baseEntry({ payTo: '0x6666666666666666666666666666666666666666' });
        const { payment } = await paid([baseEntry({ scheme: 'upto' }), exact]);
        assert(payment.accepted?.payTo === exact.payTo && payment.accepted?.scheme === 'exact', 'it did not pick the exact entry');
        let refused = false;
        try {
          await paid([baseEntry({ scheme: 'upto' })]);
        } catch {
          refused = true;
        }
        assert(refused, 'it built a payment for a scheme it cannot pay');
      },
    },
    {
      id: 'XC07', level: 'SHOULD', title: 'it refuses a price above the maximum its owner allowed',
      async run() {
        if (!pay) return skip('needs a pay function');
        let refused = false;
        try {
          await paid([baseEntry({ amount: '5000000' })], { maxAmount: '1000000' });
        } catch {
          refused = true;
        }
        assert(refused, 'it paid 5 USDC with a maximum of 1 USDC (maxAmount is given to pay)');
      },
    },
  );

  return runChecks('x402 on agent sites', checks);
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isObject(value)) return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]));
  return value;
}
