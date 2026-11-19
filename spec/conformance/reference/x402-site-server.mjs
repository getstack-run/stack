// A reference site with one priced path: the seller side of
// spec/agent-site-payments/SPEC.md in memory. Its "facilitator" accepts every
// well-formed authorisation and "settles" it with a made-up transaction hash,
// so it moves no money and is only for testing a client or the suite. Start a
// site of your own from it.

import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

const MAX_HEADER = 8_192;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');

export function createX402Site({ path = '/reports/42', amount = '250000', payTo = '0x5555555555555555555555555555555555555555', network = 'eip155:8453', now = () => Date.now() } = {}) {
  const requirementsEntry = {
    scheme: 'exact', network, amount, asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo, maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' },
  };
  const claims = new Map();

  const demand = (host, error) => ({
    status: 402,
    headers: {
      'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
      'payment-required': encode({ x402Version: 2, error, resource: { url: `https://${host}${path}`, description: 'A report' }, accepts: [requirementsEntry] }),
    },
    body: '{}',
  });

  function decode(value) {
    if (value.length === 0 || value.length > MAX_HEADER || !/^[A-Za-z0-9+/=_-]+$/.test(value)) return null;
    let p;
    try { p = JSON.parse(Buffer.from(value, 'base64').toString('utf8')); } catch { return null; }
    const a = p?.payload?.authorization;
    if (p?.x402Version !== 2 || !p.accepted || !a) return null;
    if (typeof p.payload.signature !== 'string' || !/^0x[0-9a-fA-F]{130,}$/.test(p.payload.signature)) return null;
    if (![a.from, a.to].every((v) => typeof v === 'string' && ADDRESS.test(v))) return null;
    if (![a.value, a.validAfter, a.validBefore].every((v) => typeof v === 'string' && /^\d{1,30}$/.test(v))) return null;
    if (typeof a.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(a.nonce)) return null;
    return p;
  }

  /** Answer one request: { status, headers, body }. */
  function handle({ host, pathname, payment }) {
    if (pathname !== path) return { status: 404, headers: {}, body: 'Not found.' };
    if (payment === undefined) return demand(host, 'PAYMENT-SIGNATURE header is required');
    if (payment.length > MAX_HEADER) return { status: 431, headers: { 'cache-control': 'no-store' }, body: 'The request is too large.' };
    const p = decode(payment);
    if (!p) return demand(host, 'invalid_payload');
    const a = p.payload.authorization;
    const accepted = p.accepted;
    const same = accepted.scheme === requirementsEntry.scheme && accepted.network === requirementsEntry.network && accepted.amount === requirementsEntry.amount
      && String(accepted.asset).toLowerCase() === requirementsEntry.asset.toLowerCase() && String(accepted.payTo).toLowerCase() === payTo.toLowerCase()
      && a.value === amount && a.to.toLowerCase() === payTo.toLowerCase();
    if (!same) return demand(host, 'invalid_payment_requirements');
    const key = `${network}:${a.from.toLowerCase()}:${a.nonce.toLowerCase()}`;
    const known = claims.get(key);
    if (known) {
      const recent = known.settledAt !== undefined && now() - known.settledAt < 600_000;
      if (known.state === 'succeeded' && recent && known.path === pathname) return paid(known);
      return demand(host, known.state === 'pending' ? 'payment_in_progress' : 'payment_already_used');
    }
    const claim = { state: 'pending', path: pathname, from: a.from.toLowerCase(), transaction: `0x${randomBytes(32).toString('hex')}` };
    claims.set(key, claim);
    // The facilitator verified it; the page was produced and answered 200; the facilitator settled it.
    claim.state = 'succeeded';
    claim.settledAt = now();
    return paid(claim);
  }

  function paid(claim) {
    return {
      status: 200,
      headers: {
        'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store',
        'payment-response': encode({ success: true, transaction: claim.transaction, network, payer: claim.from }),
      },
      body: 'The report.',
    };
  }

  return { handle };
}

export async function serveX402Site(options) {
  const site = createX402Site(options);
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://site.invalid');
    const payment = req.headers['payment-signature'];
    const answer = site.handle({ host: req.headers.host ?? 'agent.example', pathname: url.pathname, payment: Array.isArray(payment) ? payment[0] : payment });
    res.writeHead(answer.status, answer.headers).end(answer.body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}${options?.path ?? '/reports/42'}`, close: () => new Promise((resolve) => server.close(resolve)) };
}
