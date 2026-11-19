// A reference wallet payment relay: the checks of spec/wallet-relay/SPEC.md
// section 6 for one wallet, in memory, in front of a "key service" that only
// counts what reaches it. It has no account, meter, controls or budget (those
// are the deployment's); it is the shape and signature gate that every relay
// shares. Start a relay of your own from it.

import { createServer } from 'node:http';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { canonicalize } from '../src/canonical.mjs';
import { BASE_USDC, signingString } from '../src/wallet-relay.mjs';
import { transferAuthorizationDigest } from '../src/keccak.mjs';

const FIELDS = ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'];
const TYPES = [
  ['from', 'address'], ['to', 'address'], ['value', 'uint256'], ['validAfter', 'uint256'], ['validBefore', 'uint256'], ['nonce', 'bytes32'],
];
const UINT = /^(0|[1-9][0-9]{0,77})$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SPKI_P256_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

class Refusal extends Error {
  constructor(status, reason, message) {
    super(message);
    this.status = status;
    this.reason = reason;
  }
}

const exactly = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => key in value);

/** @param {{ address: string, walletId: string, appId: string, perPaymentCapAtomic: bigint, dailyCapAtomic: bigint, agentPublicKey: string }} wallet */
export function createReferenceRelay(wallet, now = () => Date.now()) {
  const passedOn = new Set();
  const authorisations = [];
  let sent = 0;
  const agentKey = createPublicKey({ key: Buffer.concat([SPKI_P256_PREFIX, Buffer.from(wallet.agentPublicKey, 'base64')]), format: 'der', type: 'spki' });

  function relay(body) {
    if (!exactly(body, ['typed_data', 'agent_signature']) || typeof body.agent_signature !== 'string' || !/^[A-Za-z0-9+/]{60,120}={0,2}$/.test(body.agent_signature) || body.typed_data === null || typeof body.typed_data !== 'object') {
      return { status: 400, json: { error: { code: 'VALIDATION_ERROR', message: 'The body must be { typed_data, agent_signature }.', details: null } } };
    }
    try {
      const td = body.typed_data;
      const unsupported = (why) => new Refusal(400, 'unsupported_typed_data', `Only a Base USDC TransferWithAuthorization can be passed on: ${why}.`);
      if (!exactly(td, ['domain', 'types', 'primary_type', 'message']) || td.primary_type !== 'TransferWithAuthorization') throw unsupported('the shape');
      if (!exactly(td.types, ['TransferWithAuthorization']) || JSON.stringify(td.types.TransferWithAuthorization) !== JSON.stringify(TYPES.map(([name, type]) => ({ name, type })))) throw unsupported('the types');
      if (!exactly(td.domain, ['name', 'version', 'chainId', 'verifyingContract']) || Object.entries(BASE_USDC).some(([k, v]) => td.domain[k] !== v)) throw new Refusal(400, 'not_base_usdc', 'The payment must be USDC on Base.');
      const m = td.message;
      if (!exactly(m, FIELDS) || !ADDRESS.test(m.from) || !ADDRESS.test(m.to) || /^0x0{40}$/.test(m.to) || !/^0x[0-9a-fA-F]{64}$/.test(m.nonce)
        || ![m.value, m.validAfter, m.validBefore].every((v) => typeof v === 'string' && UINT.test(v))) throw unsupported('the message');
      const value = BigInt(m.value);
      if (value <= 0n) throw unsupported('the value is zero');
      if (m.from.toLowerCase() !== wallet.address.toLowerCase()) throw new Refusal(400, 'wrong_payer', 'message.from must be the wallet.');
      if (value > wallet.perPaymentCapAtomic) throw new Refusal(403, 'over_per_payment_cap', 'Over the per-payment cap.');
      const seconds = Math.floor(now() / 1000);
      if (BigInt(m.validBefore) <= BigInt(seconds) || BigInt(m.validBefore) > BigInt(seconds + 600) || BigInt(m.validAfter) >= BigInt(m.validBefore)) throw new Refusal(400, 'authorization_window', 'The authorisation window is wrong.');
      const signed = signingString({ appId: wallet.appId, walletId: wallet.walletId, typedData: td });
      let valid = false;
      try {
        valid = verify('sha256', Buffer.from(signed), { key: agentKey, dsaEncoding: 'der' }, Buffer.from(body.agent_signature, 'base64'));
      } catch { /* not a signature */ }
      if (!valid) throw new Refusal(403, 'agent_signature_invalid', 'The agent signature does not match this payment.');
      const hash = transferAuthorizationDigest(td.domain, m);
      if (passedOn.has(hash)) throw new Refusal(409, 'replayed', 'Each authorisation is passed on once.');
      const since = now() - 24 * 3600 * 1000;
      const recent = authorisations.filter((a) => a.at >= since).reduce((sum, a) => sum + a.value, 0n);
      if (recent + value > wallet.dailyCapAtomic) throw new Refusal(403, 'over_daily_cap', 'Past the daily cap.');
      passedOn.add(hash);
      authorisations.push({ at: now(), value });
      sent += 1; // the one call to the key service
      return {
        status: 201,
        json: {
          payment_id: `pay_${randomBytes(9).toString('base64url')}`,
          payload_hash: hash,
          signature: `0x${randomBytes(65).toString('hex')}`,
          from: m.from, to: m.to, amount_atomic: m.value,
          amount_cents: Number((value + 9_999n) / 10_000n),
          valid_before: m.validBefore,
        },
      };
    } catch (error) {
      if (error instanceof Refusal) return { status: error.status, json: { error: { code: 'WALLET_PAYMENT_REFUSED', message: error.message, details: { reason: error.reason } } } };
      throw error;
    }
  }

  return { relay, sentCount: () => sent, canonicalize };
}

/** The relay behind HTTP, for the suite to be pointed at. */
export async function serveReferenceRelay(wallet, now) {
  const relay = createReferenceRelay(wallet, now);
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { body = null; }
      const { status, json } = relay.relay(body);
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(json));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}/v1/accounts/acct_conformance/wallet/payments`, sentCount: relay.sentCount, close: () => new Promise((resolve) => server.close(resolve)) };
}
