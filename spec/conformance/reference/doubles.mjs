// Implementations used to test the kit itself: one correct of each kind, and
// deliberately broken variants. A suite that cannot tell them apart would
// certify anything, so the broken ones must FAIL and the correct ones pass.

import { createServer } from 'node:http';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { listen } from './support.mjs';
import { signMessage, verifyMessage } from '../src/webhook.mjs';

// ─── Decision servers and events receivers ──────────────────────────

const readBody = async (req) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
};

/**
 * A decision server and events receiver with one deliberate defect, or none.
 * quirk: 'none' | 'no-verify' | 'wrong-id' | 'no-echo' | 'crash-on-unknown' | 'allow-stale' | 'no-rotation' | 'bad-verdict'
 */
export async function startControlServer({ quirk = 'none', decisionSecret, eventsSecret }) {
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    const verify = (secrets) => verifyMessage({ headers: req.headers, body, secrets });
    if (req.url === '/decide') {
      if (quirk !== 'no-verify') {
        // 'no-rotation' reads only the first signature of the header, so a rotation overlap fails.
        const headers = quirk === 'no-rotation'
          ? { ...req.headers, 'webhook-signature': String(req.headers['webhook-signature'] ?? '').split(' ')[0] }
          : req.headers;
        const checked = verifyMessage({ headers, body, secrets: [decisionSecret] });
        if (!checked.ok && !(quirk === 'allow-stale' && checked.reason === 'stale')) return res.writeHead(401).end();
      }
      let request;
      try {
        request = JSON.parse(body);
      } catch {
        return res.writeHead(400).end();
      }
      if (quirk === 'crash-on-unknown' && request.action?.type === 'future.kind') return res.writeHead(500).end();
      const answer = {
        decision_id: request.decision_id,
        request_digest: quirk === 'no-echo' ? `sha256:${'0'.repeat(64)}` : request.request_digest,
        verdict: quirk === 'bad-verdict' ? 'maybe' : 'allow',
      };
      const text = JSON.stringify(answer);
      const headers = signMessage({ id: quirk === 'wrong-id' ? 'dec_somethingelse' : request.decision_id, body: text, secrets: [decisionSecret] });
      return res.writeHead(200, { 'content-type': 'application/json', ...headers }).end(text);
    }
    if (req.url === '/events') {
      if (quirk !== 'no-verify' && !verify([eventsSecret]).ok) return res.writeHead(401).end();
      return res.writeHead(200).end('{}');
    }
    return res.writeHead(404).end();
  });
  return listen(server);
}

// ─── Passport verifiers ─────────────────────────────────────────────

const b64json = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

/**
 * A verifier written the way a careless one is: it checks the signature of the
 * key named by `kid` and nothing else. quirk: 'signature-only' | 'accepts-none' | 'no-expiry'
 */
export function carelessVerifier(quirk) {
  return async (token, { jwks, issuer, audience }) => {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('malformed');
    const header = b64json(parts[0]);
    const payload = b64json(parts[1]);
    if (header.alg === 'none' && quirk === 'accepts-none') return payload;
    const jwk = jwks.keys.find((k) => k.kid === header.kid);
    if (!jwk) throw new Error('unknown kid');
    const ok = nodeVerify(null, Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'));
    if (!ok) throw new Error('bad signature');
    if (quirk !== 'signature-only') {
      if (payload.iss !== issuer) throw new Error('issuer');
      if (payload.aud !== audience) throw new Error('audience');
      if (quirk !== 'no-expiry' && !(payload.exp > Math.floor(Date.now() / 1000))) throw new Error('expired');
    }
    return payload;
  };
}

// ─── Provider adapters ──────────────────────────────────────────────

class RetryablePieceError extends Error {
  constructor(code, message) { super(message); this.code = code; this.name = 'RetryablePieceError'; }
}
class PermanentPieceError extends Error {
  constructor(code, message) { super(message); this.code = code; this.name = 'PermanentPieceError'; }
}
class AwaitingCustomerError extends Error {
  constructor(code, message, details, providerResourceId = null) { super(message); this.code = code; this.details = details; this.providerResourceId = providerResourceId; this.name = 'AwaitingCustomerError'; }
}
class PieceNotConfiguredError extends Error {
  constructor(code = 'provider_not_configured', message = 'not configured') { super(message); this.code = code; this.name = 'PieceNotConfiguredError'; }
}

const PROVIDER_KEY = ['sk', 'double', '6f1d2c9a7b'].join('_');

/**
 * An in-memory provider and an adapter for it. quirk: 'none' | 'duplicates'
 * | 'leaks-secret' | 'raw-errors' | 'close-throws-when-gone' | 'find-creates' | 'leaks-in-error' | 'random-name'.
 */
export function makeInboxDouble(quirk = 'none') {
  const resources = new Map(); // by name -> { id }
  let armed = null;
  let counter = 0;

  const nameFor = (ctx) => (quirk === 'random-name' ? `box-${Math.random().toString(36).slice(2)}` : `box-${ctx.pieceId}`);
  const create = (ctx) => {
    counter += 1;
    const name = nameFor(ctx);
    const id = `res_${counter}_${ctx.pieceId}`;
    resources.set(`${name}#${counter}`, { id, name });
    return { id, name };
  };
  const byPiece = (ctx) => [...resources.values()].find((r) => r.name === nameFor(ctx));
  const result = (r) => ({
    providerResourceId: r.id,
    details: { address: `${r.name}@agents.example.test`, ...(quirk === 'leaks-secret' ? { api_key: PROVIDER_KEY } : {}) },
  });

  const adapter = {
    kind: 'inbox',
    provider: 'acme-mail',
    async find(ctx) {
      if (quirk === 'find-creates' && !byPiece(ctx)) create(ctx);
      const found = byPiece(ctx);
      return found ? result(found) : null;
    },
    async open(ctx) {
      if (armed) {
        const failure = armed;
        if (quirk === 'raw-errors') throw new Error(`provider said ${failure} with key ${PROVIDER_KEY}`);
        if (failure === 'retryable') throw new RetryablePieceError('provider_unavailable', quirk === 'leaks-in-error' ? `503 from provider, key ${PROVIDER_KEY}` : 'provider is unavailable');
        if (failure === 'permanent') throw new PermanentPieceError('provider_refused_400', 'the provider refused the request');
        if (failure === 'awaiting_customer') throw new AwaitingCustomerError('mail_domain_not_verified', 'waits for the domain', { action: 'verify_mail_domain' });
        if (failure === 'not_configured') throw new PieceNotConfiguredError('provider_not_configured', 'inboxes are not configured');
      }
      const existing = byPiece(ctx);
      if (existing && quirk !== 'duplicates') return result(existing);
      return result(create(ctx));
    },
    async close(ctx) {
      const entry = [...resources.entries()].find(([, r]) => r.id === ctx.providerResourceId);
      if (!entry) {
        if (quirk === 'close-throws-when-gone') throw new Error('not found');
        return;
      }
      resources.delete(entry[0]);
    },
  };

  return {
    adapter,
    provider: {
      resourceCount: () => resources.size,
      arm: (kind) => { armed = kind; },
      disarm: () => { armed = null; },
      secrets: [PROVIDER_KEY],
    },
  };
}
