// The receiving end of every webhook STACK signs: wake-ups, notification
// delivery methods, inbound-webhook forwards (partner tenants included),
// network revocation pushes and both directions of the control socket. They all
// use Standard Webhooks (https://www.standardwebhooks.com), written out in
// `spec/webhooks/SPEC.md`: three headers, `webhook-id`, `webhook-timestamp` and
// `webhook-signature`, an HMAC-SHA256 over `<id>.<timestamp>.<body>` keyed with
// the bytes of your `whsec_<base64>` secret. This file is the whole of it, with
// no dependency beyond node:crypto; any published Standard Webhooks library
// verifies STACK's requests as well.
//
//   const check = verifyWebhook({ headers: req.headers, body: rawBody, secret });
//   if (!check.ok) return res.status(401).end();
//   handle(check.id, check.payload);
//
// Verify the raw body exactly as received; re-serialised JSON does not match.
// A message is fresh for `toleranceSeconds` (300) either side of your clock, and
// a request STACK retries carries the same `webhook-id` every time: keep the
// ids you have handled (`createReplayGuard`) and acknowledge a repeat without
// handling it again.

import { createHmac, timingSafeEqual } from 'node:crypto';

const SECRET_PREFIX = 'whsec_';
const SECRET_MIN_BYTES = 16;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** A signed message older (or newer) than this many seconds is refused. */
export const WEBHOOK_TOLERANCE_SECONDS = 5 * 60;

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

export type WebhookFailure =
  | 'missing_headers'
  | 'bad_timestamp'
  | 'stale'
  | 'bad_signature'
  | 'bad_body'
  | 'replayed';

export type VerifiedWebhook =
  | {
      ok: true;
      /** The `webhook-id`: the message's identity, the same on every retry. */
      id: string;
      /** The signed timestamp, unix seconds. */
      timestamp: number;
      /** The parsed JSON body (an object). */
      payload: Record<string, unknown>;
    }
  | { ok: false; reason: WebhookFailure };

/** Remembers the ids it has been given for a while, so a repeat inside the tolerance is noticed. */
export interface ReplayGuard {
  /** True the first time an id is offered inside the window, false on a repeat. */
  firstSeen(id: string, now?: number): boolean;
  /** Take an id back, after a delivery you could not handle, so STACK's retry of it is not taken for a replay. */
  forget(id: string): void;
}

export interface VerifyWebhookInput {
  /** The request's headers: a `Headers`, or a plain object (node's `req.headers`). */
  headers: HeaderSource;
  /** The raw body exactly as received. */
  body: string | Uint8Array;
  /** Your signing secret, or the old and the new one while a rotation is live. */
  secret: string | readonly string[];
  /** Accepted clock difference in seconds; 300 when omitted. */
  toleranceSeconds?: number;
  /** Unix seconds; the clock when omitted. For tests. */
  now?: number;
  /** Refuse a `webhook-id` already seen (`createReplayGuard`). Optional; without it a replay inside the tolerance is accepted. */
  replayGuard?: ReplayGuard;
}

/**
 * The HMAC key of a secret. A secret STACK issues is `whsec_` and base64: its key is the decoded
 * bytes. A secret issued before this scheme (a hexadecimal string, or a value you chose) has no
 * prefix and is read the same way when it is base64, and by its UTF-8 bytes when it is not, which
 * is what every published Standard Webhooks library computes from that string.
 */
export function webhookSecretKey(secret: string): Buffer {
  const prefixed = secret.startsWith(SECRET_PREFIX);
  const text = prefixed ? secret.slice(SECRET_PREFIX.length) : secret;
  const key = prefixed || BASE64.test(text) ? Buffer.from(text, 'base64') : Buffer.from(text, 'utf8');
  if (key.length < SECRET_MIN_BYTES) throw new Error('A webhook secret (whsec_ followed by base64) holds at least 16 bytes');
  return key;
}

export function signWebhookBody(secret: string, id: string, timestamp: string, body: string): Buffer {
  return createHmac('sha256', webhookSecretKey(secret)).update(`${id}.${timestamp}.${body}`).digest();
}

function headerValue(headers: HeaderSource, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

/**
 * An in-memory replay guard: it remembers every id for `ttlSeconds` (twice the tolerance by
 * default, so an id outlives the window in which its signature is fresh). One process only; share
 * the ids through your own store when you run several.
 */
export function createReplayGuard(options: { ttlSeconds?: number; maxEntries?: number } = {}): ReplayGuard {
  const ttl = (options.ttlSeconds ?? WEBHOOK_TOLERANCE_SECONDS * 2) * 1000;
  const maxEntries = options.maxEntries ?? 100_000;
  const seen = new Map<string, number>();
  return {
    firstSeen(id, now = Date.now()) {
      for (const [key, expires] of seen) {
        if (expires > now) break;
        seen.delete(key);
      }
      if (seen.has(id)) return false;
      if (seen.size >= maxEntries) {
        const oldest = seen.keys().next().value;
        if (oldest !== undefined) seen.delete(oldest);
      }
      seen.set(id, now + ttl);
      return true;
    },
    forget(id) {
      seen.delete(id);
    },
  };
}

/**
 * Check that a request really comes from STACK and is fresh, then read it. The signature is
 * compared in constant time against every secret given; a malformed signature is a mismatch, never
 * a throw. A malformed secret throws, because that is your configuration, not an attacker's input.
 * An `Error` thrown here is never a verdict on the request.
 */
export function verifyWebhook(input: VerifyWebhookInput): VerifiedWebhook {
  const secrets = typeof input.secret === 'string' ? [input.secret] : [...input.secret];
  if (secrets.length === 0) throw new Error('At least one secret is needed to verify');
  for (const secret of secrets) webhookSecretKey(secret);

  const id = headerValue(input.headers, 'webhook-id');
  const timestampText = headerValue(input.headers, 'webhook-timestamp');
  const signatures = headerValue(input.headers, 'webhook-signature');
  if (!id || !timestampText || !signatures) return { ok: false, reason: 'missing_headers' };
  if (!/^\d{1,12}$/.test(timestampText)) return { ok: false, reason: 'bad_timestamp' };
  const now = input.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestampText)) > (input.toleranceSeconds ?? WEBHOOK_TOLERANCE_SECONDS)) {
    return { ok: false, reason: 'stale' };
  }

  const body = typeof input.body === 'string' ? input.body : Buffer.from(input.body).toString('utf8');
  const offered = signatures
    .split(' ')
    .map((part) => part.trim())
    .filter((part) => part.startsWith('v1,'))
    .map((part) => Buffer.from(part.slice(3), 'base64'));
  let matched = false;
  for (const secret of secrets) {
    const expected = signWebhookBody(secret, id, timestampText, body);
    for (const candidate of offered) {
      if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) matched = true;
    }
  }
  if (!matched) return { ok: false, reason: 'bad_signature' };

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, reason: 'bad_body' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, reason: 'bad_body' };
  // Last, so only a message that is genuine and fresh takes a place in the guard's memory.
  if (input.replayGuard && !input.replayGuard.firstSeen(id, now * 1000)) return { ok: false, reason: 'replayed' };
  return { ok: true, id, timestamp: Number(timestampText), payload: parsed as Record<string, unknown> };
}
