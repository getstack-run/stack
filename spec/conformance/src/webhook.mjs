// Standard Webhooks (https://www.standardwebhooks.com), the v1 HMAC-SHA256
// scheme, written from the specification and independent of every STACK
// package, so that the kit can judge an implementation without trusting its
// libraries.

import { createHmac, timingSafeEqual } from 'node:crypto';

export const TOLERANCE_SECONDS = 5 * 60;

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// spec/webhooks/SPEC.md section 4: `whsec_` and base64 is the key's bytes; a secret issued before the
// scheme has no prefix and is read as base64 when it is valid base64, else by its UTF-8 bytes.
export function secretKey(secret) {
  const prefixed = secret.startsWith('whsec_');
  const text = prefixed ? secret.slice('whsec_'.length) : secret;
  const key = prefixed || BASE64.test(text) ? Buffer.from(text, 'base64') : Buffer.from(text, 'utf8');
  if (key.length < 16) throw new Error('a webhook secret holds at least 16 bytes');
  return key;
}

export function signature(secret, id, timestamp, body) {
  return createHmac('sha256', secretKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64');
}

/** The three headers for one message, signed with every secret given. */
export function signMessage({ id, body, secrets, timestamp = Math.floor(Date.now() / 1000) }) {
  const ts = String(timestamp);
  return {
    'webhook-id': id,
    'webhook-timestamp': ts,
    'webhook-signature': secrets.map((s) => `v1,${signature(s, id, ts, body)}`).join(' '),
  };
}

/** Verify a received message. Returns { ok: true, id } or { ok: false, reason }. */
export function verifyMessage({ headers, body, secrets, now = Math.floor(Date.now() / 1000), toleranceSeconds = TOLERANCE_SECONDS }) {
  const get = (name) => (headers instanceof Headers ? headers.get(name) : headers[name]) ?? undefined;
  const id = get('webhook-id');
  const timestampText = get('webhook-timestamp');
  const signatures = get('webhook-signature');
  if (!id || !timestampText || !signatures) return { ok: false, reason: 'missing_headers' };
  if (!/^\d{1,12}$/.test(timestampText)) return { ok: false, reason: 'bad_timestamp' };
  if (Math.abs(now - Number(timestampText)) > toleranceSeconds) return { ok: false, reason: 'stale' };
  const offered = signatures
    .split(' ')
    .filter((part) => part.startsWith('v1,'))
    .map((part) => Buffer.from(part.slice(3), 'base64'));
  for (const secret of secrets) {
    const expected = Buffer.from(signature(secret, id, timestampText, body), 'base64');
    for (const candidate of offered) {
      if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) return { ok: true, id };
    }
  }
  return { ok: false, reason: 'bad_signature' };
}

/** A secret that is not the one under test. */
export const WRONG_SECRET = `whsec_${Buffer.alloc(32, 0x7e).toString('base64')}`;
