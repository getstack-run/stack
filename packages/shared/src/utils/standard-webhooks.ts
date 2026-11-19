// Standard Webhooks signing (https://www.standardwebhooks.com): the format both
// directions of the control socket use, so a customer can verify STACK with any
// of the published libraries.
//
//   webhook-id         a unique id for the message (the decision or batch id)
//   webhook-timestamp  unix seconds
//   webhook-signature  space-separated `v1,<base64>` signatures, each an
//                      HMAC-SHA256 over `<id>.<timestamp>.<body>` keyed with
//                      the secret's bytes (`whsec_<base64>`)
//
// Several signatures in one header carry a rotation: STACK signs with every
// live secret, and a receiver accepts any one of them.
//
// This is the one scheme for every request STACK signs to someone else's server
// (wake-ups, notification webhooks, inbound-webhook forwards, network revocation
// pushes, the control socket). `spec/webhooks/SPEC.md` is the written contract.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const WEBHOOK_SECRET_PREFIX = 'whsec_';
const SECRET_BYTES = 32;
const SECRET_MIN_BYTES = 16;

/** A signed message older (or newer) than this many seconds is refused by a receiver. */
export const WEBHOOK_SIGNATURE_TOLERANCE_SECONDS = 5 * 60;
/** A rotated signing secret stays valid this long beside its replacement. */
export const WEBHOOK_SECRET_ROTATION_GRACE_MS = 24 * 60 * 60 * 1000;

export const WEBHOOK_ID_HEADER = 'webhook-id';
export const WEBHOOK_TIMESTAMP_HEADER = 'webhook-timestamp';
export const WEBHOOK_SIGNATURE_HEADER = 'webhook-signature';

/** A fresh signing secret: `whsec_` and 32 random bytes in base64. */
export function generateWebhookSecret(): string {
  return `${WEBHOOK_SECRET_PREFIX}${randomBytes(SECRET_BYTES).toString('base64')}`;
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * The HMAC key of a secret. A secret STACK issues is `whsec_` and base64, and its key is the
 * decoded bytes. A secret issued before this scheme (a hexadecimal string, or a value the owner
 * chose) has no prefix: it is read the same way when it is base64, and by its UTF-8 bytes when it
 * is not, so the secret an owner already holds keeps working and every published Standard
 * Webhooks library, handed that string, computes the same key.
 */
export function webhookSecretKey(secret: string): Buffer {
  const prefixed = secret.startsWith(WEBHOOK_SECRET_PREFIX);
  const text = prefixed ? secret.slice(WEBHOOK_SECRET_PREFIX.length) : secret;
  const key = prefixed || BASE64.test(text) ? Buffer.from(text, 'base64') : Buffer.from(text, 'utf8');
  if (key.length < SECRET_MIN_BYTES) throw new Error('A webhook secret (whsec_ followed by base64) holds at least 16 bytes');
  return key;
}

function signature(secret: string, id: string, timestamp: string, body: string): string {
  return createHmac('sha256', webhookSecretKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64');
}

/** Whether a rotation is recent enough that the secret it replaced still signs (24 hours). */
export function webhookRotationLive(rotatedAt: Date | null | undefined, now: number = Date.now()): boolean {
  return !!rotatedAt && now - rotatedAt.getTime() < WEBHOOK_SECRET_ROTATION_GRACE_MS;
}

/**
 * The secrets that are live for one destination: the current one, and the previous one for 24
 * hours after a rotation. A sender signs with all of them; the receiver accepts any one.
 */
export function liveWebhookSecrets(input: {
  current: string;
  previous: string | null | undefined;
  rotatedAt: Date | null | undefined;
  /** Milliseconds since the epoch; the clock when omitted. */
  now?: number;
}): string[] {
  return input.previous && webhookRotationLive(input.rotatedAt, input.now) ? [input.current, input.previous] : [input.current];
}

/** A type alias, not an interface: it is assignable to a header record (an interface has no index signature). */
export type SignedWebhookHeaders = {
  [WEBHOOK_ID_HEADER]: string;
  [WEBHOOK_TIMESTAMP_HEADER]: string;
  [WEBHOOK_SIGNATURE_HEADER]: string;
};

/** The three headers for one message, signed with every secret given (one, or two while a rotation is live). */
export function signStandardWebhook(input: {
  id: string;
  body: string;
  secrets: readonly string[];
  /** Unix seconds; the clock when omitted. */
  timestamp?: number;
}): SignedWebhookHeaders {
  if (input.secrets.length === 0) throw new Error('At least one secret is needed to sign');
  const timestamp = String(input.timestamp ?? Math.floor(Date.now() / 1000));
  return {
    [WEBHOOK_ID_HEADER]: input.id,
    [WEBHOOK_TIMESTAMP_HEADER]: timestamp,
    [WEBHOOK_SIGNATURE_HEADER]: input.secrets
      .map((secret) => `v1,${signature(secret, input.id, timestamp, input.body)}`)
      .join(' '),
  };
}

export type WebhookVerification =
  | { ok: true; id: string; timestamp: number }
  | { ok: false; reason: 'missing_headers' | 'bad_timestamp' | 'stale' | 'bad_signature' };

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

function header(headers: HeaderSource, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

/**
 * Check a received message against any of the given secrets. The timestamp must
 * be within `toleranceSeconds` of now, in either direction. Constant-time
 * comparison; never throws on a malformed signature, it just does not match.
 */
export function verifyStandardWebhook(input: {
  headers: HeaderSource;
  body: string;
  secrets: readonly string[];
  toleranceSeconds: number;
  /** Unix seconds; the clock when omitted. */
  now?: number;
}): WebhookVerification {
  const id = header(input.headers, WEBHOOK_ID_HEADER);
  const timestampText = header(input.headers, WEBHOOK_TIMESTAMP_HEADER);
  const signatures = header(input.headers, WEBHOOK_SIGNATURE_HEADER);
  if (!id || !timestampText || !signatures) return { ok: false, reason: 'missing_headers' };
  if (!/^\d{1,12}$/.test(timestampText)) return { ok: false, reason: 'bad_timestamp' };
  const timestamp = Number(timestampText);
  const now = input.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > input.toleranceSeconds) return { ok: false, reason: 'stale' };

  const offered = signatures
    .split(' ')
    .map((part) => part.trim())
    .filter((part) => part.startsWith('v1,'))
    .map((part) => Buffer.from(part.slice(3), 'base64'));
  let matched = false;
  for (const secret of input.secrets) {
    let expected: Buffer;
    try {
      expected = Buffer.from(signature(secret, id, timestampText, input.body), 'base64');
    } catch {
      continue;
    }
    for (const candidate of offered) {
      if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) matched = true;
    }
  }
  return matched ? { ok: true, id, timestamp } : { ok: false, reason: 'bad_signature' };
}
