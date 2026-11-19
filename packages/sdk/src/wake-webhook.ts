// The receiving end of a wake: what your agent's endpoint does with a request
// from STACK. A wake is delivered as a Standard Webhooks signed POST
// (https://www.standardwebhooks.com): `webhook-id` (the wake's id, the same on
// every retry, so you can ignore one you have seen), `webhook-timestamp` and
// `webhook-signature`, an HMAC-SHA256 over `<id>.<timestamp>.<body>` keyed with
// your `whsec_<base64>` secret. Any published Standard Webhooks library
// verifies it as well; this one has no dependency beyond node:crypto.
//
//   const check = verifyWakeWebhook({ headers: req.headers, body: rawBody, secret });
//   if (!check.ok) return res.status(401).end();
//   const { task, source, event } = check.wake;
//
// `task` is the owner's own text, and `event` carries facts, never what a stranger
// wrote: read a message, with the detectors' verdict, from the account's messages.
// Verify the raw body exactly as received; re-serialised JSON does not match.

import type { AccountSenderTag } from './services/accounts.js';
import type { WakeEvent, WakeSource } from './services/wake.js';
import { verifyWebhook, WEBHOOK_TOLERANCE_SECONDS } from './webhook.js';

const SECRET_PREFIX = 'whsec_';

/** A signed message older (or newer) than this many seconds is refused. */
export const WAKE_WEBHOOK_TOLERANCE_SECONDS = WEBHOOK_TOLERANCE_SECONDS;

/** The body of a wake as delivered to your endpoint. */
export interface WakeWebhookPayload {
  type: 'stack.wake';
  /** "2" since the `untrusted` object was removed; a body of another version is refused as `bad_body`. */
  version: '2';
  /** True for the check an owner asks for when setting the endpoint: nothing is waking you. */
  test?: boolean;
  wake_id: string;
  /** The agent's account; null for an agent with no account. */
  account_id: string | null;
  agent_id: string;
  mission_id: string | null;
  source: WakeSource;
  /** The owner's task, or STACK's default. Never text from the event. */
  task: string;
  occurred_at: string;
  /** Facts about the event, not its content: read the content with the account's messages API. A decision names the item and its end. */
  event: WakeEvent;
  /** STACK's checks of who wrote or is calling, made when it arrived. They warn and never block. Present for any wake that names a message or a call. */
  sender_tags?: AccountSenderTag[];
  /** The known domain a `lookalike_domain` sender imitates. */
  sender_resembles?: string | null;
}

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

export type WakeWebhookFailure = 'missing_headers' | 'bad_timestamp' | 'stale' | 'bad_signature' | 'bad_body' | 'id_mismatch';

export type VerifiedWakeWebhook =
  | { ok: true; wake: WakeWebhookPayload }
  | { ok: false; reason: WakeWebhookFailure };

export interface VerifyWakeWebhookInput {
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
}

function requireWhsec(secret: string): void {
  if (!secret.startsWith(SECRET_PREFIX)) throw new Error('A wake webhook secret starts with whsec_');
}

/**
 * Check that a request really comes from STACK and is fresh, then read it. The
 * signature is compared in constant time against every secret given; a
 * malformed signature is a mismatch, never a throw. A malformed secret throws,
 * because that is your configuration, not an attacker's input.
 */
export function verifyWakeWebhook(input: VerifyWakeWebhookInput): VerifiedWakeWebhook {
  const secrets = typeof input.secret === 'string' ? [input.secret] : [...input.secret];
  if (secrets.length === 0) throw new Error('At least one secret is needed to verify');
  for (const secret of secrets) requireWhsec(secret);

  const checked = verifyWebhook({
    headers: input.headers,
    body: input.body,
    secret: secrets,
    toleranceSeconds: input.toleranceSeconds ?? WAKE_WEBHOOK_TOLERANCE_SECONDS,
    ...(input.now !== undefined ? { now: input.now } : {}),
  });
  if (!checked.ok) return { ok: false, reason: checked.reason as WakeWebhookFailure };
  const parsed = checked.payload;
  if (!isWake(parsed)) return { ok: false, reason: 'bad_body' };
  // STACK signs a wake with its own id as the message id.
  if (parsed.wake_id !== checked.id) return { ok: false, reason: 'id_mismatch' };
  return { ok: true, wake: parsed };
}

function isWake(value: unknown): value is WakeWebhookPayload {
  if (!value || typeof value !== 'object') return false;
  const fields = value as Record<string, unknown>;
  return fields['type'] === 'stack.wake' && fields['version'] === '2' && typeof fields['wake_id'] === 'string'
    && typeof fields['task'] === 'string' && typeof fields['source'] === 'string';
}
