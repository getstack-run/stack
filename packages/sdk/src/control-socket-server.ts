// The server side of the control socket: what your decision server does with a
// request from STACK. Both directions use Standard Webhooks
// (https://www.standardwebhooks.com): three headers, `webhook-id`,
// `webhook-timestamp` and `webhook-signature`, with an HMAC-SHA256 over
// `<id>.<timestamp>.<body>` keyed with the bytes of your `whsec_<base64>`
// secret. These two functions are the whole of it, with no dependency beyond
// node:crypto; any published Standard Webhooks library verifies STACK's
// requests as well.
//
//   const check = verifyControlSocketRequest({ headers, body: rawBody, secret });
//   if (!check.ok) return reply.status(401).send();
//   const { headers: answerHeaders, body: answerBody } = signControlSocketAnswer({
//     decisionId: check.request.decision_id,
//     requestDigest: check.request.request_digest,
//     verdict: 'allow',
//     secrets: [secret],
//   });
//
// Verify the raw body exactly as received; re-serialised JSON does not match.

import { signWebhookBody, verifyWebhook, WEBHOOK_TOLERANCE_SECONDS } from './webhook.js';

const SECRET_PREFIX = 'whsec_';

/** A signed message older (or newer) than this many seconds is refused. */
export const CONTROL_SOCKET_SIGNATURE_TOLERANCE_SECONDS = WEBHOOK_TOLERANCE_SECONDS;

const REASON_CODE_PATTERN = /^[a-z0-9_]{1,64}$/;
const REASON_MESSAGE_MAX_CHARS = 200;

/**
 * The request STACK signs and posts to your decision address. It carries who,
 * what and how much; never message bodies, prompts, code, page text, card
 * numbers, credentials or Passport tokens. `target` is a small, flat object
 * whose fields depend on `action.type`. `test` is true for the setup check and
 * the test button, when nothing is being done.
 */
export interface ControlDecisionRequest {
  type: 'stack.decision.request';
  version: '1';
  decision_id: string;
  created_at: string;
  deadline_at: string;
  test: boolean;
  operator_id: string;
  socket_id: string;
  account: { id: string } | null;
  agent: { id: string; passport_jti: string | null; mission_id: string | null } | null;
  actor: { kind: 'agent' | 'owner' | 'member' };
  action: { type: string };
  target: Record<string, unknown>;
  amount: {
    max_cents: number | null;
    currency: string;
    native?: { value: string; currency: string };
  } | null;
  purpose: { agent_stated: string | null };
  retry_ref: string | null;
  /** `sha256:` over the canonical JSON of the request; the answer must echo it. */
  request_digest: string;
}

/** The answer your server signs and returns. */
export interface ControlDecisionAnswer {
  decision_id: string;
  request_digest: string;
  verdict: 'allow' | 'deny';
  reason?: { code: string; message?: string };
  /** A pending approval: the agent sends `ref` back as `X-Control-Ref` on its retry. */
  retry?: { ref: string; after_seconds?: number };
  policy_ref?: string;
}

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

export type ControlSocketRequestFailure =
  | 'missing_headers'
  | 'bad_timestamp'
  | 'stale'
  | 'bad_signature'
  | 'bad_body'
  | 'id_mismatch';

export type VerifiedControlSocketRequest =
  | { ok: true; request: ControlDecisionRequest }
  | { ok: false; reason: ControlSocketRequestFailure };

export interface VerifyControlSocketRequestInput {
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
  if (!secret.startsWith(SECRET_PREFIX)) throw new Error('A control socket secret starts with whsec_');
}

function sign(secret: string, id: string, timestamp: string, body: string): Buffer {
  return signWebhookBody(secret, id, timestamp, body);
}

/**
 * Check that a request really comes from STACK and is fresh, then read it. The
 * signature is compared in constant time against every secret given; a
 * malformed signature is a mismatch, never a throw. A malformed secret throws,
 * because that is your configuration, not an attacker's input. (`verifyWebhook`
 * is the same check for every other message STACK signs.)
 */
export function verifyControlSocketRequest(input: VerifyControlSocketRequestInput): VerifiedControlSocketRequest {
  const secrets = typeof input.secret === 'string' ? [input.secret] : [...input.secret];
  if (secrets.length === 0) throw new Error('At least one secret is needed to verify');
  for (const secret of secrets) requireWhsec(secret);

  const checked = verifyWebhook({
    headers: input.headers,
    body: input.body,
    secret: secrets,
    toleranceSeconds: input.toleranceSeconds ?? CONTROL_SOCKET_SIGNATURE_TOLERANCE_SECONDS,
    ...(input.now !== undefined ? { now: input.now } : {}),
  });
  if (!checked.ok) return { ok: false, reason: checked.reason as ControlSocketRequestFailure };
  const parsed = checked.payload;
  if (!isDecisionRequest(parsed)) return { ok: false, reason: 'bad_body' };
  // STACK signs a decision with its decision id as the message id.
  if (parsed.decision_id !== checked.id) return { ok: false, reason: 'id_mismatch' };
  return { ok: true, request: parsed };
}

function isDecisionRequest(value: unknown): value is ControlDecisionRequest {
  if (!value || typeof value !== 'object') return false;
  const fields = value as Record<string, unknown>;
  return (
    fields['type'] === 'stack.decision.request' &&
    typeof fields['decision_id'] === 'string' &&
    typeof fields['request_digest'] === 'string' &&
    typeof fields['action'] === 'object' && fields['action'] !== null
  );
}

export interface SignControlSocketAnswerInput {
  /** The request's `decision_id`. */
  decisionId: string;
  /** The request's `request_digest`, echoed back; a different one counts as no answer. */
  requestDigest: string;
  verdict: 'allow' | 'deny';
  /** Why; a `code` of lower-case letters, digits and underscores (up to 64), and an optional `message` of up to 200 characters. */
  reason?: { code: string; message?: string };
  /** Hold the action for an approval: the agent sends `ref` back as `X-Control-Ref` on its retry. */
  retry?: { ref: string; after_seconds?: number };
  /** Your own reference for the rule that decided, kept on the decision. */
  policyRef?: string;
  /** Your signing secret, or both while a rotation is live. */
  secrets: string | readonly string[];
  /** Unix seconds; the clock when omitted. For tests. */
  timestamp?: number;
}

export interface SignedControlSocketAnswer {
  /** The JSON body to return, exactly as signed. */
  body: string;
  /** The headers to return with it. */
  headers: { 'webhook-id': string; 'webhook-timestamp': string; 'webhook-signature': string };
}

/**
 * Build and sign the answer to a decision request: the body to return and the
 * three headers that go with it, `webhook-id` being the decision id. Return
 * the body as given; the signature covers its exact bytes.
 */
export function signControlSocketAnswer(input: SignControlSocketAnswerInput): SignedControlSocketAnswer {
  const secrets = typeof input.secrets === 'string' ? [input.secrets] : [...input.secrets];
  if (secrets.length === 0) throw new Error('At least one secret is needed to sign');
  if (input.reason && !REASON_CODE_PATTERN.test(input.reason.code)) {
    throw new Error('A reason code is 1 to 64 lower-case letters, digits or underscores');
  }
  if (input.reason?.message !== undefined && input.reason.message.length > REASON_MESSAGE_MAX_CHARS) {
    throw new Error(`A reason message is at most ${REASON_MESSAGE_MAX_CHARS} characters`);
  }

  const answer: ControlDecisionAnswer = {
    decision_id: input.decisionId,
    request_digest: input.requestDigest,
    verdict: input.verdict,
    ...(input.reason ? { reason: input.reason } : {}),
    ...(input.retry ? { retry: input.retry } : {}),
    ...(input.policyRef !== undefined ? { policy_ref: input.policyRef } : {}),
  };
  const body = JSON.stringify(answer);
  for (const secret of secrets) requireWhsec(secret);
  const timestamp = String(input.timestamp ?? Math.floor(Date.now() / 1000));
  return {
    body,
    headers: {
      'webhook-id': input.decisionId,
      'webhook-timestamp': timestamp,
      'webhook-signature': secrets.map((secret) => `v1,${sign(secret, input.decisionId, timestamp, body).toString('base64')}`).join(' '),
    },
  };
}
