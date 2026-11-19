// The control socket: where an account's actions are decided, and where its
// record is streamed. One socket per customer. These are the numbers and the
// closed lists every layer (API, vault, SDKs, the example server) agrees on.

/**
 * The kinds of action a customer's decider can be asked about. A customer
 * chooses which of these are checked; an unchecked kind goes through with no
 * decision. A new kind is added here and to the coverage test together.
 */
export const CONTROL_ACTION_TYPES = [
  'model.call',
  'proxy.call',
  'tool.run',
  'email.send',
  'sms.send',
  'telegram.send',
  'call.start',
  'call.answer',
  'meeting.join',
  'browser.session.start',
  'browser.navigate',
  'card.checkout',
  'wallet.payment',
  'workspace.exec',
  'account.open',
  'dropoff.create',
  'dropoff.deposit',
  'a2a.send',
  'skill.invoke',
  'passport.delegate',
  'wake.deliver',
  'drive.upload',
  'drive.share',
  'memory.write',
  'memory.delete',
  'brain.add',
  'site.publish',
  'payment.request',
  'letter.send',
  'post.scan',
  'post.forward',
  'post.shred',
  'making.quote',
  'making.order',
] as const;
export type ControlActionType = (typeof CONTROL_ACTION_TYPES)[number];

/** Who decides, for a customer: STACK's hosted controls, the customer's own server, or nobody. */
export const CONTROL_DECIDERS = ['none', 'hosted', 'remote'] as const;
export type ControlDecider = (typeof CONTROL_DECIDERS)[number];

/**
 * What a customer has chosen. `auto` is every customer who chose nothing:
 * hosted checks while their controls are on, none otherwise.
 */
export const CONTROL_MODE_SETTINGS = ['auto', 'none', 'hosted', 'remote'] as const;
export type ControlModeSetting = (typeof CONTROL_MODE_SETTINGS)[number];

/** The decision address's state. Only an `enforcing` address decides anything. */
export const CONTROL_DECISION_STATUSES = ['unverified', 'enforcing', 'paused'] as const;
export type ControlDecisionStatus = (typeof CONTROL_DECISION_STATUSES)[number];

/** The events address's state. `failing` and `paused` stop delivery; `active` delivers. */
export const CONTROL_EVENTS_STATUSES = ['off', 'unverified', 'active', 'failing'] as const;
export type ControlEventsStatus = (typeof CONTROL_EVENTS_STATUSES)[number];

export const CONTROL_VERDICTS = ['allow', 'deny', 'unavailable'] as const;
export type ControlVerdict = (typeof CONTROL_VERDICTS)[number];

/** Why no usable answer came back. Never a secret, never the customer's response text. */
export const CONTROL_UNAVAILABLE_CAUSES = [
  'timeout',
  'unreachable',
  'unsafe_address',
  'http_status',
  'bad_signature',
  'bad_body',
  'mismatch',
  'busy',
  'breaker_open',
  'unverified',
  'paused',
  'secret_unavailable',
  'hosted_failure',
] as const;
export type ControlUnavailableCause = (typeof CONTROL_UNAVAILABLE_CAUSES)[number];

/**
 * What happens to an action when the customer's own decision server does not answer in time: `refuse` (the default: the action is
 * refused, 403 `CONTROL_SOCKET_UNAVAILABLE`) or `allow` (it goes through). Allowing loosens a control, so it takes the browser-only
 * `account_control_loosen` approval; going back to refuse applies at once.
 */
export const CONTROL_ON_UNAVAILABLE_SETTINGS = ['refuse', 'allow'] as const;
export type ControlOnUnavailable = (typeof CONTROL_ON_UNAVAILABLE_SETTINGS)[number];

/**
 * The causes that mean the server did not answer: no answer in time, an address that could not be reached, an answer that was not a
 * 200, a server too busy or one whose breaker is open. Only these follow the setting. An answer that failed its signature or did not
 * parse, an address STACK refuses to call, a server not yet verified or paused and a secret that could not be read are never let
 * through by it.
 */
export const CONTROL_UNANSWERED_CAUSES: ReadonlySet<ControlUnavailableCause> = new Set<ControlUnavailableCause>([
  'timeout',
  'unreachable',
  'http_status',
  'busy',
  'breaker_open',
]);

/** The decision timeout, in milliseconds: configurable, and 2 s is the hard ceiling. */
export const CONTROL_DECISION_TIMEOUT_DEFAULT_MS = 1_500;
export const CONTROL_DECISION_TIMEOUT_MIN_MS = 300;
export const CONTROL_DECISION_TIMEOUT_MAX_MS = 2_000;

/** A decision answer larger than this is refused unread. */
export const CONTROL_DECISION_RESPONSE_MAX_BYTES = 16 * 1024;
/** A decision request or an events batch larger than this is never sent. */
export const CONTROL_DECISION_REQUEST_MAX_BYTES = 32 * 1024;

/** Decisions in flight per socket per API machine; more wait, up to the deadline. */
export const CONTROL_DECISION_MAX_IN_FLIGHT = 64;

/** The per-socket circuit breaker: opens after this many failures in a row, or over half of the last window. */
export const CONTROL_BREAKER_CONSECUTIVE_FAILURES = 5;
export const CONTROL_BREAKER_WINDOW_CALLS = 20;
export const CONTROL_BREAKER_WINDOW_MS = 30_000;
export const CONTROL_BREAKER_OPEN_MS = 15_000;

/** A signed message older (or newer) than this many seconds is refused. */
export const CONTROL_SIGNATURE_TOLERANCE_SECONDS = 5 * 60;
/** A rotated signing secret stays valid this long beside its replacement. */
export const CONTROL_SECRET_ROTATION_GRACE_MS = 24 * 60 * 60 * 1000;

/** Events batches: at most this many events or bytes, one batch in flight per socket. */
export const CONTROL_EVENTS_BATCH_MAX_EVENTS = 100;
export const CONTROL_EVENTS_BATCH_MAX_BYTES = 256 * 1024;
export const CONTROL_EVENTS_RESPONSE_MAX_BYTES = 4 * 1024;
export const CONTROL_EVENTS_TIMEOUT_MS = 10_000;
/** Retries back off from 1 s to 1 h; a batch still failing after 72 h pauses delivery. */
export const CONTROL_EVENTS_BACKOFF_BASE_MS = 1_000;
export const CONTROL_EVENTS_BACKOFF_MAX_MS = 60 * 60 * 1000;
export const CONTROL_EVENTS_GIVE_UP_MS = 72 * 60 * 60 * 1000;
/** After this many refusals (a 4xx other than 408 and 429) a batch becomes a dead-letter gap. */
export const CONTROL_EVENTS_CLIENT_ERROR_LIMIT = 3;
/** Undelivered events are kept this long, then turn into a gap marker. */
export const CONTROL_EVENTS_RETENTION_DAYS = 7;

/** The request of a refused or unreachable decision is kept this long; the slim row of every decision, longer. */
export const CONTROL_DECISION_REQUEST_RETENTION_DAYS = 30;
export const CONTROL_DECISION_ROW_RETENTION_DAYS = 90;

/** What the agent may say about why it acts (header `X-Stack-Purpose`), passed on as untrusted text. */
export const CONTROL_PURPOSE_MAX_CHARS = 200;
/** A refused action hands back this reference header so the retry can name its approval. */
export const CONTROL_REF_HEADER = 'x-control-ref';
export const CONTROL_PURPOSE_HEADER = 'x-stack-purpose';

/** A control decision's reason code, as the customer's server gives it. */
export const CONTROL_REASON_CODE_PATTERN = /^[a-z0-9_]{1,64}$/;
export const CONTROL_REASON_MESSAGE_MAX_CHARS = 200;
