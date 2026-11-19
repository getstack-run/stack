// Policies: the configuration behind hosted controls.
//
// A policy narrows what a connection grant already allows; it never opens
// anything. It is stored server-side, keyed by customer and agent, and never
// bound into a Passport. These are its fixed vocabulary and its bounds.

/** The stance a rule takes: let through, hold for a person's approval, or refuse. */
export const POLICY_STANCES = ['allow', 'review', 'deny'] as const;
export type PolicyStance = (typeof POLICY_STANCES)[number];

/**
 * How tight a stance is: deny 0, review 1, allow 2. A revision whose stance
 * ranks higher than before widens the policy.
 */
export const POLICY_STANCE_RANK: Readonly<Record<PolicyStance, number>> = { deny: 0, review: 1, allow: 2 };

/**
 * Whether connections not named by a rule may be called. `any`: every
 * connection the agent has a grant for, minus what a rule denies or holds.
 * `listed`: only the connections an allow rule names.
 */
export const POLICY_CONNECTION_MODES = ['any', 'listed'] as const;
export type PolicyConnectionMode = (typeof POLICY_CONNECTION_MODES)[number];

/** The windows a limit counts in, and what it counts. Day and month are UTC; a Mission is one job. */
/**
 * The counters of a Mission's own limits (`max_actions`, `max_actions_per_service`, `coverage_cap_cents`), kept in the
 * `mission` window of an agent account beside a policy's: a scope after the Mission id, so each is a row of its own
 * and a single conditional update decides every call against it.
 */
export const MISSION_ACTIONS_SCOPE = 'mission_actions';
export const MISSION_SPEND_SCOPE = 'mission_spend';
/** A money cap of one day (`coverage_cap_period: 'day'`): one counter per local date of the Mission's time zone. */
export const missionDaySpendScope = (localDate: string): string => `${MISSION_SPEND_SCOPE}@${localDate}`;
/** Whether a counter scope is one of a Mission's money cap (the whole Mission's or a day's). */
export const isMissionSpendScope = (scope: string | null | undefined): boolean =>
  scope === MISSION_SPEND_SCOPE || (typeof scope === 'string' && scope.startsWith(`${MISSION_SPEND_SCOPE}@`));
/** What the owner pre-approved of a Mission's print-on-demand orders, used up as orders are approved under it. */
export const MISSION_MAKING_ORDERS_SCOPE = 'mission_making_orders';
export const missionServiceActionsScope = (service: string): string => `mission_service:${service}`;

export const LIMIT_PERIOD_KINDS = ['day', 'month', 'mission'] as const;
export type LimitPeriodKind = (typeof LIMIT_PERIOD_KINDS)[number];
export const LIMIT_UNITS = ['cents', 'actions'] as const;
export type LimitUnit = (typeof LIMIT_UNITS)[number];

/** One limit of a policy's spend section. */
export interface PolicyLimitRule {
  kind: LimitPeriodKind;
  unit: LimitUnit;
  limit: number;
}

/** The part of the policy that says which section a refusal came from. */
export const POLICY_SECTIONS = [
  'connections',
  'actions',
  'recipients',
  'spend',
  'review',
  'models',
  'browser',
  'card',
  'wallet',
  'workspace',
  'tools',
] as const;
export type PolicySection = (typeof POLICY_SECTIONS)[number];

/** Stable reason codes a hosted refusal carries (the customer's agent and logs read them). */
export const POLICY_REASON_CODES = [
  'connection_denied',
  'connection_not_listed',
  'call_outside_rules',
  'action_denied',
  'recipient_not_allowed',
  'recipients_not_pinned',
  'amount_over_limit',
  'model_not_allowed',
  'cost_over_limit',
  'host_not_allowed',
  'merchant_not_allowed',
  'payee_not_allowed',
  'timeout_over_limit',
  'tool_not_allowed',
  'limit_reached',
  'concurrency_reached',
  'review_required',
  'review_pending',
  'review_rejected',
  'review_mismatch',
  'policy_unevaluable',
] as const;
export type PolicyReasonCode = (typeof POLICY_REASON_CODES)[number];

/** Size bounds: a policy is small by design. */
export const POLICY_MAX_CONNECTION_RULES = 64;
export const POLICY_MAX_LIST_ENTRIES = 256;
export const POLICY_MAX_LIMITS = 12;
export const POLICY_MAX_CONCURRENT = 10_000;
export const POLICY_MAX_CENTS = 100_000_000;
export const POLICY_MAX_LIMIT_VALUE = 1_000_000_000;

/** How a revision relates to the one before it. Mixed is loosening. */
export const POLICY_CHANGE_KINDS = ['create', 'start_from_access', 'tighten', 'loosen', 'delete', 'unchanged'] as const;
export type PolicyChangeKind = (typeof POLICY_CHANGE_KINDS)[number];

/** A held action's review: its states follow the intent approval gate (pending, approved, consuming, consumed). */
export const CONTROL_REVIEW_STATUSES = ['pending', 'approved', 'consuming', 'consumed', 'rejected', 'expired'] as const;
export type ControlReviewStatus = (typeof CONTROL_REVIEW_STATUSES)[number];

/** Once a person approves a held action, the agent has this long to retry it. */
export const CONTROL_REVIEW_USE_WINDOW_SECONDS = 60 * 60;

/** A concurrency lease that is never released (a crashed machine) expires after this long. */
export const CONTROL_CONCURRENCY_LEASE_SECONDS = 5 * 60;

/** Spend rules: per-merchant and per-category limits on card purchases and wallet payments. */
export const POLICY_MAX_SPEND_RULES = 64;
export const POLICY_MAX_SPEND_CATEGORIES = 256;
/** What a spend rule can limit: one payment, the UTC day, the UTC month. */
export const SPEND_RULE_LIMIT_FIELDS = ['max_per_payment_cents', 'max_per_day_cents', 'max_per_month_cents'] as const;
export type SpendRuleLimitField = (typeof SPEND_RULE_LIMIT_FIELDS)[number];

/**
 * The surfaces that pay: a card purchase and a wallet payment. A spend rule applies to the payments of these two.
 */
export const PAYMENT_SURFACES = ['card', 'wallet'] as const;
export type PaymentSurface = (typeof PAYMENT_SURFACES)[number];

/** The counter of one spend rule sits under this scope in the period key of the limit counters. */
export function spendRuleScope(ruleId: string): string {
  return `spend:${ruleId}`;
}

/** Chat approvals of held payments (Telegram, text, Slack): the customer's own limits, none by default. */
export const CHAT_APPROVAL_SCOPE = 'chat_approval';
/** A person has this long to answer a prompt in the chat; after that the approval page is the only way. */
export const CHAT_APPROVAL_REQUEST_TTL_SECONDS = 10 * 60;
/** A chat identity's link or code is good for this long and for this many wrong tries. */
export const CHAT_LINK_TTL_SECONDS = 10 * 60;
export const CHAT_CODE_MAX_ATTEMPTS = 5;
/** Prompts STACK sends to one chat identity in 24 hours, so a flood of held payments cannot flood a phone. */
export const CHAT_PROMPTS_PER_IDENTITY_PER_DAY = 20;

/**
 * A send rule, or a list of where the account's own mail, texts or calls may go, can leave its
 * recipients to each Mission: it then allows a send only inside a Mission that names the
 * recipients exactly, and only to them.
 */
export const POLICY_RECIPIENTS_PER_MISSION = 'per_mission' as const;

/** The most recipient pins one Mission carries, and the most values one pin lists. */
export const MISSION_RECIPIENT_PINS_MAX = 64;
export const MISSION_RECIPIENT_VALUES_MAX = 1000;
/** A pin on this path applies to every recipient field a send names (an address, a number, a channel id). */
export const MISSION_RECIPIENT_ANY_PATH = '*';
