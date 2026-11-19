// The control socket: the wire shapes STACK and a customer's server exchange,
// and the API's own inputs and views for configuring it.

import { z } from 'zod';
import {
  CONTROL_ACTION_TYPES,
  CONTROL_DECIDERS,
  CONTROL_DECISION_STATUSES,
  CONTROL_DECISION_TIMEOUT_MAX_MS,
  CONTROL_DECISION_TIMEOUT_MIN_MS,
  CONTROL_EVENTS_STATUSES,
  CONTROL_MODE_SETTINGS,
  CONTROL_ON_UNAVAILABLE_SETTINGS,
  CONTROL_REASON_CODE_PATTERN,
  CONTROL_REASON_MESSAGE_MAX_CHARS,
  CONTROL_UNAVAILABLE_CAUSES,
  CONTROL_VERDICTS,
} from '../constants/control-socket.js';

export const ControlActionTypeEnum = z.enum(CONTROL_ACTION_TYPES);
export const ControlDeciderEnum = z.enum(CONTROL_DECIDERS);
export const ControlModeSettingEnum = z.enum(CONTROL_MODE_SETTINGS);
export const ControlDecisionStatusEnum = z.enum(CONTROL_DECISION_STATUSES);
export const ControlEventsStatusEnum = z.enum(CONTROL_EVENTS_STATUSES);
export const ControlVerdictEnum = z.enum(CONTROL_VERDICTS);
export const ControlUnavailableCauseEnum = z.enum(CONTROL_UNAVAILABLE_CAUSES);
export const ControlOnUnavailableEnum = z.enum(CONTROL_ON_UNAVAILABLE_SETTINGS);

// ─── Wire: what STACK sends to a decision address ────────────────────

/**
 * The request STACK signs and posts to the decision address. It carries who,
 * what and how much; never message bodies, prompts, code, page text, typed
 * text, card numbers, credentials or Passport tokens. `target` is a small,
 * flat object whose fields depend on `action.type`.
 */
export const ControlDecisionRequest = z.object({
  type: z.literal('stack.decision.request'),
  version: z.literal('1'),
  decision_id: z.string().regex(/^dec_[A-Za-z0-9_-]{16,64}$/),
  created_at: z.string(),
  deadline_at: z.string(),
  /** True for the setup check and the test button: nothing is being done. */
  test: z.boolean(),
  operator_id: z.string(),
  socket_id: z.string(),
  account: z.object({ id: z.string() }).nullable(),
  agent: z
    .object({
      id: z.string(),
      passport_jti: z.string().nullable(),
      mission_id: z.string().nullable(),
    })
    .nullable(),
  actor: z.object({ kind: z.enum(['agent', 'owner', 'member']) }),
  action: z.object({ type: z.union([ControlActionTypeEnum, z.literal('test')]) }),
  target: z.record(z.unknown()),
  amount: z
    .object({
      max_cents: z.number().int().nonnegative().nullable(),
      currency: z.string(),
      native: z.object({ value: z.string(), currency: z.string() }).optional(),
    })
    .nullable(),
  purpose: z.object({ agent_stated: z.string().nullable() }),
  retry_ref: z.string().nullable(),
  /** `sha256:` over the canonical JSON of everything above; the answer must echo it. */
  request_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
});
export type ControlDecisionRequest = z.infer<typeof ControlDecisionRequest>;

/**
 * The answer a customer's server signs and returns. Unknown fields are
 * ignored. A missing or different `decision_id` or `request_digest` counts as
 * no answer.
 */
export const ControlDecisionAnswer = z.object({
  decision_id: z.string(),
  request_digest: z.string(),
  verdict: z.enum(['allow', 'deny']),
  reason: z
    .object({
      code: z.string().regex(CONTROL_REASON_CODE_PATTERN),
      message: z.string().max(CONTROL_REASON_MESSAGE_MAX_CHARS).optional(),
    })
    .optional(),
  /** A pending approval: the agent sends `ref` back as `X-Control-Ref` on its retry. */
  retry: z
    .object({
      ref: z.string().min(1).max(200),
      after_seconds: z.number().int().min(0).max(86_400).optional(),
    })
    .optional(),
  policy_ref: z.string().max(200).optional(),
});
export type ControlDecisionAnswer = z.infer<typeof ControlDecisionAnswer>;

// ─── Wire: what STACK sends to an events address ─────────────────────

/** One event of the customer's record: an audit row, minimised. */
export const ControlEvent = z.object({
  id: z.string(),
  seq: z.number().int().positive(),
  type: z.string(),
  occurred_at: z.string(),
  operator_id: z.string(),
  agent_id: z.string().nullable(),
  account_id: z.string().nullable(),
  outcome: z.string(),
  layer: z.string(),
  error_code: z.string().nullable(),
  decision_id: z.string().nullable(),
  amount_cents: z.number().nullable(),
  chain: z.object({ entry_hash: z.string(), prev_entry_hash: z.string() }).nullable(),
  /** Set on a refusal by a hosted policy: which rule refused. Never a value from the call. */
  refusal: z
    .object({
      policy_id: z.string(),
      policy_revision: z.number().int(),
      section: z.string(),
      rule: z.string(),
      code: z.string(),
    })
    .optional(),
  /** Set on a gap marker: the events from `from_seq` to `to_seq` could not be delivered. */
  gap: z.object({ from_seq: z.number().int(), to_seq: z.number().int() }).optional(),
});
export type ControlEvent = z.infer<typeof ControlEvent>;

export const ControlEventsBatch = z.object({
  type: z.literal('stack.events.batch'),
  version: z.literal('1'),
  batch_id: z.string(),
  test: z.boolean(),
  operator_id: z.string(),
  socket_id: z.string(),
  events: z.array(ControlEvent),
});
export type ControlEventsBatch = z.infer<typeof ControlEventsBatch>;

// ─── API: configuring the socket ─────────────────────────────────────

const SocketUrl = z.string().trim().min(12).max(2048);

/** Set or change the decision address. Secret created on first use and shown once. */
export const SetControlDecisionAddressInput = z
  .object({
    url: SocketUrl,
    timeout_ms: z.number().int().min(CONTROL_DECISION_TIMEOUT_MIN_MS).max(CONTROL_DECISION_TIMEOUT_MAX_MS).optional(),
  })
  .strict();
export type SetControlDecisionAddressInput = z.infer<typeof SetControlDecisionAddressInput>;

export const SetControlEventsAddressInput = z.object({ url: SocketUrl }).strict();
export type SetControlEventsAddressInput = z.infer<typeof SetControlEventsAddressInput>;

/** Switch between STACK's hosted checks and none. Your own server is switched on by verifying its address. */
export const SetControlModeInput = z.object({ mode: z.enum(['none', 'hosted']) }).strict();
export type SetControlModeInput = z.infer<typeof SetControlModeInput>;

/** Which action kinds are checked. `null` checks every kind, including kinds added later. */
export const SetControlCheckedTypesInput = z
  .object({ types: z.array(ControlActionTypeEnum).min(1).max(CONTROL_ACTION_TYPES.length).nullable() })
  .strict();
export type SetControlCheckedTypesInput = z.infer<typeof SetControlCheckedTypesInput>;

/**
 * What happens when your own decision server does not answer in time: `refuse` (default) or `allow`. Allowing loosens a control, so it
 * takes a person's approval in a browser; refusing applies at once.
 */
export const SetControlOnUnavailableInput = z.object({ on_unavailable: ControlOnUnavailableEnum }).strict();
export type SetControlOnUnavailableInput = z.infer<typeof SetControlOnUnavailableInput>;

export const ControlSocketTarget = z.enum(['decision', 'events']);
export type ControlSocketTarget = z.infer<typeof ControlSocketTarget>;

export const ControlAddressView = z.object({
  url: z.string().nullable(),
  /** A new address that is set but not yet verified; the current one keeps deciding until it is. */
  pending_url: z.string().nullable(),
  status: z.string(),
  verified_at: z.string().nullable(),
  secret_set: z.boolean(),
  secret_rotated_at: z.string().nullable(),
});

export const ControlSocketView = z.object({
  socket_id: z.string().nullable(),
  mode_setting: ControlModeSettingEnum,
  /** Who decides right now: `remote` only while the decision address is enforcing. */
  effective_mode: ControlDeciderEnum,
  /** Whether STACK's hosted controls are on for this customer (a controls subscription or a contract plan). */
  controls_enabled: z.boolean(),
  decision: ControlAddressView.extend({
    status: ControlDecisionStatusEnum,
    timeout_ms: z.number().int(),
    /** What happens when this server does not answer in time: `refuse` (default) or `allow`. */
    on_unavailable: ControlOnUnavailableEnum,
  }),
  events: ControlAddressView.extend({
    status: ControlEventsStatusEnum,
    last_acknowledged_seq: z.number().int(),
    pending_events: z.number().int(),
    dead_events: z.number().int(),
    last_error: z.string().nullable(),
  }),
  /** The action kinds checked right now. */
  checked_types: z.array(ControlActionTypeEnum),
  /** True when the list is "every kind", which also covers kinds added later. */
  checks_all_types: z.boolean(),
});
export type ControlSocketView = z.infer<typeof ControlSocketView>;

/**
 * Where a person reads a signing secret that was created for a caller who must not
 * hold it (an OAuth token, which is what a chat assistant has). Single use, an hour.
 */
export const ControlSecretReveal = z.object({
  url: z.string(),
  expires_at: z.string(),
});
export type ControlSecretReveal = z.infer<typeof ControlSecretReveal>;

/**
 * The signing secret, shown exactly once, when it is created or rotated. Only a
 * dashboard session or an API key receives it in the answer; an OAuth caller gets
 * null and `secret_reveal`, a link the person opens in the Console.
 */
export const ControlSecretView = z.object({
  target: ControlSocketTarget,
  secret: z.string().nullable(),
  secret_reveal: ControlSecretReveal.nullable(),
  /** A rotated-out secret keeps verifying for 24 hours. */
  previous_valid_until: z.string().nullable(),
});
export type ControlSecretView = z.infer<typeof ControlSecretView>;

export const ControlAddressChangeView = z.object({
  socket: ControlSocketView,
  /** Present only when a signing secret was created by this call and the caller may hold it. Store it now; it is not shown again. */
  secret: z.string().nullable(),
  /** Present instead of `secret` when the caller is an OAuth token: the Console link where the person reads it once. */
  secret_reveal: ControlSecretReveal.nullable(),
});
export type ControlAddressChangeView = z.infer<typeof ControlAddressChangeView>;

export const ControlTestResultView = z.object({
  target: ControlSocketTarget,
  ok: z.boolean(),
  latency_ms: z.number().int().nonnegative(),
  /** For a decision address: the verdict the server gave. */
  verdict: z.enum(['allow', 'deny']).nullable(),
  cause: ControlUnavailableCauseEnum.nullable(),
  /** Set by verify: the address is now in use. */
  activated: z.boolean(),
});
export type ControlTestResultView = z.infer<typeof ControlTestResultView>;

export const ControlDecisionView = z.object({
  id: z.string(),
  account_id: z.string().nullable(),
  agent_id: z.string().nullable(),
  action_type: z.string(),
  decider: ControlDeciderEnum,
  verdict: ControlVerdictEnum,
  reason_code: z.string().nullable(),
  cause: z.string().nullable(),
  latency_ms: z.number().int(),
  charged: z.boolean(),
  request_digest: z.string(),
  /** The request as sent, for a refusal or an unreachable server, within its retention. */
  request: z.record(z.unknown()).nullable(),
  /** Which rule of a hosted policy refused (policy, revision, section, rule, code): its side only, never a value from the call. */
  evidence: z.record(z.unknown()).nullable(),
  created_at: z.string(),
});
export type ControlDecisionView = z.infer<typeof ControlDecisionView>;

export const ListControlDecisionsQuery = z
  .object({
    limit: z.coerce.number().int().min(1).max(200).default(50),
    account_id: z.string().max(80).optional(),
    verdict: ControlVerdictEnum.optional(),
    before: z.string().max(40).optional(),
  })
  .strict();
export type ListControlDecisionsQuery = z.infer<typeof ListControlDecisionsQuery>;
