// Policies: the wire shapes of the configuration behind hosted controls.
//
// A policy is a small, closed, credential-free object. It never widens a
// connection grant: it names what to refuse, what to hold for a person, and
// where an agent's own account surfaces (models, browser, card, wallet,
// workspace, tools, mail, texts and calls) are bounded. Every list is an
// allowlist when present and "no restriction" when absent; every number is a
// ceiling. That is why a smaller list or a lower number is a tightening and
// the reverse is a loosening (see utils/control-policy.ts).

import { z } from 'zod';
import {
  CONTROL_REVIEW_STATUSES,
  LIMIT_PERIOD_KINDS,
  LIMIT_UNITS,
  POLICY_CHANGE_KINDS,
  POLICY_CONNECTION_MODES,
  POLICY_MAX_CENTS,
  POLICY_MAX_CONCURRENT,
  POLICY_MAX_CONNECTION_RULES,
  POLICY_MAX_LIMIT_VALUE,
  POLICY_MAX_LIMITS,
  POLICY_MAX_LIST_ENTRIES,
  POLICY_MAX_SPEND_CATEGORIES,
  POLICY_MAX_SPEND_RULES,
  POLICY_RECIPIENTS_PER_MISSION,
  POLICY_REASON_CODES,
  POLICY_SECTIONS,
  POLICY_STANCES,
} from '../constants/control-policy.js';
import { IntentRef } from '../intents/types.js';
import { ControlActionTypeEnum } from './control-socket.js';
import { Constraint } from './passport.js';

export const PolicyStanceEnum = z.enum(POLICY_STANCES);
export const PolicyConnectionModeEnum = z.enum(POLICY_CONNECTION_MODES);
export const LimitPeriodKindEnum = z.enum(LIMIT_PERIOD_KINDS);
export const LimitUnitEnum = z.enum(LIMIT_UNITS);
export const PolicySectionEnum = z.enum(POLICY_SECTIONS);
export const PolicyReasonCodeEnum = z.enum(POLICY_REASON_CODES);
export const PolicyChangeKindEnum = z.enum(POLICY_CHANGE_KINDS);
export const ControlReviewStatusEnum = z.enum(CONTROL_REVIEW_STATUSES);

const ruleId = z.string().min(1).max(64).regex(/^[A-Za-z0-9][\w.-]*$/);
const cents = z.number().int().positive().max(POLICY_MAX_CENTS);

/** An email address, or `@domain` for every address at one domain. Lower case. */
const EmailPattern = z
  .string()
  .max(254)
  .regex(/^(@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+|[^\s@]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)$/, 'Use an email address, or @domain for a whole domain, in lower case');
const PhoneNumber = z.string().regex(/^\+[1-9]\d{6,14}$/, 'Use an E.164 number such as +46701740605');
/** A host, or `*.host` for every subdomain of it. Lower case; no scheme, no path. */
const HostPattern = z
  .string()
  .max(253)
  .regex(/^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/, 'Use a host such as example.com, or *.example.com for its subdomains');
const WalletAddress = z.string().regex(/^0x[0-9a-f]{40}$/, 'Use a lower-case 0x address');
/** A spending category the customer names: `groceries`, `software`, `travel`. Lower case. */
const SpendCategory = z.string().regex(/^[a-z][a-z0-9_-]{0,39}$/, 'Use a lower-case name such as groceries or software');
/** A name, or a prefix ending in `*` (`openai/*`, `claude-*`). */
const NamePattern = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]*\*?$/);

function list<T extends z.ZodTypeAny>(item: T) {
  return z
    .array(item)
    .max(POLICY_MAX_LIST_ENTRIES)
    .refine((values) => new Set(values.map((v) => JSON.stringify(v))).size === values.length, { message: 'Entries must be unique' });
}

/** Which calls on one connection a rule is about, in the shape `findUnboundSendRules` reads. */
export const PolicyConnectionAccess = z
  .object({
    connection_id: z.string().regex(/^scon_[\w-]+$/),
    intents: z.array(IntentRef).max(32).default([]),
    constraints: z.array(Constraint).max(32).default([]),
  })
  .strict();
export type PolicyConnectionAccess = z.infer<typeof PolicyConnectionAccess>;

export const PolicyConnectionRule = z
  .object({
    id: ruleId,
    effect: PolicyStanceEnum,
    access: PolicyConnectionAccess,
    /**
     * Absent: the rule names who its sends may go to, in its own constraints. `per_mission`: each
     * Mission names them. Such a rule allows a send only inside a Mission that pins every recipient
     * field with an exact value, and only to those values. Only an allow rule can say it.
     */
    recipients: z.literal(POLICY_RECIPIENTS_PER_MISSION).optional(),
  })
  .strict()
  .refine((rule) => rule.recipients === undefined || rule.effect === 'allow', {
    path: ['recipients'],
    message: 'Only an allow rule can leave its recipients to each Mission',
  });
export type PolicyConnectionRule = z.infer<typeof PolicyConnectionRule>;

export const PolicyLimit = z
  .object({
    kind: LimitPeriodKindEnum,
    unit: LimitUnitEnum,
    limit: z.number().int().positive().max(POLICY_MAX_LIMIT_VALUE),
  })
  .strict();
export type PolicyLimit = z.infer<typeof PolicyLimit>;

/**
 * One spend rule: limits for the payments it matches. A rule names a card
 * merchant (`merchant`), a wallet payee (`payee`), a category, or none of them
 * (every payment). Each limit is optional but at least one is set. The day and
 * month limits count in their own counter per rule; a payment whose merchant,
 * payee or category the policy cannot tell (an unknown one) is held to, and
 * counts against, every rule it might match: the strictest applies.
 */
export const PolicySpendRule = z
  .object({
    id: ruleId,
    merchant: HostPattern.optional(),
    payee: WalletAddress.optional(),
    category: SpendCategory.optional(),
    max_per_payment_cents: cents.optional(),
    max_per_day_cents: cents.optional(),
    max_per_month_cents: cents.optional(),
  })
  .strict()
  .refine((rule) => !(rule.merchant !== undefined && rule.payee !== undefined), {
    message: 'A rule names a card merchant or a wallet payee, not both',
  })
  .refine(
    (rule) => rule.max_per_payment_cents !== undefined || rule.max_per_day_cents !== undefined || rule.max_per_month_cents !== undefined,
    { message: 'A spend rule sets at least one limit' },
  );
export type PolicySpendRule = z.infer<typeof PolicySpendRule>;

/** Which category a card merchant or a wallet payee belongs to, as the customer says. The card authorisation names the merchant, not a category. */
export const PolicySpendCategory = z
  .object({
    merchant: HostPattern.optional(),
    payee: WalletAddress.optional(),
    category: SpendCategory,
  })
  .strict()
  .refine((entry) => (entry.merchant !== undefined) !== (entry.payee !== undefined), {
    message: 'Name a card merchant or a wallet payee',
  });
export type PolicySpendCategory = z.infer<typeof PolicySpendCategory>;

/**
 * Chat approval of held payments: the customer's own limits. A held card or
 * wallet payment can be approved from a verified chat (Telegram, text, Slack)
 * only when BOTH are set and the payment is within them; absent, chat approval
 * of payments is off. There is no STACK default.
 */
export const PolicyChatApproval = z
  .object({
    max_per_payment_cents: cents.optional(),
    max_per_day_cents: cents.optional(),
  })
  .strict();
export type PolicyChatApproval = z.infer<typeof PolicyChatApproval>;

export const PolicyDefinition = z
  .object({
    name: z.string().trim().min(1).max(128),
    /** Which connections a call may use, and which calls on them need a person or are refused. */
    connections: z
      .object({
        mode: PolicyConnectionModeEnum.default('any'),
        rules: z.array(PolicyConnectionRule).max(POLICY_MAX_CONNECTION_RULES).default([]),
      })
      .strict()
      .default({}),
    /** One stance per kind of action; a kind not named here is allowed. */
    actions: z
      .object({
        kinds: z.record(ControlActionTypeEnum, PolicyStanceEnum).default({}),
      })
      .strict()
      .default({}),
    /**
     * Where the account's own email, texts and calls may go. Absent: anywhere the platform allows. A list names them;
     * `per_mission` leaves them to each send: the send must name the message it answers (`reply_to_message`), and
     * goes only to who wrote it.
     */
    recipients: z
      .object({
        email: z.union([list(EmailPattern), z.literal(POLICY_RECIPIENTS_PER_MISSION)]).optional(),
        sms: z.union([list(PhoneNumber), z.literal(POLICY_RECIPIENTS_PER_MISSION)]).optional(),
        call: z.union([list(PhoneNumber), z.literal(POLICY_RECIPIENTS_PER_MISSION)]).optional(),
      })
      .strict()
      .default({}),
    spend: z
      .object({
        /** The most one action may cost, in USD cents. */
        max_per_action_cents: cents.optional(),
        /** Counters that cannot be overrun by parallel calls. One per (kind, unit). */
        limits: z.array(PolicyLimit).max(POLICY_MAX_LIMITS).default([]),
        /** Actions of this agent running at the same moment. */
        max_concurrent: z.number().int().positive().max(POLICY_MAX_CONCURRENT).optional(),
        /** Per-merchant, per-payee and per-category limits for card purchases and wallet payments. */
        rules: z.array(PolicySpendRule).max(POLICY_MAX_SPEND_RULES).default([]),
        /** The customer's own labels: which category a merchant or a payee belongs to. */
        categories: z.array(PolicySpendCategory).max(POLICY_MAX_SPEND_CATEGORIES).default([]),
      })
      .strict()
      .default({}),
    /** Hold an action for a person above this amount, in USD cents. */
    review: z
      .object({
        over_cents: cents.optional(),
        /** Approving a held payment from a verified chat: off until the customer sets both limits. */
        chat: PolicyChatApproval.optional(),
      })
      .strict()
      .default({}),
    /** The account's own surfaces. */
    surfaces: z
      .object({
        models: z
          .object({
            allowed: list(NamePattern).optional(),
            max_cost_per_call_cents: cents.optional(),
          })
          .strict()
          .default({}),
        browser: z.object({ hosts: list(HostPattern).optional() }).strict().default({}),
        card: z
          .object({
            merchants: list(HostPattern).optional(),
            max_amount_cents: cents.optional(),
          })
          .strict()
          .default({}),
        wallet: z
          .object({
            payees: list(WalletAddress).optional(),
            max_amount_cents: cents.optional(),
          })
          .strict()
          .default({}),
        workspace: z
          .object({
            /** The longest one command may be given to run, in seconds. */
            max_timeout_seconds: z.number().int().positive().max(86_400).optional(),
          })
          .strict()
          .default({}),
        tools: z.object({ allowed: list(NamePattern).optional() }).strict().default({}),
      })
      .strict()
      .default({}),
  })
  .strict()
  .superRefine((value, ctx) => {
    const ids = value.connections.rules.map((rule) => rule.id);
    if (new Set(ids).size !== ids.length) {
      ctx.addIssue({ code: 'custom', path: ['connections', 'rules'], message: 'Rule ids must be unique' });
    }
    const seen = new Set<string>();
    value.spend.limits.forEach((limit, index) => {
      const key = `${limit.kind}:${limit.unit}`;
      if (seen.has(key)) ctx.addIssue({ code: 'custom', path: ['spend', 'limits', index], message: 'One limit per period and unit' });
      seen.add(key);
    });
    const spendIds = value.spend.rules.map((rule) => rule.id);
    if (new Set(spendIds).size !== spendIds.length) {
      ctx.addIssue({ code: 'custom', path: ['spend', 'rules'], message: 'Spend rule ids must be unique' });
    }
    const labelled = new Set<string>();
    value.spend.categories.forEach((entry, index) => {
      const key = entry.merchant !== undefined ? `m:${entry.merchant}` : `p:${entry.payee}`;
      if (labelled.has(key)) ctx.addIssue({ code: 'custom', path: ['spend', 'categories', index], message: 'One category per merchant or payee' });
      labelled.add(key);
    });
  });
export type PolicyDefinition = z.infer<typeof PolicyDefinition>;
/** What a caller may send: every defaulted section can be left out. */
export type PolicyDefinitionInput = z.input<typeof PolicyDefinition>;

// ─── API ────────────────────────────────────────────────────────────

export const PolicyAgentParams = z.object({ agentId: z.string().regex(/^agt_[\w-]+$/) }).strict();
export const PolicyScopeParams = z.object({ scope: z.union([z.literal('default'), z.string().regex(/^agt_[\w-]+$/)]) }).strict();

export const SetControlPolicyInput = z
  .object({
    definition: PolicyDefinition,
    /** The revision the caller read. Required to revise a policy; absent creates one. */
    expected_revision: z.number().int().nonnegative().optional(),
  })
  .strict();
export type SetControlPolicyInput = z.infer<typeof SetControlPolicyInput>;

export const DeleteControlPolicyQuery = z.object({ expected_revision: z.coerce.number().int().nonnegative().optional() }).strict();

/** One call to try against a policy, in the terms a decision request uses. Nothing is counted, held or sent. */
export const SimulateControlPolicyInput = z
  .object({
    /** The agent whose policy applies (its own, else the default). Ignored when `definition` is given. */
    agent_id: z.string().regex(/^agt_[\w-]+$/).optional(),
    /** A draft to try instead of the stored policy. */
    definition: PolicyDefinition.optional(),
    call: z
      .object({
        action: ControlActionTypeEnum,
        /** The target as a decision request carries it (see the control socket docs). */
        target: z.record(z.unknown()).default({}),
        amount_cents: z.number().int().nonnegative().nullable().optional(),
        /** For action `proxy.call`: the call itself, to try the connection rules against it. */
        request: z
          .object({
            method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
            url: z.string().url(),
            body: z.unknown().optional(),
            query: z.record(z.string()).optional(),
          })
          .strict()
          .optional(),
        connection_id: z.string().regex(/^scon_[\w-]+$/).optional(),
        /** Try the call inside this Mission: the recipients it pinned count for a rule that leaves recipients to each Mission. */
        mission_id: z.string().regex(/^ms_[\w-]+$/).optional(),
        /**
         * For an account's own `email.send`, `sms.send` or `call.start`: the stored message (or incoming call) the send answers,
         * as a live send's `reply_to_message`. Its sender is the recipient a list that leaves the account's sends to each send
         * allows. Needs `agent_id`.
         */
        reply_to_message: z.string().min(1).max(200).optional(),
      })
      .strict(),
  })
  .strict()
  .refine((v) => v.agent_id !== undefined || v.definition !== undefined, { message: 'Name an agent or give a definition' });
export type SimulateControlPolicyInput = z.infer<typeof SimulateControlPolicyInput>;

/** Which rule refused an action, and nothing else: no values from the call, no other customer's data. */
export const PolicyRefusalEvidence = z
  .object({
    policy_id: z.string(),
    policy_revision: z.number().int(),
    section: PolicySectionEnum,
    rule: z.string(),
    code: PolicyReasonCodeEnum,
    /** The policy's own side of the comparison (a limit, an allowed list's size), never what the call carried. */
    detail: z.record(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
  })
  .strict();
export type PolicyRefusalEvidence = z.infer<typeof PolicyRefusalEvidence>;

export const PolicyFinding = z
  .object({
    kind: z.enum(['unbound_send']),
    rule_id: z.string(),
    message: z.string(),
  })
  .strict();
export type PolicyFinding = z.infer<typeof PolicyFinding>;

/**
 * What a connection grant's response adds (`control_policy`) when controls are
 * on and the agent's policy lists connections without listing this one: the
 * grant is made, and the agent still cannot call the connection until a
 * revision of the policy lists it. A loosening, so a person approves it in a
 * browser; an agent never changes its own policy.
 */
export interface GrantControlPolicyNotice {
  policy_id: string;
  /** The revision the agent is held to now; the revision that lists the connection is `revision_needed`. */
  policy_revision: number;
  /** Whose policy it is: the agent's own, or the customer's default that applies to it. */
  source: 'agent' | 'default';
  agent_id: string;
  connection_id: string;
  action_needed: 'list_connection';
  revision_needed: number;
  message: string;
}

export interface ControlPolicyView {
  id: string;
  /** Null for the customer's default policy. */
  agent_id: string | null;
  name: string;
  revision: number;
  definition: PolicyDefinition;
  /** How the last revision related to the one before it. */
  last_change: (typeof POLICY_CHANGE_KINDS)[number];
  /** Sends the policy allows without naming who receives them (only a policy started from current access can hold one). */
  findings: PolicyFinding[];
  created_at: string;
  updated_at: string;
}

export interface ControlPolicySimulationView {
  verdict: 'allow' | 'review' | 'deny';
  /** The policy that was tried: the agent's own, the default, or the draft. Null when none applies. */
  policy: { id: string | null; revision: number | null; source: 'agent' | 'default' | 'draft' } | null;
  refusal: PolicyRefusalEvidence | null;
  message: string | null;
  /** Counters that apply to this call and what is left of each (read, never counted). */
  limits: Array<{ kind: (typeof LIMIT_PERIOD_KINDS)[number]; unit: (typeof LIMIT_UNITS)[number]; limit: number; used: number; remaining: number }>;
  controls_enabled: boolean;
  checked: boolean;
}

export interface ControlReviewView {
  id: string;
  account_id: string;
  agent_id: string;
  policy_id: string;
  policy_revision: number;
  action_type: string;
  summary: string;
  status: (typeof CONTROL_REVIEW_STATUSES)[number];
  approval_id: string;
  approval_url: string;
  expires_at: string;
  created_at: string;
}
