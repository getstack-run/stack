// Policies: evaluation, revision classification and the starting policy.
//
// Pure functions over a PolicyDefinition. Nothing here reads a database, a
// clock or the network; the hosted decider (apps/api) wraps them with the
// stored policy, the counters and the review flow.
//
// The one rule that shapes all of it: a policy only narrows. It is judged
// after the connection grant, the Passport scope and the scope wall, so it can
// refuse or hold what they let through and can never let through what they
// refused. `evaluatePolicy` has no way to answer "allowed because the policy
// says so": its best answer is "the policy does not object".

import { createHash } from 'node:crypto';
import {
  POLICY_RECIPIENTS_PER_MISSION,
  POLICY_STANCE_RANK,
  SPEND_RULE_LIMIT_FIELDS,
  spendRuleScope,
  type LimitPeriodKind,
  type PaymentSurface,
  type PolicyReasonCode,
  type PolicySection,
  type PolicyChangeKind,
} from '../constants/control-policy.js';
import { CONTROL_ACTION_TYPES, type ControlActionType } from '../constants/control-socket.js';
import { expandIntents } from '../intents/index.js';
import type { IntentRef } from '../intents/types.js';
import type { Constraint } from '../schemas/passport.js';
import {
  PolicyDefinition,
  type PolicyConnectionAccess,
  type PolicyConnectionRule,
  type PolicyFinding,
  type PolicyLimit,
  type PolicyRefusalEvidence,
  type PolicySpendRule,
} from '../schemas/control-policy.js';
import { canonicalize } from './json-canonicalize.js';
import { findFailingConstraint, type NormalizedRequest } from './constraints.js';
import { fleetConstraintNarrows } from './fleet-policy.js';
import { describeConstraint, describeRefusedHttpCall } from './refusal-evidence.js';
import { assertSendRulesBounded, describeUnboundSendRule, endpointsOverlap, findUnboundSendRules, intentEndpoints, perMissionRecipientPaths } from './send-bounds.js';
import {
  MISSION_NOT_PINNED_MESSAGE,
  judgeAccountRecipients,
  judgePerMissionSend,
  type RecipientJudgement,
  type RecipientPin,
} from './mission-recipients.js';

// ─── identity of a policy ───────────────────────────────────────────

/** The policy with every list lower-cased and defaults applied, so equal policies have equal digests. */
export function normalizePolicy(raw: unknown): PolicyDefinition {
  const parsed = PolicyDefinition.parse(raw);
  const lower = <T extends string>(values: T[] | undefined): T[] | undefined =>
    values === undefined ? undefined : ([...values].map((v) => v.toLowerCase()) as T[]);
  const { surfaces, recipients } = parsed;
  return {
    ...parsed,
    recipients: { ...recipients, ...(Array.isArray(recipients.email) ? { email: lower(recipients.email)! } : {}) },
    surfaces: {
      ...surfaces,
      browser: { ...surfaces.browser, ...(surfaces.browser.hosts ? { hosts: lower(surfaces.browser.hosts)! } : {}) },
      card: { ...surfaces.card, ...(surfaces.card.merchants ? { merchants: lower(surfaces.card.merchants)! } : {}) },
      wallet: { ...surfaces.wallet, ...(surfaces.wallet.payees ? { payees: lower(surfaces.wallet.payees)! } : {}) },
    },
  };
}

export function policyDigest(definition: PolicyDefinition): string {
  return createHash('sha256').update(canonicalize(definition)).digest('hex');
}

// ─── what a decision hands to the evaluator ─────────────────────────

export interface PolicyCall {
  action: ControlActionType;
  /** The target as a decision request carries it. */
  target: Readonly<Record<string, unknown>>;
  /** The most the action can cost, in USD cents, when known. */
  amountCents: number | null;
  /**
   * In-process only. The proxy call as the proxy sees it, so a connection
   * rule's constraints can be tried against it. Absent: a rule that has
   * constraints cannot be judged and is judged against the caller.
   */
  request?: NormalizedRequest | null | undefined;
  /**
   * In-process only. The Mission the call runs under, with the recipients it pinned when it opened
   * (null for a Mission with none). Absent: the call runs under no Mission, so a rule that leaves
   * its recipients to each Mission cannot allow it.
   */
  mission?: { recipientPins: readonly RecipientPin[] | null } | null | undefined;
}

export type PolicyVerdict =
  | { verdict: 'allow' }
  | {
      verdict: 'deny' | 'review';
      section: PolicySection;
      /** The rule's id: a connection rule's own id, or the field of the section (`allowed`, `hosts`, `over_cents`). */
      rule: string;
      code: PolicyReasonCode;
      message: string;
      detail?: Record<string, string | number | boolean | null>;
    };

type Refusal = Exclude<PolicyVerdict, { verdict: 'allow' }>;
type Detail = NonNullable<Refusal['detail']>;

function refuse(
  verdict: 'deny' | 'review',
  section: PolicySection,
  rule: string,
  code: PolicyReasonCode,
  message: string,
  detail?: Detail,
): Refusal {
  return { verdict, section, rule, code, message, ...(detail ? { detail } : {}) };
}

// ─── pattern matching ───────────────────────────────────────────────

/** A name, or a prefix ending in `*`. Case-insensitive. */
export function nameMatches(pattern: string, value: string): boolean {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  return p.endsWith('*') ? v.startsWith(p.slice(0, -1)) : p === v;
}

function hostnameOf(host: string): string {
  const lower = host.toLowerCase();
  const colon = lower.lastIndexOf(':');
  return colon > -1 && !lower.endsWith(']') ? lower.slice(0, colon) : lower;
}

/** A host, or `*.host` for every subdomain (not the host itself). */
export function hostMatches(pattern: string, host: string): boolean {
  const h = hostnameOf(host);
  return pattern.startsWith('*.') ? h.endsWith(pattern.slice(1)) && h.length > pattern.length - 1 : pattern === h;
}

/** An address, or `@domain` for every address at that domain. */
export function emailMatches(pattern: string, address: string): boolean {
  const a = address.toLowerCase();
  const at = a.lastIndexOf('@');
  if (at < 1) return false;
  return pattern.startsWith('@') ? a.slice(at) === pattern : a === pattern;
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function hostOfOrigin(origin: unknown): string | null {
  const text = str(origin);
  if (!text) return null;
  try {
    return new URL(text).host.toLowerCase();
  } catch {
    return null;
  }
}

// ─── evaluation ─────────────────────────────────────────────────────

/**
 * Tries one call against a policy. A refusal outranks a hold: when one rule
 * refuses and another would hold the action for a person, it is refused.
 * Anything the policy cannot judge (a constraint with no request to try it on,
 * an amount it cannot read) is judged against the caller, never for them.
 */
export function evaluatePolicy(policy: PolicyDefinition, call: PolicyCall): PolicyVerdict {
  const state: { hold: Refusal | null } = { hold: null };
  /** A refusal stops the evaluation; a hold is remembered, and the first one wins. */
  const stops = (found: Refusal | null): Refusal | null => {
    if (!found) return null;
    if (found.verdict === 'deny') return found;
    state.hold ??= found;
    return null;
  };

  const stance = policy.actions.kinds[call.action];
  if (stance === 'deny') {
    return refuse('deny', 'actions', `kinds.${call.action}`, 'action_denied', `Your controls do not allow this kind of action (${call.action}).`);
  }
  if (stance === 'review') {
    state.hold = refuse('review', 'actions', `kinds.${call.action}`, 'review_required', `Your controls hold this kind of action (${call.action}) for a person to approve.`);
  }

  const checks: Array<() => Refusal | null> = [
    () => connectionCheck(policy, call),
    () => recipientCheck(policy, call),
    () => amountCheck(policy, call),
    () => surfaceCheck(policy, call),
  ];
  for (const check of checks) {
    const denied = stops(check());
    if (denied) return denied;
  }
  return state.hold ?? { verdict: 'allow' };
}

/** Constraints of a rule's access: its intents expanded, plus its own. Throws when an intent cannot be expanded. */
function accessConstraints(access: Pick<PolicyConnectionAccess, 'intents' | 'constraints'>): Constraint[] {
  return [...expandIntents(access.intents as IntentRef[]), ...access.constraints];
}

type RuleMatch = 'matches' | 'outside' | 'unjudged';

/** Whether the call falls inside what a rule describes. Unjudgeable is its own answer. */
function ruleMatches(rule: PolicyConnectionRule, request: NormalizedRequest | null | undefined): { match: RuleMatch; failed?: Constraint } {
  let constraints: Constraint[];
  try {
    constraints = accessConstraints(rule.access);
  } catch {
    return { match: 'unjudged' };
  }
  if (constraints.length === 0) return { match: 'matches' };
  if (!request) return { match: 'unjudged' };
  const failed = findFailingConstraint(constraints, request);
  return failed ? { match: 'outside', failed } : { match: 'matches' };
}

/**
 * What an agent is told when its policy lists connections and this one is not
 * among them (a grant made after the policy). The agent cannot change its own
 * controls, so the text names who can and how.
 */
export const NOT_LISTED_MESSAGE =
  "Your controls do not list this connection. A person must add it to this agent's policy, a loosening they approve in their browser.";

/**
 * Does this policy refuse every call on the connection because it does not
 * list it? True for a policy in `listed` mode with no rule at all for the
 * connection: a grant made after the policy, which stays uncallable until a
 * revision lists it. A rule that denies or limits the connection is the
 * customer's choice and is not this.
 */
export function connectionNeedsListing(policy: PolicyDefinition, connectionId: string): boolean {
  return policy.connections.mode === 'listed' && !policy.connections.rules.some((rule) => rule.access.connection_id === connectionId);
}

function connectionCheck(policy: PolicyDefinition, call: PolicyCall): Refusal | null {
  if (call.action !== 'proxy.call') return null;
  const connectionId = str(call.target['connection_id']);
  const { mode, rules } = policy.connections;
  if (!connectionId) {
    return mode === 'listed'
      ? refuse('deny', 'connections', 'mode', 'connection_not_listed', 'This call names no connection your controls list.')
      : null;
  }
  const own = rules.filter((rule) => rule.access.connection_id === connectionId);
  const callDetail: Detail = call.request
    ? { ...describeRefusedHttpCall(call.request) }
    : { connection_id: connectionId };

  let hold: Refusal | null = null;
  let allowed = false;
  let lastOutside: { rule: PolicyConnectionRule; failed: Constraint } | null = null;
  let perMissionRefusal: { rule: PolicyConnectionRule; judgement: Extract<RecipientJudgement, { ok: false }> } | null = null;
  for (const rule of own) {
    const judged = ruleMatches(rule, call.request);
    // Deny and review rules the policy cannot judge apply (fail closed); an allow rule it cannot judge does not.
    const applies = judged.match === 'matches' || (judged.match === 'unjudged' && rule.effect !== 'allow');
    if (!applies) {
      if (judged.match === 'outside' && judged.failed) lastOutside = { rule, failed: judged.failed };
      continue;
    }
    if (rule.effect === 'deny') {
      return refuse('deny', 'connections', rule.id, 'connection_denied', `Your controls refuse this call (rule ${rule.id}).`, callDetail);
    }
    if (rule.effect === 'review') {
      hold ??= refuse('review', 'connections', rule.id, 'review_required', `Your controls hold this call for a person to approve (rule ${rule.id}).`, callDetail);
    } else {
      if (rule.recipients === POLICY_RECIPIENTS_PER_MISSION) {
        // The rule leaves its recipients to each Mission: it allows this send only inside a Mission that pins them, and only to them.
        const paths = perMissionRecipientPaths(rule);
        const judgement: RecipientJudgement =
          paths && call.request
            ? judgePerMissionSend(paths, call.mission?.recipientPins, call.request)
            : { ok: false, code: 'recipients_not_pinned', message: MISSION_NOT_PINNED_MESSAGE };
        if (!judgement.ok) {
          perMissionRefusal ??= { rule, judgement };
          continue;
        }
      }
      allowed = true;
    }
  }
  if (hold) return hold;
  // A send that only per-job rules cover is refused, whatever the mode: the rule's allowance is the Mission's pin.
  if (!allowed && perMissionRefusal) {
    return refuse('deny', 'connections', perMissionRefusal.rule.id, perMissionRefusal.judgement.code, perMissionRefusal.judgement.message, callDetail);
  }
  // In `listed` mode a call no allow rule matches is refused. In `any` mode a per-job rule refuses only the calls it covers.
  if (mode === 'listed' && !allowed) {
    if (own.length === 0) {
      return refuse('deny', 'connections', 'mode', 'connection_not_listed', NOT_LISTED_MESSAGE, { connection_id: connectionId });
    }
    const detail: Detail = { ...callDetail };
    if (lastOutside) {
      const described = describeConstraint(lastOutside.failed);
      detail['constraint_path'] = described.path;
      detail['constraint_op'] = described.op;
    }
    return refuse('deny', 'connections', lastOutside?.rule.id ?? 'mode', 'call_outside_rules', 'This call is outside what your controls allow on this connection.', detail);
  }
  return null;
}

function recipientsOf(call: PolicyCall, field: 'address' | 'number'): string[] | null {
  const raw = call.target['recipients'];
  if (!Array.isArray(raw)) return null;
  const out: string[] = [];
  for (const entry of raw) {
    const value = entry && typeof entry === 'object' ? str((entry as Record<string, unknown>)[field]) : null;
    if (!value) return null;
    out.push(value);
  }
  return out;
}

/** A send under an account list that leaves its recipients to each send: judged against what the call pinned. */
function perMissionAccountCheck(call: PolicyCall, rule: 'email' | 'sms' | 'call', recipients: string[] | null): Refusal | null {
  const judgement = judgeAccountRecipients(call.mission?.recipientPins, rule, recipients);
  if (judgement.ok) return null;
  return refuse('deny', 'recipients', rule, judgement.code, judgement.message);
}

function recipientCheck(policy: PolicyDefinition, call: PolicyCall): Refusal | null {
  const { email, sms, call: calls } = policy.recipients;
  if (call.action === 'email.send' && email === POLICY_RECIPIENTS_PER_MISSION) {
    return perMissionAccountCheck(call, 'email', recipientsOf(call, 'address'));
  }
  if (call.action === 'sms.send' && sms === POLICY_RECIPIENTS_PER_MISSION) {
    return perMissionAccountCheck(call, 'sms', recipientsOf(call, 'number'));
  }
  if (call.action === 'call.start' && calls === POLICY_RECIPIENTS_PER_MISSION) {
    return perMissionAccountCheck(call, 'call', recipientsOf(call, 'number'));
  }
  if (call.action === 'email.send' && Array.isArray(email)) {
    const addresses = recipientsOf(call, 'address');
    if (!addresses || addresses.length === 0) return refuse('deny', 'recipients', 'email', 'policy_unevaluable', 'Your controls list who this agent may email, and this send names no recipient they can read.');
    if (addresses.some((a) => !(email as string[]).some((pattern) => emailMatches(pattern, a)))) {
      return refuse('deny', 'recipients', 'email', 'recipient_not_allowed', 'This recipient is not on the list of addresses your controls allow this agent to email.', { allowed_entries: (email as string[]).length });
    }
  }
  const numberRule = call.action === 'sms.send' ? { list: sms, rule: 'sms', noun: 'text' } : call.action === 'call.start' ? { list: calls, rule: 'call', noun: 'call' } : null;
  if (numberRule && Array.isArray(numberRule.list)) {
    const numbers = recipientsOf(call, 'number');
    if (!numbers || numbers.length === 0) return refuse('deny', 'recipients', numberRule.rule, 'policy_unevaluable', `Your controls list who this agent may ${numberRule.noun}, and this one names no number they can read.`);
    if (numbers.some((n) => !(numberRule.list as string[]).includes(n))) {
      return refuse('deny', 'recipients', numberRule.rule, 'recipient_not_allowed', `This number is not on the list your controls allow this agent to ${numberRule.noun}.`, { allowed_entries: (numberRule.list as string[]).length });
    }
  }
  return null;
}

function amountCheck(policy: PolicyDefinition, call: PolicyCall): Refusal | null {
  const { amountCents } = call;
  const cap = policy.spend.max_per_action_cents;
  if (cap !== undefined && amountCents !== null && amountCents > cap) {
    return refuse('deny', 'spend', 'max_per_action_cents', 'amount_over_limit', 'This action costs more than your controls allow for one action.', { limit_cents: cap });
  }
  const over = policy.review.over_cents;
  if (over !== undefined && amountCents !== null && amountCents > over) {
    return refuse('review', 'review', 'over_cents', 'review_required', 'Your controls hold actions above this amount for a person to approve.', { over_cents: over });
  }
  return null;
}

function surfaceCheck(policy: PolicyDefinition, call: PolicyCall): Refusal | null {
  const { surfaces } = policy;
  switch (call.action) {
    case 'model.call': {
      const list = surfaces.models.allowed;
      if (!list) return null;
      const model = str(call.target['model']);
      const provider = str(call.target['provider']);
      if (!model || !list.some((p) => nameMatches(p, model) || (provider !== null && nameMatches(p, `${provider}/${model}`)))) {
        return refuse('deny', 'models', 'allowed', 'model_not_allowed', 'This model is not on the list your controls allow.', { allowed_entries: list.length });
      }
      return null;
    }
    case 'browser.navigate': {
      const list = surfaces.browser.hosts;
      if (!list) return null;
      const host = hostOfOrigin(call.target['origin']);
      if (!host || !list.some((p) => hostMatches(p, host))) {
        return refuse('deny', 'browser', 'hosts', 'host_not_allowed', 'This site is not on the list your controls allow the browser to visit.', { allowed_entries: list.length });
      }
      return null;
    }
    case 'card.checkout': {
      const { merchants, max_amount_cents: cap } = surfaces.card;
      if (merchants) {
        const host = hostOfOrigin(call.target['merchant_origin']);
        if (!host || !merchants.some((p) => hostMatches(p, host))) {
          return refuse('deny', 'card', 'merchants', 'merchant_not_allowed', 'This merchant is not on the list your controls allow the card to pay.', { allowed_entries: merchants.length });
        }
      }
      if (cap !== undefined) {
        if (call.amountCents === null) return refuse('deny', 'card', 'max_amount_cents', 'policy_unevaluable', 'Your controls cap card purchases in USD, and this one is not in USD.');
        if (call.amountCents > cap) return refuse('deny', 'card', 'max_amount_cents', 'amount_over_limit', 'This purchase is over the card limit your controls set.', { limit_cents: cap });
      }
      return spendRuleCheck(policy, call, paymentFactsOf('card.checkout', call.target)!);
    }
    case 'wallet.payment': {
      const { payees, max_amount_cents: cap } = surfaces.wallet;
      if (payees) {
        const payee = str(call.target['payee'])?.toLowerCase();
        if (!payee || !payees.includes(payee)) {
          return refuse('deny', 'wallet', 'payees', 'payee_not_allowed', 'This payee is not on the list your controls allow the wallet to pay.', { allowed_entries: payees.length });
        }
      }
      if (cap !== undefined) {
        if (call.amountCents === null) return refuse('deny', 'wallet', 'max_amount_cents', 'policy_unevaluable', 'Your controls cap wallet payments, and this amount could not be read.');
        if (call.amountCents > cap) return refuse('deny', 'wallet', 'max_amount_cents', 'amount_over_limit', 'This payment is over the wallet limit your controls set.', { limit_cents: cap });
      }
      return spendRuleCheck(policy, call, paymentFactsOf('wallet.payment', call.target)!);
    }
    case 'workspace.exec': {
      const { max_timeout_seconds: max } = surfaces.workspace;
      if (max !== undefined) {
        // The target names the limit the command will run under (the platform's own when the agent named none); a command started
        // in the background names none (null), so a cap on how long a command may run refuses it.
        const timeout = call.target['timeout_seconds'];
        if (typeof timeout !== 'number') return refuse('deny', 'workspace', 'max_timeout_seconds', 'policy_unevaluable', 'Your controls cap how long a workspace command may run, and this one names no limit they can read.');
        if (timeout > max) return refuse('deny', 'workspace', 'max_timeout_seconds', 'timeout_over_limit', 'This command may run longer than your controls allow.', { limit_seconds: max });
      }
      return null;
    }
    case 'tool.run': {
      const list = surfaces.tools.allowed;
      if (!list) return null;
      const provider = str(call.target['provider']);
      const endpoint = str(call.target['endpoint']);
      if (!provider || !list.some((p) => nameMatches(p, provider) || (endpoint !== null && nameMatches(p, `${provider}/${endpoint}`)))) {
        return refuse('deny', 'tools', 'allowed', 'tool_not_allowed', 'This tool is not on the list your controls allow.', { allowed_entries: list.length });
      }
      return null;
    }
    default:
      return null;
  }
}

/** The evidence a refusal carries: which policy, which rule, never a value from the call. */
export function refusalEvidence(
  policy: { id: string; revision: number },
  refusal: Refusal,
): PolicyRefusalEvidence {
  // A connection the policy does not list: the revision that would list it is the next one, so the refusal says so.
  const detail =
    refusal.code === 'connection_not_listed' && refusal.rule === 'mode' && policy.id !== 'draft'
      ? { ...refusal.detail, revision_needed: policy.revision + 1 }
      : refusal.detail;
  return {
    policy_id: policy.id,
    policy_revision: policy.revision,
    section: refusal.section,
    rule: refusal.rule,
    code: refusal.code,
    ...(detail ? { detail } : {}),
  };
}

// ─── spend rules: merchants, payees, categories ─────────────────────

/** What a payment is, as far as the policy can tell. A null is unknown, and unknown is held to the strictest rule. */
export interface PaymentFacts {
  surface: PaymentSurface;
  /** The card merchant's host, lower case, no port. */
  merchant: string | null;
  /** The wallet payee's address, lower case. */
  payee: string | null;
}

/** The payment a card checkout or a wallet payment is, from a decision target. Null for any other action. */
export function paymentFactsOf(action: ControlActionType, target: Readonly<Record<string, unknown>>): PaymentFacts | null {
  if (action === 'card.checkout') {
    const host = hostOfOrigin(target['merchant_origin']);
    return { surface: 'card', merchant: host ? hostnameOf(host) : null, payee: null };
  }
  if (action === 'wallet.payment') {
    return { surface: 'wallet', merchant: null, payee: str(target['payee'])?.toLowerCase() ?? null };
  }
  return null;
}

/**
 * The category the customer gave this merchant or payee, or null when none
 * (or when two labels disagree): an unknown category is never guessed.
 */
export function categoryOf(policy: PolicyDefinition, facts: PaymentFacts): string | null {
  const found = new Set<string>();
  for (const entry of policy.spend.categories) {
    if (facts.surface === 'card' && entry.merchant !== undefined && facts.merchant !== null && hostMatches(entry.merchant, facts.merchant)) {
      found.add(entry.category);
    }
    if (facts.surface === 'wallet' && entry.payee !== undefined && facts.payee !== null && entry.payee === facts.payee) {
      found.add(entry.category);
    }
  }
  return found.size === 1 ? [...found][0]! : null;
}

/**
 * The spend rules this payment may fall under. A rule that names a merchant, a
 * payee or a category applies when the payment's own is that one, or is not
 * known: an unknown merchant or category is held to every rule that might
 * match it, which is the strictest reading, never the loosest.
 */
export function matchingSpendRules(policy: PolicyDefinition, facts: PaymentFacts): PolicySpendRule[] {
  const category = categoryOf(policy, facts);
  return policy.spend.rules.filter((rule) => {
    if (rule.merchant !== undefined) {
      if (facts.surface !== 'card') return false;
      if (facts.merchant !== null && !hostMatches(rule.merchant, facts.merchant)) return false;
    }
    if (rule.payee !== undefined) {
      if (facts.surface !== 'wallet') return false;
      if (facts.payee !== null && facts.payee !== rule.payee) return false;
    }
    if (rule.category !== undefined && category !== null && category !== rule.category) return false;
    return true;
  });
}

/** One counter a payment counts in: a window of one rule. */
export interface SpendCounter {
  ruleId: string;
  kind: Extract<LimitPeriodKind, 'day' | 'month'>;
  limit: number;
  /** Where the counter sits (see spendRuleScope). */
  scope: string;
}

export interface SpendPlan {
  /** The tightest per-payment limit among the matching rules, and the rule that sets it. */
  perPayment: { limit: number; ruleId: string } | null;
  counters: SpendCounter[];
}

/** What a payment is held to: the per-payment ceiling and the counters it counts in, from the rules it may fall under. */
export function spendPlanFor(policy: PolicyDefinition, facts: PaymentFacts): SpendPlan {
  let perPayment: SpendPlan['perPayment'] = null;
  const counters: SpendCounter[] = [];
  for (const rule of matchingSpendRules(policy, facts)) {
    if (rule.max_per_payment_cents !== undefined && (perPayment === null || rule.max_per_payment_cents < perPayment.limit)) {
      perPayment = { limit: rule.max_per_payment_cents, ruleId: rule.id };
    }
    if (rule.max_per_day_cents !== undefined) {
      counters.push({ ruleId: rule.id, kind: 'day', limit: rule.max_per_day_cents, scope: spendRuleScope(rule.id) });
    }
    if (rule.max_per_month_cents !== undefined) {
      counters.push({ ruleId: rule.id, kind: 'month', limit: rule.max_per_month_cents, scope: spendRuleScope(rule.id) });
    }
  }
  return { perPayment, counters };
}

function spendRuleCheck(policy: PolicyDefinition, call: PolicyCall, facts: PaymentFacts): Refusal | null {
  const plan = spendPlanFor(policy, facts);
  if (plan.perPayment === null) return null;
  const { limit, ruleId } = plan.perPayment;
  const rule = `rules.${ruleId}.max_per_payment_cents`;
  if (call.amountCents === null) {
    return refuse('deny', 'spend', rule, 'policy_unevaluable', 'Your controls cap what one payment may cost in USD, and this amount could not be read in USD.');
  }
  if (call.amountCents > limit) {
    return refuse('deny', 'spend', rule, 'amount_over_limit', 'This payment is over the limit your controls set for this merchant or category.', { limit_cents: limit });
  }
  return null;
}

/**
 * The limits a customer set for approving held payments from a chat. Both or
 * nothing: with either missing, chat approval of payments is off.
 */
export function chatApprovalLimits(policy: Pick<PolicyDefinition, 'review'>): { perPaymentCents: number; perDayCents: number } | null {
  const chat = policy.review.chat;
  if (chat?.max_per_payment_cents === undefined || chat.max_per_day_cents === undefined) return null;
  return { perPaymentCents: chat.max_per_payment_cents, perDayCents: chat.max_per_day_cents };
}

/** Spend-rule revisions: every rule of the current policy must be covered by a rule at least as wide and no looser. */
function spendRulesNarrow(next: PolicyDefinition['spend'], current: PolicyDefinition['spend']): boolean {
  const covers = (n: PolicySpendRule, c: PolicySpendRule): boolean => {
    // Scope: n must apply to everything c applies to.
    if (n.merchant !== undefined && (c.merchant === undefined || !hostCovers(c.merchant, n.merchant))) return false;
    if (n.payee !== undefined && n.payee !== c.payee) return false;
    if (n.category !== undefined && n.category !== c.category) return false;
    // Limits: every limit c sets, n sets at least as low.
    for (const field of SPEND_RULE_LIMIT_FIELDS) {
      const was = c[field];
      if (was !== undefined && (n[field] === undefined || n[field]! > was)) return false;
    }
    return true;
  };
  if (!current.rules.every((c) => next.rules.some((n) => covers(n, c)))) return false;
  // A category rule leans on the customer's labels (an unlabelled merchant is held to every category rule), so with
  // one in force the labels must not change: adding a label could move a merchant out of a strict category.
  if (current.rules.some((rule) => rule.category !== undefined)) {
    const labels = (spend: PolicyDefinition['spend']) =>
      spend.categories.map((entry) => canonicalize(entry)).sort().join('|');
    if (labels(next) !== labels(current)) return false;
  }
  return true;
}

/** Chat approval is off when absent, so a narrower setting is "off, or no higher than before". */
function chatApprovalNarrows(next: PolicyDefinition, current: PolicyDefinition): boolean {
  const was = chatApprovalLimits(current);
  const now = chatApprovalLimits(next);
  if (now === null) return true;
  if (was === null) return false;
  return now.perPaymentCents <= was.perPaymentCents && now.perDayCents <= was.perDayCents;
}

// ─── limits ─────────────────────────────────────────────────────────

/** The window a counter row is kept under. Day and month are UTC; a Mission is its own id. */
export function limitWindowKey(kind: LimitPeriodKind, now: Date, missionId: string | null): string {
  switch (kind) {
    case 'day':
      return now.toISOString().slice(0, 10);
    case 'month':
      return now.toISOString().slice(0, 7);
    case 'mission':
      // A call with no Mission shares one bucket, which is the stricter reading of a Mission limit.
      return missionId ?? 'no_mission';
  }
}

/**
 * The key a counter row is kept under: the window's own key, and for a counter
 * that belongs to one spend rule or to chat approvals, that scope after an `@`.
 * One table, one primary key, no second counter machinery.
 */
export function scopedPeriodKey(windowKey: string, scope: string | undefined): string {
  return scope ? `${windowKey}@${scope}` : windowKey;
}

export function limitsOf(policy: PolicyDefinition, unit: PolicyLimit['unit']): PolicyLimit[] {
  return policy.spend.limits.filter((limit) => limit.unit === unit);
}

// ─── revisions: narrowing and loosening ─────────────────────────────

const ALL_KINDS: readonly ControlActionType[] = CONTROL_ACTION_TYPES;

type Covers<T> = (next: T, current: T) => boolean;

/** Lists are allowlists: absent means no restriction, so a list may only shrink and may not appear to disappear. */
function listNarrows<T>(next: readonly T[] | undefined, current: readonly T[] | undefined, covers: Covers<T>): boolean {
  if (current === undefined) return true;
  if (next === undefined) return false;
  return next.every((entry) => current.some((existing) => covers(entry, existing)));
}

/**
 * The account's recipients: a list, `per_mission` (each send names who it answers) or absent. A list is narrower than
 * absent and per-send is narrower than absent, but neither is provably narrower than the other, so a change from one to the
 * other is a loosening.
 */
function recipientListNarrows(
  next: readonly string[] | typeof POLICY_RECIPIENTS_PER_MISSION | undefined,
  current: readonly string[] | typeof POLICY_RECIPIENTS_PER_MISSION | undefined,
  covers: Covers<string>,
): boolean {
  if (current === undefined) return true;
  if (current === POLICY_RECIPIENTS_PER_MISSION) return next === POLICY_RECIPIENTS_PER_MISSION;
  if (next === undefined || next === POLICY_RECIPIENTS_PER_MISSION) return false;
  return listNarrows(next, current, covers);
}

/** Numbers are ceilings: absent means no ceiling, so a ceiling may only fall. */
function capNarrows(next: number | undefined, current: number | undefined): boolean {
  if (current === undefined) return true;
  return next !== undefined && next <= current;
}

const sameString: Covers<string> = (a, b) => a === b;
const emailCovers: Covers<string> = (next, current) =>
  next === current || (current.startsWith('@') && !next.startsWith('@') && next.endsWith(current));
const nameCovers: Covers<string> = (next, current) =>
  current.endsWith('*') ? next.toLowerCase().startsWith(current.slice(0, -1).toLowerCase()) : next.toLowerCase() === current.toLowerCase();
/** `*.x.com` covers every host and wildcard strictly below x.com; an exact host covers only itself. */
const hostCovers: Covers<string> = (next, current) => {
  if (next === current) return true;
  if (!current.startsWith('*.')) return false;
  const base = next.startsWith('*.') ? next.slice(2) : next;
  return base.endsWith(current.slice(1));
};

function accessNarrows(child: PolicyConnectionAccess, parent: PolicyConnectionAccess): boolean {
  if (child.connection_id !== parent.connection_id) return false;
  const childConstraints = accessConstraints(child);
  return accessConstraints(parent).every((p) => childConstraints.some((c) => fleetConstraintNarrows(c, p)));
}

function connectionsNarrow(next: PolicyDefinition['connections'], current: PolicyDefinition['connections']): boolean {
  if (current.mode === 'listed' && next.mode === 'any') return false;
  // A refusal or a hold that is gone, or made weaker, would admit what it stopped: each must be kept at least as tight.
  for (const kept of current.rules.filter((rule) => rule.effect !== 'allow')) {
    const covered = next.rules.some(
      (rule) =>
        POLICY_STANCE_RANK[rule.effect] <= POLICY_STANCE_RANK[kept.effect] &&
        accessNarrows(kept.access, rule.access),
    );
    if (!covered) return false;
  }
  // A rule that leaves its recipients to each Mission limits sends in either mode, so it must stay: kept by a rule that is
  // per job as well, or by a hold or a refusal.
  for (const kept of current.rules.filter((rule) => rule.recipients === POLICY_RECIPIENTS_PER_MISSION)) {
    const covered = next.rules.some(
      (rule) =>
        accessNarrows(kept.access, rule.access) &&
        (rule.effect !== 'allow' || rule.recipients === POLICY_RECIPIENTS_PER_MISSION),
    );
    if (!covered) return false;
  }
  // An allowance the current policy did not give, at the endpoint of a send a kept per-job rule covers, would send where the rule
  // refused, in either mode: it must be per job itself (or hold or refuse), or be inside a plain allowance the current policy had.
  for (const kept of current.rules.filter((rule) => rule.effect === 'allow' && rule.recipients === POLICY_RECIPIENTS_PER_MISSION)) {
    const keptEndpoints = intentEndpoints(kept.access, 'sends');
    for (const rule of next.rules.filter((r) => r.effect === 'allow' && r.recipients !== POLICY_RECIPIENTS_PER_MISSION && r.access.connection_id === kept.access.connection_id)) {
      const already = current.rules.some(
        (parent) => parent.effect === 'allow' && parent.recipients !== POLICY_RECIPIENTS_PER_MISSION && accessNarrows(rule.access, parent.access),
      );
      if (already) continue;
      const own = intentEndpoints(rule.access, 'all');
      if (keptEndpoints === null || own === null || endpointsOverlap(own, keptEndpoints)) return false;
    }
  }
  // In `listed` mode every allowance in the next policy must sit inside one the current policy gave.
  if (current.mode === 'listed') {
    for (const rule of next.rules.filter((r) => r.effect !== 'deny')) {
      const inside = current.rules.some(
        (parent) =>
          parent.effect !== 'deny' &&
          POLICY_STANCE_RANK[parent.effect] >= POLICY_STANCE_RANK[rule.effect] &&
          accessNarrows(rule.access, parent.access) &&
          // Inside a per-job allowance means per job as well: a rule that names its own recipients needs no pinned Mission.
          !(parent.effect === 'allow' && parent.recipients === POLICY_RECIPIENTS_PER_MISSION && rule.effect === 'allow' && rule.recipients !== POLICY_RECIPIENTS_PER_MISSION),
      );
      if (!inside) return false;
    }
  }
  return true;
}

function limitsNarrow(next: readonly PolicyLimit[], current: readonly PolicyLimit[]): boolean {
  return current.every((c) => {
    const n = next.find((l) => l.kind === c.kind && l.unit === c.unit);
    return n !== undefined && n.limit <= c.limit;
  });
}

/**
 * Is `next` provably no wider than `current`? Deliberately conservative:
 * anything it cannot prove narrower answers false, and a human approves it.
 * `null` is "no policy", the widest there is.
 */
export function policyNarrows(next: PolicyDefinition | null, current: PolicyDefinition | null): boolean {
  if (current === null) return true;
  if (next === null) return false;
  try {
    if (!connectionsNarrow(next.connections, current.connections)) return false;
    for (const kind of ALL_KINDS) {
      const was = POLICY_STANCE_RANK[current.actions.kinds[kind] ?? 'allow'];
      const now = POLICY_STANCE_RANK[next.actions.kinds[kind] ?? 'allow'];
      if (now > was) return false;
    }
    const r = { n: next.recipients, c: current.recipients };
    if (!recipientListNarrows(r.n.email, r.c.email, emailCovers)) return false;
    if (!recipientListNarrows(r.n.sms, r.c.sms, sameString)) return false;
    if (!recipientListNarrows(r.n.call, r.c.call, sameString)) return false;
    if (!capNarrows(next.spend.max_per_action_cents, current.spend.max_per_action_cents)) return false;
    if (!capNarrows(next.spend.max_concurrent, current.spend.max_concurrent)) return false;
    if (!limitsNarrow(next.spend.limits, current.spend.limits)) return false;
    if (!spendRulesNarrow(next.spend, current.spend)) return false;
    if (!capNarrows(next.review.over_cents, current.review.over_cents)) return false;
    if (!chatApprovalNarrows(next, current)) return false;
    const s = { n: next.surfaces, c: current.surfaces };
    if (!listNarrows(s.n.models.allowed, s.c.models.allowed, nameCovers)) return false;
    if (!capNarrows(s.n.models.max_cost_per_call_cents, s.c.models.max_cost_per_call_cents)) return false;
    if (!listNarrows(s.n.browser.hosts, s.c.browser.hosts, hostCovers)) return false;
    if (!listNarrows(s.n.card.merchants, s.c.card.merchants, hostCovers)) return false;
    if (!capNarrows(s.n.card.max_amount_cents, s.c.card.max_amount_cents)) return false;
    if (!listNarrows(s.n.wallet.payees, s.c.wallet.payees, sameString)) return false;
    if (!capNarrows(s.n.wallet.max_amount_cents, s.c.wallet.max_amount_cents)) return false;
    if (!capNarrows(s.n.workspace.max_timeout_seconds, s.c.workspace.max_timeout_seconds)) return false;
    if (!listNarrows(s.n.tools.allowed, s.c.tools.allowed, nameCovers)) return false;
    return true;
  } catch {
    // An intent that no longer expands, or a rule too large to compare: a person decides.
    return false;
  }
}

/**
 * How a revision relates to the policy it replaces. A change that is not
 * provably a tightening, mixed changes included, is a loosening.
 */
export function classifyPolicyRevision(next: PolicyDefinition | null, current: PolicyDefinition | null): Extract<PolicyChangeKind, 'tighten' | 'loosen' | 'unchanged'> {
  if (next !== null && current !== null && policyDigest(next) === policyDigest(current)) return 'unchanged';
  return policyNarrows(next, current) ? 'tighten' : 'loosen';
}

// ─── send bounds and findings ───────────────────────────────────────

/** Does a rule of this policy leave its recipients to each Mission? Only then does a call need its Mission's pins read. */
export function policyUsesPerMission(policy: PolicyDefinition): boolean {
  return policy.connections.rules.some((rule) => rule.recipients === POLICY_RECIPIENTS_PER_MISSION);
}

/**
 * Only the rules of this policy that leave their recipients to each Mission, and nothing else: no listed mode, no
 * other rule, no limit, no hold. A call tried against it is refused only for want of a pinned recipient. This is how a
 * delegated Passport, which runs in the Mission of the agent that delegated, is held to the per-job rules of the agent
 * the Mission was opened for as well as to its own policy.
 */
export function perMissionRulesOnly(policy: PolicyDefinition): PolicyDefinition {
  return normalizePolicy({
    name: policy.name,
    connections: { mode: 'any', rules: policy.connections.rules.filter((rule) => rule.recipients === POLICY_RECIPIENTS_PER_MISSION) },
  });
}

/** Refuses a new or revised policy that allows a send without naming who receives it. */
export function assertPolicyBounded(policy: PolicyDefinition, providerOf?: (connectionId: string) => string | undefined): void {
  assertSendRulesBounded({ rules: policy.connections.rules }, providerOf);
}

/** The sends a stored policy allows without naming who receives them. */
export function policyFindings(policy: PolicyDefinition, providerOf?: (connectionId: string) => string | undefined): PolicyFinding[] {
  return findUnboundSendRules({ rules: policy.connections.rules }, providerOf).map((finding) => ({
    kind: 'unbound_send' as const,
    rule_id: finding.rule_id,
    message: describeUnboundSendRule(finding),
  }));
}

// ─── start from current access ──────────────────────────────────────

export interface GrantForPolicy {
  connection_id: string;
  constraints: readonly Constraint[] | null;
}

/**
 * A policy equal to an agent's current grants: only the connections it holds
 * grants for may be called, each within the constraints the grant already
 * carries. Every call it admits was admitted by the grant, so it changes no
 * outcome until it is tightened. A connection granted afterwards is not
 * listed: a policy never opens anything, so it is added on purpose.
 */
export function startingPolicyFromGrants(name: string, grants: readonly GrantForPolicy[]): PolicyDefinition {
  const sorted = [...grants].sort((a, b) => a.connection_id.localeCompare(b.connection_id));
  return normalizePolicy({
    name,
    connections: {
      mode: 'listed',
      rules: sorted.map((grant, index) => ({
        id: `connection-${index + 1}`,
        effect: 'allow',
        access: {
          connection_id: grant.connection_id,
          intents: [],
          // The grant's own constraints, which already bound every call it admits (a grant that carries more than a rule can hold keeps its first 32: the grant still enforces the rest).
          constraints: (grant.constraints ?? []).slice(0, 32),
        },
      })),
    },
  });
}
