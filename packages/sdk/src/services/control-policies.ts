import type { HttpClient } from '../client.js';
import type { ControlActionType } from './control-socket.js';

// Policies: the configuration behind hosted controls. A policy only narrows
// what a connection grant already allows: it refuses an action, holds it for a
// person, or limits it. It never opens anything. It is stored by STACK, one per
// agent plus one default for the customer, and is never bound into a Passport.
//
// Every call is an owner or admin decision and never available to an agent: an
// agent can never read or change its own controls. Tightening a policy applies
// at once. Loosening it, and deleting it, needs a person in a signed-in
// browser: without a dashboard session the call throws
// `GovernanceApprovalRequiredError` first; once a person approves at its link,
// send the same call again with its `governanceApprovalId`. A revision that is
// not provably a tightening counts as a loosening. Controls must be on
// (`CONTROLS_NOT_ENABLED` otherwise). None of it is metered.
//
// A refused action reaches the agent as `CONTROL_DENIED` (`ControlDeniedError`),
// whose `rule` says which rule refused and never a value from the call.

export type PolicyStance = 'allow' | 'review' | 'deny';
/** `any`: every connection the agent has a grant for, minus what a rule denies or holds. `listed`: only what an allow rule names. */
export type PolicyConnectionMode = 'any' | 'listed';
export type LimitPeriodKind = 'day' | 'month' | 'mission';
export type LimitUnit = 'cents' | 'actions';
/** The part of a policy a refusal came from. */
export type PolicySection =
  | 'connections'
  | 'actions'
  | 'recipients'
  | 'spend'
  | 'review'
  | 'models'
  | 'browser'
  | 'card'
  | 'wallet'
  | 'workspace'
  | 'tools';
/** The stable reason a hosted refusal carries. */
export type PolicyReasonCode =
  | 'connection_denied'
  | 'connection_not_listed'
  | 'call_outside_rules'
  | 'action_denied'
  | 'recipient_not_allowed'
  | 'recipients_not_pinned'
  | 'amount_over_limit'
  | 'model_not_allowed'
  | 'cost_over_limit'
  | 'host_not_allowed'
  | 'merchant_not_allowed'
  | 'payee_not_allowed'
  | 'timeout_over_limit'
  | 'tool_not_allowed'
  | 'limit_reached'
  | 'concurrency_reached'
  | 'review_required'
  | 'review_pending'
  | 'review_rejected'
  | 'review_mismatch'
  | 'policy_unevaluable';
/** How a revision relates to the one before it. A mixed change is a loosening. */
export type PolicyChangeKind = 'create' | 'start_from_access' | 'tighten' | 'loosen' | 'delete' | 'unchanged';
export type ControlReviewStatus = 'pending' | 'approved' | 'consuming' | 'consumed' | 'rejected' | 'expired';

export type PolicyConstraintOp =
  | 'eq'
  | 'not_eq'
  | 'in'
  | 'not_in'
  | 'matches'
  | 'starts_with'
  | 'lt'
  | 'lte'
  | 'gt'
  | 'gte'
  | 'exists'
  | 'not_exists'
  | 'any_of';

/**
 * A condition on one field of a call, for example `{ path: 'body.to', op: 'in', value: ['a@example.com'] }`. The one
 * exception is `{ path: 'any_of', op: 'any_of', value: [[...], [...]] }`: a choice of rules, each a list of conditions,
 * which holds when any one list holds in full (a rule started from a grant that names several does this).
 */
export interface PolicyConstraint {
  path: string;
  op: PolicyConstraintOp;
  value: string | number | boolean | string[] | Array<Array<PolicyConstraint>>;
}

export interface PolicyConnectionAccess {
  connection_id: string;
  /** The calls (by intent name and parameters) the rule is about. */
  intents?: Array<{ name: string; params?: Record<string, unknown> }>;
  constraints?: PolicyConstraint[];
}

/**
 * Recipients set per job: a send rule that leaves who may be written to each
 * Mission. Each Mission names who it may send to (`recipients`,
 * `recipient_pins` or `reply_to_message` when it is opened). A delegated Passport
 * carries the same Mission, so it carries the same recipients.
 */
export const POLICY_RECIPIENTS_PER_MISSION = 'per_mission' as const;
export type PolicyRecipientsPerMission = typeof POLICY_RECIPIENTS_PER_MISSION;

export interface PolicyConnectionRule {
  /** Unique within the policy. */
  id: string;
  effect: PolicyStance;
  access: PolicyConnectionAccess;
  /**
   * `per_mission`: recipients set per job. Each Mission names who it may send to. The rule allows a send only inside a
   * Mission that pins every recipient field the send names with an exact value (`eq` or `in`), and only to those
   * values; a Mission without the pin is refused (`recipients_not_pinned`). Only on an `allow` rule that names a send
   * intent with a recipient field (not a reply, a stored draft or a rule of raw constraints). Without it, a send rule
   * that does not name its recipients is refused when written (`UnboundedSendRuleError`).
   */
  recipients?: PolicyRecipientsPerMission;
}

export interface PolicyLimit {
  kind: LimitPeriodKind;
  unit: LimitUnit;
  limit: number;
}

/**
 * Limits for the card purchases and wallet payments one rule matches. Name a
 * card `merchant` (a host, or `*.host`), a wallet `payee` (a lower-case 0x
 * address), a `category`, or none of them for every payment. At least one limit
 * is set. The day and month limits (USD cents, UTC) have a counter of their own
 * per rule that parallel payments cannot overrun. A payment whose merchant,
 * payee or category is not known (a merchant you never labelled) is held to,
 * and counted against, every rule it might match: the strictest applies.
 */
export interface PolicySpendRule {
  /** Unique within the policy. */
  id: string;
  merchant?: string;
  payee?: string;
  category?: string;
  max_per_payment_cents?: number;
  max_per_day_cents?: number;
  max_per_month_cents?: number;
}

/**
 * Which category a card merchant or wallet payee belongs to, as you say. The
 * card authorisation names the merchant and no category, so categories are
 * your labels. Name exactly one of `merchant` and `payee`.
 */
export interface PolicySpendCategory {
  merchant?: string;
  payee?: string;
  category: string;
}

/**
 * Approving a held payment from a verified chat (Telegram, text, Slack): off
 * until BOTH limits are set, and then only for a payment within them. There is
 * no STACK default. Raising either, or turning it on, is a loosening.
 */
export interface PolicyChatApproval {
  max_per_payment_cents?: number;
  max_per_day_cents?: number;
}

/**
 * A policy. Every list is an allowlist when present and "no restriction" when
 * absent; every number is a ceiling. A smaller list or a lower number is a
 * tightening, the reverse a loosening. Every section can be left out.
 */
export interface PolicyDefinition {
  name: string;
  /** Which connections a call may use, and which calls on them need a person or are refused. */
  connections?: { mode?: PolicyConnectionMode; rules?: PolicyConnectionRule[] };
  /** One stance per kind of action; a kind not named here is allowed. */
  actions?: { kinds?: Partial<Record<ControlActionType, PolicyStance>> };
  /**
   * Where the account's own email, texts and calls may go: addresses (or `@domain`), and E.164 numbers. Each is a list,
   * or `per_mission`: the send then names a stored message it answers (`reply_to_message`) and goes only to whoever wrote
   * it. A send that names none is refused (`recipients_not_pinned`), any other recipient is `recipient_not_allowed`.
   */
  recipients?: {
    email?: string[] | PolicyRecipientsPerMission;
    sms?: string[] | PolicyRecipientsPerMission;
    call?: string[] | PolicyRecipientsPerMission;
  };
  spend?: {
    /** The most one action may cost, in USD cents. */
    max_per_action_cents?: number;
    /** Counters that parallel calls cannot overrun. One per period and unit. */
    limits?: PolicyLimit[];
    /** Actions of one agent running at the same moment. */
    max_concurrent?: number;
    /** Per-merchant, per-payee and per-category limits for card purchases and wallet payments. */
    rules?: PolicySpendRule[];
    /** Which category a merchant or a payee belongs to. */
    categories?: PolicySpendCategory[];
  };
  /** Hold an action for a person above this amount, in USD cents. */
  review?: { over_cents?: number; /** Approving a held payment from a verified chat; off until both limits are set. */ chat?: PolicyChatApproval };
  /** The account's own surfaces. */
  surfaces?: {
    models?: { allowed?: string[]; max_cost_per_call_cents?: number };
    browser?: { hosts?: string[] };
    card?: { merchants?: string[]; max_amount_cents?: number };
    wallet?: { payees?: string[]; max_amount_cents?: number };
    workspace?: { max_timeout_seconds?: number };
    tools?: { allowed?: string[] };
  };
}

/** A send a policy allows without naming who receives it. */
export interface PolicyFinding {
  kind: 'unbound_send';
  rule_id: string;
  message: string;
}

export interface ControlPolicyView {
  id: string;
  /** Null for the customer's default policy. */
  agent_id: string | null;
  name: string;
  revision: number;
  definition: PolicyDefinition;
  last_change: PolicyChangeKind;
  /** Sends the policy allows without naming who receives them (only a policy started from current access can hold one). */
  findings: PolicyFinding[];
  created_at: string;
  updated_at: string;
}

export interface ListControlPoliciesResult {
  controls_enabled: boolean;
  policies: ControlPolicyView[];
}

export interface AgentControlPolicy {
  /** The agent's own policy; null when it has none. */
  policy: ControlPolicyView | null;
  /** The policy that applies to the agent now: its own, else the customer's default. */
  in_force: { id: string; revision: number; source: 'agent' | 'default' } | null;
  controls_enabled: boolean;
}

/** The answer to a create, revise, start or delete. */
export interface ControlPolicyChange {
  change: PolicyChangeKind;
  /** The policy after the change; null after a delete. */
  policy: ControlPolicyView | null;
}

export interface ControlPolicyRevision {
  revision: number;
  change: PolicyChangeKind;
  actor: string;
  /** The governance approval that let a loosening through, when there was one. */
  approval_id: string | null;
  definition: PolicyDefinition;
  created_at: string;
}

export interface ListControlPolicyRevisionsResult {
  revisions: ControlPolicyRevision[];
}

/**
 * Which rule refused an action. Never a value from the call. A call on a
 * connection the policy does not list (`connection_not_listed`, typically a
 * grant made after the policy) carries `detail.connection_id` and
 * `detail.revision_needed`: the connection stays refused until a revision
 * after `policy_revision` lists it, a loosening a person approves in a browser.
 */
export interface ControlRefusalRule {
  policy_id: string;
  policy_revision: number;
  section: PolicySection;
  rule: string;
  code: PolicyReasonCode;
  /** The policy's own side of the comparison (a limit, a list's size), never what the call carried. */
  detail?: Record<string, string | number | boolean | null>;
}

/**
 * What a connection grant's answer adds when controls are on and the agent's
 * policy lists connections without listing this one: the grant is made, and
 * the agent still cannot call the connection until a revision of the policy
 * lists it. A loosening, so a person approves it in a browser; an agent never
 * changes its own policy.
 */
export interface GrantControlPolicyNotice {
  policy_id: string;
  /** The revision the agent is held to now. */
  policy_revision: number;
  /** Whose policy it is: the agent's own, or the customer's default that applies to it. */
  source: 'agent' | 'default';
  agent_id: string;
  connection_id: string;
  action_needed: 'list_connection';
  /** The revision that lists the connection. */
  revision_needed: number;
  message: string;
}

/** A grant, as the API returns it, plus `control_policy` when its policy still has to list the connection. */
export type GrantAgentAccessResult = Record<string, unknown> & { control_policy?: GrantControlPolicyNotice };

/** One call to try against a policy. Nothing is counted, held or sent. */
export interface SimulateControlPolicyCall {
  action: ControlActionType;
  /** The target as a decision request carries it. */
  target?: Record<string, unknown>;
  amount_cents?: number | null;
  /** For `proxy.call`: the call itself, to try the connection rules against it. */
  request?: { method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; url: string; body?: unknown; query?: Record<string, string> };
  connection_id?: string;
  /** A Mission (`ms_...`): the call is tried with the recipients that Mission pinned. */
  mission_id?: string;
  /**
   * For an account's own `email.send`, `sms.send` or `call.start`: the stored message (or incoming call) the send answers,
   * as a live send's `reply_to_message`. Needs `agent_id`.
   */
  reply_to_message?: string;
}

/** Name an agent (its policy, else the default, is tried) or give a draft definition; one of the two is required. */
export interface SimulateControlPolicyInput {
  agent_id?: string;
  definition?: PolicyDefinition;
  call: SimulateControlPolicyCall;
}

export interface ControlPolicySimulation {
  verdict: 'allow' | 'review' | 'deny';
  /** The policy that was tried: the agent's own, the default, or the draft. Null when none applies. */
  policy: { id: string | null; revision: number | null; source: 'agent' | 'default' | 'draft' } | null;
  refusal: ControlRefusalRule | null;
  message: string | null;
  /** Counters that apply to this call and what is left of each (read, never counted). */
  limits: Array<{ kind: LimitPeriodKind; unit: LimitUnit; limit: number; used: number; remaining: number }>;
  controls_enabled: boolean;
  /** Whether hosted controls check this kind of action right now. */
  checked: boolean;
}

/** An action a policy held for a person. A person decides it through its governance approval; there is no decide call. */
export interface ControlReview {
  id: string;
  account_id: string;
  agent_id: string;
  policy_id: string;
  policy_revision: number;
  action_type: string;
  summary: string;
  status: ControlReviewStatus;
  approval_id: string;
  /** Where a person decides it. */
  approval_url: string;
  expires_at: string;
  created_at: string;
}

export interface ListControlReviewsQuery {
  /** `pending` (default) or `all`. */
  status?: 'pending' | 'all';
  /** 1 to 200; 50 when omitted. */
  limit?: number;
}

export interface ListControlReviewsResult {
  reviews: ControlReview[];
}

/** Changes that may need a person's approval first. */
export interface ControlPolicyGovernedOptions {
  /** The approval id from `GovernanceApprovalRequiredError`, once a person approved it. Call again with the same input. */
  governanceApprovalId?: string;
}

export interface SetControlPolicyOptions extends ControlPolicyGovernedOptions {
  /** The revision you read. Required to revise a policy; leave it out to create one. */
  expectedRevision?: number;
}

export interface DeleteControlPolicyOptions extends ControlPolicyGovernedOptions {
  /** The revision you read; the delete is refused if the policy moved on. */
  expectedRevision?: number;
}

const seg = encodeURIComponent;

/** `'default'` is the customer's default policy; anything else is an agent id. */
function scopePath(scope: string): string {
  return scope === 'default' ? '/v1/control-policies/default' : `/v1/control-policies/agents/${seg(scope)}`;
}

function governed(options?: ControlPolicyGovernedOptions): { headers: Record<string, string> } | undefined {
  return options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined;
}

/**
 * Policies for hosted controls.
 *
 * @example
 * ```ts
 * // Start from what the agent can already do, then tighten.
 * const { policy } = await stack.controlPolicies.startFromCurrentAccess('agt_...');
 * const next = { ...policy!.definition, spend: { max_per_action_cents: 500 } };
 * await stack.controlPolicies.set('agt_...', next, { expectedRevision: policy!.revision });
 * // Try a call before it happens: nothing is counted, held or sent.
 * const result = await stack.controlPolicies.simulate({
 *   agent_id: 'agt_...',
 *   call: { action: 'card.checkout', amount_cents: 900 },
 * });
 * ```
 */
export class ControlPoliciesService {
  constructor(private readonly client: HttpClient) {}

  /** Every policy of the customer, and whether controls are on. */
  async list(): Promise<ListControlPoliciesResult> {
    return this.client.get<ListControlPoliciesResult>('/v1/control-policies');
  }

  /** The customer's default policy (`'default'`, throws a 404 `StackError` when none), or an agent's own policy and the one in force for it. */
  async get(scope: 'default'): Promise<ControlPolicyView>;
  async get(scope: string): Promise<AgentControlPolicy>;
  async get(scope: string): Promise<ControlPolicyView | AgentControlPolicy> {
    return this.client.get<ControlPolicyView | AgentControlPolicy>(scopePath(scope));
  }

  /**
   * Create or revise the default (`'default'`) or an agent's policy. Leave out
   * `expectedRevision` to create; pass the revision you read to revise. A
   * loosening is a governance action. Throws `UnboundedSendRuleError` when the
   * policy allows a send that does not name who receives it: bind the recipient
   * fields, or set the rule's `recipients` to `"per_mission"` so each Mission
   * names them.
   */
  async set(scope: string, definition: PolicyDefinition, options?: SetControlPolicyOptions): Promise<ControlPolicyChange> {
    return this.client.put<ControlPolicyChange>(
      scopePath(scope),
      { definition, ...(options?.expectedRevision !== undefined ? { expected_revision: options.expectedRevision } : {}) },
      governed(options),
    );
  }

  /** Delete the default (`'default'`) or an agent's policy. Always a governance action. */
  async delete(scope: string, options?: DeleteControlPolicyOptions): Promise<ControlPolicyChange> {
    const query = options?.expectedRevision !== undefined ? `?expected_revision=${options.expectedRevision}` : '';
    return this.client.delete<ControlPolicyChange>(`${scopePath(scope)}${query}`, governed(options));
  }

  /**
   * Create a policy equal to what the agent's connection grants allow now. It
   * changes no outcome until you tighten it.
   */
  async startFromCurrentAccess(agentId: string, options?: ControlPolicyGovernedOptions): Promise<ControlPolicyChange> {
    return this.client.post<ControlPolicyChange>(
      `/v1/control-policies/agents/${seg(agentId)}/start-from-current-access`,
      undefined,
      governed(options),
    );
  }

  /**
   * Try one call against a policy. Nothing is counted, held or sent. Give the
   * call a `mission_id` to try it with what that Mission pinned.
   */
  async simulate(input: SimulateControlPolicyInput): Promise<ControlPolicySimulation> {
    return this.client.post<ControlPolicySimulation>('/v1/control-policies/simulate', input);
  }

  /** The revisions of a policy, with who made each and the approval that let a loosening through. */
  async revisions(policyId: string): Promise<ListControlPolicyRevisionsResult> {
    return this.client.get<ListControlPolicyRevisionsResult>(`/v1/control-policies/${seg(policyId)}/revisions`);
  }
}

/**
 * Actions a policy held for a person. A review is decided through its ordinary
 * governance approval (the approve page, or the chat); the agent then retries
 * the action with the `retry.ref` of its `ControlDeniedError`.
 */
export class ControlReviewsService {
  constructor(private readonly client: HttpClient) {}

  /** Held actions, newest first; pending ones unless `status: 'all'`. */
  async list(query: ListControlReviewsQuery = {}): Promise<ListControlReviewsResult> {
    return this.client.get<ListControlReviewsResult>('/v1/control-reviews', {
      status: query.status,
      limit: query.limit !== undefined ? String(query.limit) : undefined,
    });
  }

  /** One held action, with where a person decides it. */
  async get(id: string): Promise<ControlReview> {
    return this.client.get<ControlReview>(`/v1/control-reviews/${seg(id)}`);
  }
}
