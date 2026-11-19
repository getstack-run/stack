import type {
  ControlActionType,
  ControlReviewRow,
  LimitPeriodKind,
  LimitUnit,
  PaymentFacts,
} from '@stack/shared';

/**
 * What the controls ask of an agent account and its budget. The engine's
 * controls (the decision engine, the policy check, the limit resolver) know a
 * customer's policy; the account an agent belongs to, the cents and action
 * counters of its windows, and the chat that can approve a held payment belong
 * to the deployment that sells accounts. An install without accounts gives
 * the nulls below: every agent is outside an account, so no account limit
 * applies.
 */

/** The account an agent belongs to, if any. */
export interface AccountDirectory {
  accountOfAgent(operatorId: string, agentId: string): Promise<{ accountId: string; status: string } | null>;
}

/** Every agent is outside an account: the path a self-managed install takes today. */
export const NO_ACCOUNTS: AccountDirectory = {
  async accountOfAgent() {
    return null;
  },
};

/** What one reservation is checked against, resolved by the caller BEFORE it opens its transaction. */
export interface ResolvedBudgetLimits {
  /** Whether the account's own monthly budget refuses this reservation. Default true when `limits` is absent. */
  enforceAccountBudget: boolean;
  /** The most this one reservation may be, in cents (a policy's per-action ceiling). */
  maxEntryCents?: number;
  /** Windows of unit `cents` to count the reservation in. */
  rules: Array<{
    kind: LimitPeriodKind;
    limit: number;
    /** A counter of its own (one spend rule, see spendRuleScope); absent: the account's shared window. */
    scope?: string;
  }>;
  /** The Mission for a `mission` window; null/absent: the account's standing Mission, else the shared 'no_mission' bucket. */
  missionId?: string | null;
  /**
   * The spend limit of that Mission (`coverage_cap_cents`), counted in a window of its own with the reservation so
   * parallel spends cannot pass it. Absent for the account's standing Mission (the monthly budget governs it) and
   * for a Mission with no such limit.
   */
  missionSpendCapCents?: number;
  /**
   * The counter that limit is held in: `mission_spend` for the whole Mission, `mission_spend@<local date>` for a money
   * cap of one day (`coverage_cap_period: 'day'`, the date in the Mission's time zone). Absent: `mission_spend`.
   */
  missionSpendScope?: string;
}

/** Resolves the limits that apply to one reservation. */
export interface BudgetLimitResolver {
  resolve(input: {
    operatorId: string;
    accountId: string;
    action: ControlActionType | null;
    missionId: string | null;
    /** For a card purchase or a wallet payment: who is paid, so the per-merchant and per-category rules apply. */
    payment?: PaymentFacts | undefined;
  }): Promise<ResolvedBudgetLimits>;
}

/** One window a count went into, kept so handing the count back moves the same rows. */
export interface ActionLimitRef {
  accountId: string;
  kind: LimitPeriodKind;
  periodKey: string;
  amount: number;
  /** What was counted: actions (the default) or cents counted straight in, with no ledger entry (chat approvals). */
  unit?: LimitUnit;
}

export type ActionLimitResult =
  | { ok: true; refs: ActionLimitRef[] }
  | { ok: false; kind: LimitPeriodKind; limit: number; remaining: number; scope?: string };

/** What is left of one window of a limit rule, read only. */
export interface LimitUsage {
  kind: LimitPeriodKind;
  unit: LimitUnit;
  limit: number;
  used: number;
  scope?: string;
  remaining: number;
}

/** The counters of an agent account's action and cents windows. */
export interface ActionLimitCounter {
  /** What is left of each window of `rules`, read only. */
  usage(input: {
    accountId: string;
    missionId: string | null;
    rules: ReadonlyArray<{ kind: LimitPeriodKind; unit: LimitUnit; limit: number; scope?: string }>;
  }): Promise<LimitUsage[]>;
  /** Count `amount` (default 1) in every window of `rules`, or in none. */
  consumeActions(input: {
    operatorId: string;
    accountId: string;
    missionId: string | null;
    rules: ReadonlyArray<{ kind: LimitPeriodKind; limit: number; scope?: string }>;
    amount?: number;
    unit?: LimitUnit;
  }): Promise<ActionLimitResult>;
  /** Count cents straight into scoped windows, with no ledger entry. */
  consumeCents(input: {
    operatorId: string;
    accountId: string;
    rules: ReadonlyArray<{ kind: LimitPeriodKind; limit: number; scope: string }>;
    amountCents: number;
  }): Promise<ActionLimitResult>;
  /** Hand counted actions back (an action that did not run). */
  releaseActions(refs: readonly ActionLimitRef[]): Promise<void>;
}

const noAccount = (): Promise<never> =>
  Promise.reject(new Error('This install has no agent accounts, so there is no counter to read or change.'));

/** No accounts, no counters: only reached with an account id, which this install never has. */
export const NO_ACTION_LIMITS: ActionLimitCounter = {
  consumeActions: noAccount,
  consumeCents: noAccount,
  releaseActions: noAccount,
  usage: noAccount,
};

/** What the detectors do on an agent account's traffic, which follows its owner's controls. */
export interface AccountDetectorPosture {
  /** The detector mode: `enforced` refuses on a critical verdict, `standard` only records. */
  mode: 'enforced' | 'standard';
  /** The paid L3 classifier does not run. */
  skipL3: boolean;
  /**
   * Whether a flagged result of each severity is withheld from the agent; otherwise it is delivered with its flag. With
   * controls on it is the customer's own setting (withhold for both by default); with controls off, false for both.
   */
  withhold: Readonly<{ warning: boolean; critical: boolean }>;
}

/** Whether a flagged result of this severity is withheld under this posture. */
export function withholdsFlag(posture: Pick<AccountDetectorPosture, 'withhold'>, severity: 'warning' | 'critical'): boolean {
  return posture.withhold[severity];
}

/** The detector posture of an agent, by whether it belongs to an account. */
export interface AccountDetection {
  /** Null for an agent outside an account: the caller keeps the Passport's own mode. */
  forAgent(operatorId: string, agentId: string, action?: ControlActionType | null): Promise<AccountDetectorPosture | null>;
  forOperator(operatorId: string, action?: ControlActionType | null): Promise<AccountDetectorPosture>;
}

/** No accounts: every agent is outside one, and what is recorded for an operator is only flagged. */
export const NO_ACCOUNT_DETECTION: AccountDetection = {
  async forAgent() {
    return null;
  },
  async forOperator() {
    return { mode: 'standard', skipL3: true, withhold: { warning: false, critical: false } };
  },
};

/** Offers a held payment to the owner's bound chat identities when their own limits allow it. */
export interface HeldPaymentChat {
  offer(review: ControlReviewRow): Promise<{
    sent: number;
    skipped?: 'off' | 'not_a_payment' | 'over_limit' | 'day_used' | 'not_open';
  }>;
}

/**
 * What the engine does when an agent is deleted: an agent with an open account is
 * deleted by closing the account (one transaction that also ends its Mission, grants
 * and pieces), so the route asks first. An install has no accounts, so the answer is
 * always "none" and the delete is a plain delete.
 */
export interface AgentAccountLifecycle {
  findOpenAccountByAgent(agentId: string): Promise<{ id: string; operator_id: string } | null>;
  close(input: { operatorId: string; accountId: string }): Promise<{ transitioned: boolean }>;
}

export const NO_ACCOUNT_LIFECYCLE: AgentAccountLifecycle = {
  async findOpenAccountByAgent() {
    return null;
  },
  async close() {
    throw new Error('This install has no agent accounts to close.');
  },
};
