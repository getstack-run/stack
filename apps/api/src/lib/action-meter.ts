import type { FastifyRequest } from 'fastify';
import type { IntentClaim } from '@stack/shared';
import type { EntitlementAccount } from '@stack/vault';

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * Set when this request counted a recorded action. The end-of-request hook
     * (`registerMeterRefund`) runs it on a denial that did not use the action,
     * so a refused call does not burn allowance.
     */
    meterRollback?: () => Promise<void>;
    /**
     * Set by the error handler when the request failed with an error that says
     * STACK could not serve it (`StackError.stackSide`), so a counted action is
     * handed back even though the status is a 5xx.
     */
    stackSideUnavailable?: boolean;
    /**
     * Set by decideControl when the customer's decider refused the action, gave
     * no usable answer, or could not be paid: the action never ran, so a counted
     * action is handed back whatever the status (a refused action is never charged).
     */
    refundAction?: boolean;
    /**
     * What an allowed action's control decision left open (a counted action, a
     * reserved approval, a lease on concurrency). The end-of-request hook of
     * middleware/control-settle.ts tells each how the action ended.
     */
    controlSettle?: Array<(outcome: { ok: boolean; handedBack: boolean }) => Promise<void>>;
    /** Finalize a durable idempotent meter immediately before work dispatch. */
    meterCommit?: () => Promise<void>;
    /**
     * Set when a request reserved an approval at the gate (approved ->
     * consuming). The route clears it on successful consume; the end-of-request
     * hook releases whatever is left, so any failure path after admit -
     * including a thrown gate refusal - restores the approval for retry. Mirror
     * of `meterRollback`. See apps/api/src/start.ts.
     */
    approvalToRelease?: () => Promise<void>;
    /**
     * Set when a route started the prompt-injection scan early (enforced mode)
     * and has not yet acted on it. The route clears it once the verdict is
     * used; the end-of-request hook aborts whatever is left, so a request
     * refused by a later gate cancels its in-flight L3 call and releases its
     * budget hold. See apps/api/src/start.ts.
     */
    pendingInputScanAbort?: () => void;
  }
}

/**
 * The action meter, as the engine sees it. Every agent action is counted once;
 * what counting means is the deployment's business. STACK's hosted product
 * prices each action by band from prepaid credit and refuses an operator
 * without a plan; an install that runs on the contract plan counts nothing and
 * refuses nothing, which is `NO_METER`.
 *
 * The engine calls these through `services.actionMeter` (and the facade in
 * `middleware/meter.ts`), never the hosted implementation.
 */

/** When the meter refuses, the intent that was attempted, so the refusal is recorded as a signed denial. */
export interface MeterDenialContext {
  passportJti: string;
  attemptedIntent: IntentClaim;
}

/** Undoes one counted action that was refused downstream. */
export interface MeterRollback {
  (): Promise<void>;
}

/** A retried operation counts once: the key names the logical operation. */
export interface IdempotentMeterOptions {
  /** Stable logical-operation identity. It is hashed before it reaches the counter. */
  key: string;
  /** The persisted time of the operation keeps a retry in the original month. */
  accountingDate?: Date;
  onCommit: (commit: () => Promise<void>) => void;
}

/** What the meter would do for one more action, without counting it. */
export interface MeterPeek {
  used: number;
  cap: number;
  walletBalanceCents: number;
  overagePriceCents: number;
  wouldDeny: boolean;
}

export interface RecordCheckResult {
  checksThisMonth: number;
  centsCharged: number;
}

/** What a billing account has used of the actions its plan includes in a month. */
export interface ActionPool {
  /** The actions the plan includes in the month; `Infinity` when it names no limit. */
  limit: number;
  used: number;
}

export interface ActionMeter {
  /** One recorded action of the request's caller. Registers the rollback on the request. */
  meterAction(
    request: FastifyRequest,
    denial?: MeterDenialContext,
    idempotencyKey?: string,
    actingAgentId?: string | null,
    /** Whose action it is when the caller acts for another operator (a partner for one of its accounts); default: the request's. */
    operatorId?: string,
  ): Promise<void>;
  /** One recorded action for an operator the route resolved itself (a public receiver, a workload consumer). */
  enforce(
    operatorId: string,
    meter: 'action',
    denial?: MeterDenialContext,
    onCounted?: (rollback: MeterRollback) => void,
    idempotency?: IdempotentMeterOptions,
  ): Promise<void>;
  /** What `enforce` would do for one hypothetical action. */
  peek(operatorId: string, meter: 'action'): Promise<MeterPeek>;
  /** Hosted control checks, `count` of them, charged once per batch decided. */
  recordCheck(operatorId: string, count: number): Promise<RecordCheckResult>;
  /** Decisions the customer's own control server made, `count` of them, charged once per batch decided. */
  recordDecision(operatorId: string, count: number): Promise<RecordCheckResult>;
  /** Issuing and refreshing an account agent's passport is upkeep, not an action. */
  passportUpkeep(request: FastifyRequest, agentId: string): Promise<void>;
  /** The recorded actions of the account's month so far, as the usage readouts show them. */
  pool(account: EntitlementAccount, now: Date): Promise<ActionPool>;
}

/** The meter of an install with no plans: nothing is counted, nothing is refused, nothing is charged. */
export const NO_METER: ActionMeter = {
  async meterAction() {},
  async enforce() {},
  async peek() {
    return { used: 0, cap: Infinity, walletBalanceCents: 0, overagePriceCents: 0, wouldDeny: false };
  },
  async recordCheck() {
    return { checksThisMonth: 0, centsCharged: 0 };
  },
  async recordDecision() {
    return { checksThisMonth: 0, centsCharged: 0 };
  },
  async passportUpkeep() {},
  async pool() {
    return { limit: Infinity, used: 0 };
  },
};

/**
 * The deployment's own operator: STACK dogfoods itself, so what it does is never
 * counted or charged and must never be refusable. The id is an inert constant
 * here; a deployment that exempts more operators does so in its own meter.
 */
export function isSystemOperator(operatorId: string): boolean {
  return operatorId === 'op_stack_system' || operatorId === (process.env['STACK_SYSTEM_OPERATOR_ID'] || 'op_stack_system');
}

/**
 * Whether an action that was counted (or that a decision left something open
 * for) never ran, from the final response: it is handed back.
 *
 * The meter fires before the work, so an action counted and then refused
 * downstream for a client mistake (bad body, unknown resource, rate limit)
 * spent allowance on nothing and is refunded.
 *
 * Not refunded:
 * - 403 is a POLICY denial: the caller made a real, evaluated attempt that ran
 *   the scope check, the wall, the detector chain and the mission gate, and
 *   was refused. Refunding it made brute-force probing free - an agent could
 *   map the entire policy at no quota cost, generating audit rows, security
 *   events and L3 spend the operator pays for while the meter never moves
 *   (the threat model, cell meter.denial-loop-is-free).
 * - 402 never counted: the meter undoes its own increment before it throws.
 * - 5xx, because the work may have partially run, except a 503 the error
 *   handler marked as unavailable on the deployment's side (`StackError.stackSide`:
 *   the deployment itself could not serve the request and nothing ran, a
 *   dependency it relies on or its own limits), which refuses before any work
 *   and is the deployment's doing, not the customer's.
 *
 * Refunded whatever the status: an action the customer's own decider refused
 * (or could not answer for), which `decideControl` marks `refundAction`. It
 * never ran, and a refused action is never charged; the policy-denial rule
 * above is about STACK's own gates, and the customer already pays for their
 * own refusals through the check price, not through the action price.
 *
 * The one rule: the meter's rollback and the control decision's settle hooks
 * (an approval given back, a lease returned) both read it.
 */
export function actionHandedBack(status: number, stackSideUnavailable: boolean, refundAction = false): boolean {
  if (refundAction && status >= 400) return true;
  if (status === 503 && stackSideUnavailable) return true;
  if (status < 400 || status >= 500) return false;
  return status !== 402 && status !== 403;
}
