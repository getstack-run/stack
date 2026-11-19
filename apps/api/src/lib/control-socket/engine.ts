// The control decision engine: one question per checked action, answered by the
// customer's decider.
//
//   none    nobody asks anything.
//   hosted  STACK's own checks, in process. The price is per action checked: a
//           check that ran is one billable check whether it allowed or denied.
//           The action itself is never charged when it is refused. STACK-side
//           failures (no verdict) are never charged. The check is charged after
//           the decision and before the action, so an allowed action that STACK
//           then refuses (the do-not-contact list, credit) still leaves its check
//           charged. A denial is never masked by a check that cannot be paid:
//           the agent is still refused, and the decision row records the check
//           as uncharged for the meter to settle.
//   remote  the customer's own server. Charged per decision it made, at a lower price than a hosted check: an answer
//           (allow or deny) is one decision; no usable answer (a timeout, an unreachable or invalid server) is none
//           and is never charged. Paid after the answer, as a hosted check is.
//
// Which kinds are checked is the customer's choice; an unchecked kind is not
// asked and not counted. A decision row is written for every checked action
// (slim for an allow, and off the action's path; with the request for a refusal),
// and a refusal also leaves an audit row naming its decision, which the
// customer's events stream carries.

import {
  ids,
  sha256,
  type ControlActionType,
  type ControlDecider,
  type ControlDecisionRequest,
  type ControlUnavailableCause,
} from '@stack/shared';
import {
  ControlPosture,
  type AuditContext,
  type AuditService,
  type ControlSocketRepository,
  type ControlSocketService,
  type EntitlementResolver,
} from '@stack/vault';
import { CONTROL_UNANSWERED_CAUSES, safeErrorSummary, type PolicyRefusalEvidence } from '@stack/shared';
import { buildDecisionRequest } from './request-builder.js';
import { runSettle } from './settle.js';
import type { Decider, DecisionContext, DecisionResult, SettleHook } from './types.js';

export interface AskInput {
  operatorId: string;
  action: ControlActionType;
  accountId: string | null;
  agent: { id: string; passportJti: string | null; missionId: string | null } | null;
  actorKind: 'agent' | 'owner' | 'member';
  target: Record<string, unknown>;
  amount: ControlDecisionRequest['amount'];
  purpose: string | null;
  retryRef: string | null;
  audit: AuditContext;
  privileged?: Readonly<Record<string, unknown>>;
}

export type Asked =
  | { asked: false }
  | {
      asked: true;
      decisionId: string;
      decider: ControlDecider;
      verdict: 'allow' | 'deny' | 'unavailable';
      reason: { code: string; message: string | null } | null;
      retry: { ref: string; after_seconds?: number } | null;
      cause: ControlUnavailableCause | null;
      latencyMs: number;
      charged: boolean;
      /** Which rule of a hosted policy refused, when one did. */
      evidence: PolicyRefusalEvidence | null;
      /** What an allowed action leaves open; the caller runs these once the outcome is known. */
      settle: SettleHook[];
    };

export interface ControlDecisionEngineDeps {
  sockets: Pick<ControlSocketService, 'runtime'>;
  repo: Pick<ControlSocketRepository, 'insertDecision'>;
  controls: Pick<EntitlementResolver, 'controlsEnabled'>;
  /**
   * The one reading of who decides and which kinds are checked, shared with the
   * checks that run at their own call site. Built from `sockets` and `controls`
   * when not given.
   */
  posture?: Pick<ControlPosture, 'decision'>;
  audit: Pick<AuditService, 'write'>;
  none: Decider;
  hosted: Decider;
  remote: Decider;
  /** One hosted check, charged at the check price. Throws (402, a freeze) when it cannot be paid. */
  charge: (operatorId: string) => Promise<void>;
  /** One decision the customer's own server made, charged at the own-server price. Throws (402, a freeze) when it cannot be paid. */
  chargeDecision: (operatorId: string) => Promise<void>;
  now?: () => Date;
  clock?: () => number;
}

/** A hosted decision may not take longer than this either. */
const HOSTED_DEADLINE_MS = 2_000;

/**
 * Action kinds whose hosted decision is not a billable check. Opening an account
 * has no action price and no meter (an account opens with no charge and a
 * customer with no credit can still open one); it is asked so a policy or the
 * customer's own server can refuse it, but it is not counted as a check.
 */
const UNBILLED_HOSTED_ACTIONS: ReadonlySet<ControlActionType> = new Set<ControlActionType>(['account.open']);

export class ControlDecisionEngine {
  private readonly now: () => Date;
  private readonly clock: () => number;
  private readonly posture: Pick<ControlPosture, 'decision'>;

  constructor(private readonly deps: ControlDecisionEngineDeps) {
    this.now = deps.now ?? (() => new Date());
    this.clock = deps.clock ?? (() => performance.now());
    this.posture = deps.posture ?? new ControlPosture({ sockets: deps.sockets, controls: deps.controls });
  }

  async ask(input: AskInput): Promise<Asked> {
    const { decider: kind, checked, socket } = await this.posture.decision(input.operatorId, input.action);
    if (kind === 'none' || !checked) return { asked: false };

    const decider = kind === 'remote' ? this.deps.remote : this.deps.hosted;
    const decisionId = ids.controlDecision();
    const deadlineMs = kind === 'remote' ? socket.timeoutMs : HOSTED_DEADLINE_MS;
    const { request, body } = buildDecisionRequest({
      decisionId,
      now: this.now(),
      deadlineMs,
      test: false,
      operatorId: input.operatorId,
      socketId: socket.socketId ?? 'csk_unset',
      accountId: input.accountId,
      agent: input.agent,
      actorKind: input.actorKind,
      action: input.action,
      target: input.target,
      amount: input.amount,
      purpose: input.purpose,
      retryRef: input.retryRef,
    });

    const started = this.clock();
    let result: DecisionResult;
    try {
      result = kind === 'hosted'
        ? await this.decideHosted(decider, { request, body, operatorId: input.operatorId, socket, ...(input.privileged ? { privileged: input.privileged } : {}) })
        : await decider.decide({ request, body, operatorId: input.operatorId, socket });
    } catch {
      // A decider that throws is not an answer. Nothing is allowed on its say-so.
      result = { verdict: 'unavailable', cause: kind === 'hosted' ? 'hosted_failure' : 'unreachable' };
    }
    const latencyMs = Math.max(0, Math.round(this.clock() - started));

    // The customer's own server did not answer in time and the customer chose to let the action through: it is allowed, and the
    // decision row says why (the cause stays on it). Only an answer that never came counts: a signature that failed, an answer that
    // did not parse, an address that is blocked, a server not verified or paused are refused whatever the setting says.
    let unansweredCause: ControlUnavailableCause | null = null;
    if (kind === 'remote' && result.verdict === 'unavailable' && socket.onUnavailable === 'allow' && CONTROL_UNANSWERED_CAUSES.has(result.cause)) {
      unansweredCause = result.cause;
      result = { verdict: 'allow', settle: [] };
    }

    // A hosted check that gave a verdict ran, so it is one check, charged whether it
    // allowed or denied (the price is per action checked); one that failed on STACK's
    // side did not run and costs nothing. A decision the customer's own server made is
    // charged the same way at its own price, and one it did not answer is not. Opening
    // an account is neither.
    const settle = result.verdict === 'allow' ? (result.settle ?? []) : [];
    let charged = false;
    if ((kind === 'hosted' || kind === 'remote') && result.verdict !== 'unavailable' && unansweredCause === null && !UNBILLED_HOSTED_ACTIONS.has(input.action)) {
      try {
        await (kind === 'hosted' ? this.deps.charge(input.operatorId) : this.deps.chargeDecision(input.operatorId));
        charged = true;
      } catch (error) {
        if (result.verdict === 'allow') {
          // The check could not be paid, so the action does not run: whatever the
          // decision left open (a counted action, a reserved approval, a lease) is handed back.
          await runSettle(settle, { ok: false, handedBack: true });
          throw error;
        }
        // A refusal stands. The agent is told CONTROL_DENIED, not a payment error that would hide
        // it; the row below says the check ran and was not charged, for the meter to settle.
        console.error('[CONTROL] a refusing check could not be charged', safeErrorSummary(error));
      }
    }

    const reason = result.verdict === 'deny' ? result.reason : null;
    const evidence = result.verdict === 'deny' ? (result.evidence ?? null) : null;
    const row = {
      id: decisionId,
      operator_id: input.operatorId,
      socket_id: socket.socketId,
      account_id: input.accountId,
      agent_id: input.agent?.id ?? null,
      action_type: input.action,
      decider: kind,
      verdict: result.verdict,
      reason_code: reason?.code ?? null,
      cause: result.verdict === 'unavailable' ? result.cause : unansweredCause,
      latency_ms: latencyMs,
      charged,
      request_digest: request.request_digest,
      request: result.verdict === 'allow' ? null : (request as unknown as Record<string, unknown>),
      evidence: evidence as unknown as Record<string, unknown> | null,
    };
    if (result.verdict === 'allow') {
      // Off the action's path: a slim row for the record, never waited on.
      void this.deps.repo.insertDecision(row).catch((error: unknown) => {
        console.error('[CONTROL] decision row not written', safeErrorSummary(error));
      });
    } else {
      await this.deps.repo.insertDecision(row).catch((error: unknown) => {
        console.error('[CONTROL] decision row not written', safeErrorSummary(error));
      });
      await this.auditRefusal(input, row.id, request.request_digest, result, evidence);
    }

    return {
      asked: true,
      decisionId,
      decider: kind,
      verdict: result.verdict,
      reason: result.verdict === 'deny' ? { code: result.reason.code, message: result.reason.message } : null,
      retry: result.verdict === 'deny' ? (result.retry ?? null) : null,
      cause: result.verdict === 'unavailable' ? result.cause : null,
      latencyMs,
      charged,
      evidence,
      settle,
    };
  }

  /**
   * A hosted decision under its deadline. A check that is still running when the
   * deadline passes is told to stop (`signal`), and whatever it still takes or
   * leaves open is handed back when it ends: the caller has already been told
   * "unavailable", so the action never runs and nothing may stay counted,
   * reserved or leased on its behalf.
   */
  private async decideHosted(decider: Decider, context: DecisionContext): Promise<DecisionResult> {
    const abort = new AbortController();
    const work = decider.decide({ ...context, signal: abort.signal });
    try {
      return await withDeadline(work, HOSTED_DEADLINE_MS);
    } catch (error) {
      if (error instanceof DecisionDeadlineError) {
        abort.abort();
        void work.then(
          (late) => (late.verdict === 'allow' ? runSettle(late.settle ?? [], { ok: false, handedBack: true }) : undefined),
          () => undefined,
        );
      }
      throw error;
    }
  }

  private async auditRefusal(
    input: AskInput,
    decisionId: string,
    digest: string,
    result: Exclude<DecisionResult, { verdict: 'allow' }>,
    evidence: PolicyRefusalEvidence | null,
  ): Promise<void> {
    const code = result.verdict === 'deny' ? result.reason.code : result.cause;
    try {
      await this.deps.audit.write({
        ctx: input.audit,
        layer: 'system',
        action: `control.decision.${result.verdict}`,
        outcome: 'blocked',
        payload_hash: sha256(`${digest}:${result.verdict}:${code}`),
        // A refusal by a hosted policy names the rule on the audit row itself (the policy's side only), so the record answers "which rule".
        error: {
          code: result.verdict === 'deny' ? 'CONTROL_DENIED' : 'CONTROL_SOCKET_UNAVAILABLE',
          message: evidence ? `${code} ${evidence.section}/${evidence.rule} ${evidence.policy_id}@${evidence.policy_revision}` : code,
        },
        event_details: {
          decision_id: decisionId,
          ...(input.accountId ? { account_id: input.accountId } : {}),
          ...(evidence
            ? {
                refusal: {
                  policy_id: evidence.policy_id,
                  policy_revision: evidence.policy_revision,
                  section: evidence.section,
                  rule: evidence.rule,
                  code: evidence.code,
                },
              }
            : {}),
        },
      });
    } catch (error) {
      // The refusal stands; only its audit row is missing, and the decision row has it.
      console.error('[CONTROL] refusal audit row not written', safeErrorSummary(error));
    }
  }
}

class DecisionDeadlineError extends Error {
  constructor() {
    super('control decision deadline');
  }
}

function withDeadline<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new DecisionDeadlineError()), ms);
  });
  return Promise.race([work, deadline]).finally(() => clearTimeout(timer));
}
