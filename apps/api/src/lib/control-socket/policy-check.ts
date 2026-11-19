// STACK's hosted policy, as the one hosted check.
//
// For every checked action of an agent whose customer has hosted controls on,
// this finds the policy in force (the agent's own, else the customer's
// default) and tries the action against it. It only ever narrows: the action
// has already passed the connection grant, the Passport scope and the scope
// wall, and the best this check can say is "the policy does not object".
//
// Order, so that nothing is counted for an action that is refused:
//
//   1. the policy's rules (pure; a refusal ends it here)
//   2. a rule that holds the action for a person: no approval yet means a
//      refusal that carries `retry.ref`; an approved one is reserved for this
//      operation (the intent approval gate's own reserve)
//   3. the policy's action-count limits (one conditional update per window)
//   4. the policy's concurrency limit (an atomic Redis counter with a lease)
//
// A step that fails undoes the steps before it. Whatever an allowed action
// leaves open (a counted action, a reserved approval, a lease) is returned in
// `settle` and told how the action ended.

import {
  POLICY_REASON_CODES,
  POLICY_RECIPIENTS_PER_MISSION,
  canonicalize,
  evaluatePolicy,
  limitsOf,
  perMissionRulesOnly,
  policyUsesPerMission,
  readRecipientPins,
  redactRequestPath,
  refusalEvidence,
  safeErrorSummary,
  sha256,
  type ControlActionType,
  type NormalizedRequest,
  type PolicyCall,
  type PolicyLimit,
  type PolicyReasonCode,
  type PolicyRefusalEvidence,
} from '@stack/shared';
import type {
  ActionLimitCounter,
  ActionLimitRef,
  ControlPolicyService,
  ControlReviewService,
  EffectivePolicy,
  HeldPaymentChat,
  MissionRecipientPinReader,
  PassportLineageReader,
} from '@stack/vault';
import type { HostedCheck } from './deciders.js';
import type { ActionOutcome, DecisionContext, DecisionResult, SettleHook } from './types.js';
import type { ConcurrencyLimiter } from '../control-policy/concurrency-limiter.js';

export interface PolicyCheckDeps {
  policies: Pick<ControlPolicyService, 'effective'>;
  reviews: Pick<ControlReviewService, 'open' | 'reserve' | 'consume' | 'release'>;
  limits: Pick<ActionLimitCounter, 'consumeActions' | 'releaseActions'>;
  concurrency: Pick<ConcurrencyLimiter, 'acquire' | 'release'>;
  /** Reads what a Mission pinned, for the rules that leave recipients to each Mission. Absent: no Mission pins anyone. */
  missions?: Pick<MissionRecipientPinReader, 'read'> | undefined;
  /** Reads the agents that delegated a Passport, so a child is held to the per-job rules of each of them. Absent: only the Mission's agent. */
  lineage?: Pick<PassportLineageReader, 'agentsAbove'> | undefined;
  /**
   * Asks the account's bound chat identities about a held payment, when the
   * customer's own limits allow it to be approved from a chat. Never awaited:
   * a slow chat provider must not slow a decision, and a failure here leaves
   * the approval page as the way to decide.
   */
  chat?: HeldPaymentChat | null | undefined;
  now?: () => Date;
}

/** The account's own sends: the actions that can carry the pin of a message they answer. */
const ACCOUNT_SEND_ACTIONS: ReadonlySet<ControlActionType> = new Set<ControlActionType>(['email.send', 'sms.send', 'call.start']);

/** How long an agent is told to wait before asking again about a held action. */
const REVIEW_RETRY_AFTER_SECONDS = 30;

/** A held card purchase or wallet payment with a known USD amount: the only kind of held action a chat app may approve. */
function heldPayment(call: PolicyCall): { surface: 'card' | 'wallet'; amountCents: number } | null {
  if (call.amountCents === null) return null;
  if (call.action === 'card.checkout') return { surface: 'card', amountCents: call.amountCents };
  if (call.action === 'wallet.payment') return { surface: 'wallet', amountCents: call.amountCents };
  return null;
}

export function policyRef(policy: Pick<EffectivePolicy, 'id' | 'revision'>): string {
  return `${policy.id}@${policy.revision}`;
}

/** What the decision request says the action costs at most, in USD cents, or null when it names none. */
function amountCentsOf(context: DecisionContext): number | null {
  return context.request.amount?.max_cents ?? null;
}

function privilegedRequest(context: DecisionContext): NormalizedRequest | null {
  const value = context.privileged?.['request'];
  return value && typeof value === 'object' ? (value as NormalizedRequest) : null;
}

/** The exact call a person approves: who, what, where, how much and, for a proxy call, the whole request. Never stored. */
export function callDigestOf(context: DecisionContext, call: PolicyCall, agentId: string): string {
  const request = call.request;
  return sha256(
    canonicalize({
      agent: agentId,
      action: call.action,
      target: call.target,
      amount_cents: call.amountCents,
      request: request
        ? { method: request.method, host: request.url.host, path: request.url.pathname, query: request.query, body: request.body }
        : null,
      account: context.request.account?.id ?? null,
    }),
  );
}

/** One line a person reads on the approval: what the agent wants to do and which rule holds it. No call content. */
export function describeHeldCall(call: PolicyCall, rule: { section: string; id: string }): string {
  const t = call.target;
  const text = (key: string) => (typeof t[key] === 'string' ? (t[key] as string) : null);
  let what: string = call.action;
  switch (call.action) {
    case 'proxy.call':
      what = `${text('method') ?? 'call'} ${text('host') ?? 'a service'}${text('path') ? redactRequestPath(text('path')!) : ''} on connection ${text('connection_id') ?? 'unknown'}`;
      break;
    case 'card.checkout':
      what = `pay ${text('merchant_origin') ?? 'a merchant'} by card`;
      break;
    case 'wallet.payment':
      what = `pay ${text('payee') ?? 'a payee'} from the wallet`;
      break;
    case 'email.send':
      what = 'send an email';
      break;
    case 'sms.send':
      what = 'send a text';
      break;
    case 'telegram.send':
      what = 'send a Telegram message';
      break;
    case 'call.start':
      what = 'place a call';
      break;
    case 'call.answer':
      what = 'answer a call';
      break;
    case 'meeting.join':
      what = 'join a meeting';
      break;
    default:
      break;
  }
  const amount = call.amountCents === null ? '' : ` (up to $${(call.amountCents / 100).toFixed(2)})`;
  return `Your agent wants to ${what}${amount}. Held by ${rule.section}: ${rule.id}.`;
}

export class PolicyHostedCheck implements HostedCheck {
  readonly name = 'policy';

  constructor(private readonly deps: PolicyCheckDeps) {}

  appliesTo(action: ControlActionType | 'test'): boolean {
    return action !== 'test';
  }

  async evaluate(context: DecisionContext): Promise<DecisionResult> {
    const { request } = context;
    const action = request.action.type as ControlActionType;
    const agentId = request.agent?.id ?? null;
    const effective = await this.deps.policies.effective(context.operatorId, agentId);

    // What the Mission pinned and whose it is, for the calls a rule that leaves recipients to each Mission can judge (a
    // call through the proxy). A Mission that cannot be read throws, and the engine answers "hosted controls could not
    // decide": the send is refused, never allowed unpinned.
    const missionId = request.agent?.mission_id ?? null;
    const missionInfo =
      action === 'proxy.call' && missionId !== null && agentId !== null && this.deps.missions
        ? await this.deps.missions.read(context.operatorId, missionId)
        : null;
    // An account's own email, text or call that answers a stored message carries who wrote it (the route read the stored
    // message; in process only, never sent to a customer's own server). Without it the Mission's own pins (the ones the
    // owner gave it) are what a per-job rule allows: a forward or a new send to someone the Mission names.
    const answeredPins = ACCOUNT_SEND_ACTIONS.has(action) ? readRecipientPins(context.privileged?.['recipient_pins']) : null;
    const sendPins = answeredPins
      ?? (ACCOUNT_SEND_ACTIONS.has(action) && missionId !== null && this.deps.missions
        && effective && Object.values(effective.definition.recipients).includes(POLICY_RECIPIENTS_PER_MISSION)
        ? (await this.deps.missions.read(context.operatorId, missionId)).pins
        : null);
    const call: PolicyCall = {
      action,
      target: request.target,
      amountCents: amountCentsOf(context),
      request: privilegedRequest(context),
      ...(missionInfo ? { mission: { recipientPins: missionInfo.pins } } : sendPins ? { mission: { recipientPins: sendPins } } : {}),
    };

    // A delegated Passport runs in the Mission of the agent that delegated, so the per-job rules of every agent above it (the
    // chain of Passports it was delegated through) and of the agent the Mission was opened for, which can be none, bind it as
    // well as its own policy: a child cannot send further than its parent's job named.
    if (missionInfo && agentId !== null) {
      const above =
        this.deps.lineage && request.agent?.passport_jti
          ? await this.deps.lineage.agentsAbove(context.operatorId, request.agent.passport_jti)
          : [];
      const binding = new Set<string>(above);
      if (missionInfo.assignedAgentId) binding.add(missionInfo.assignedAgentId);
      binding.delete(agentId);
      for (const ownerId of binding) {
        const owner = await this.deps.policies.effective(context.operatorId, ownerId);
        if (owner && policyUsesPerMission(owner.definition)) {
          const inherited = evaluatePolicy(perMissionRulesOnly(owner.definition), call);
          if (inherited.verdict === 'deny') return deny(owner, inherited, policyRef(owner));
        }
      }
    }

    if (!effective) return { verdict: 'allow' };
    const verdict = evaluatePolicy(effective.definition, call);
    const ref = policyRef(effective);

    if (verdict.verdict === 'deny') {
      return deny(effective, verdict, ref);
    }

    const settle: SettleHook[] = [];
    const undo = async () => runUndo(settle);

    try {
      // A held action: no approval yet is a refusal that names the review; an approved one is reserved for this operation.
      if (verdict.verdict === 'review') {
        if (!agentId) {
          return deny(effective, { ...verdict, verdict: 'deny', code: 'policy_unevaluable', message: 'This action is held for approval, and no agent is acting, so it cannot be approved.' }, ref);
        }
        const digest = callDigestOf(context, call, agentId);
        const given = request.retry_ref;
        if (given) {
          const reserved = await this.deps.reviews.reserve({
            operatorId: context.operatorId,
            ref: given,
            agentId,
            callDigest: digest,
            operation: request.decision_id,
          });
          if (reserved.state === 'reserved') {
            const { review, ownerHash } = reserved;
            settle.push(async (outcome) => {
              if (outcome.ok) await this.deps.reviews.consume(review.id, ownerHash);
              else await this.deps.reviews.release(review.id, ownerHash);
            });
          } else if (reserved.state === 'pending' || reserved.state === 'in_use') {
            return deny(effective, { ...verdict, verdict: 'deny', code: 'review_pending', message: 'This action is waiting for a person to approve it.' }, ref, { ref: given, after_seconds: REVIEW_RETRY_AFTER_SECONDS });
          } else if (reserved.state === 'rejected') {
            return deny(effective, { ...verdict, verdict: 'deny', code: 'review_rejected', message: 'A person declined this action.' }, ref);
          }
          // Spent, lapsed, unknown or for another call: the held action is held again, with a fresh review below.
        }
        if (settle.length === 0) {
          const opened = await this.deps.reviews.open({
            operatorId: context.operatorId,
            accountId: request.account?.id ?? '',
            agentId,
            policy: { id: effective.id, revision: effective.revision },
            rule: { section: verdict.section, id: verdict.rule },
            action,
            callDigest: digest,
            summary: describeHeldCall(call, { section: verdict.section, id: verdict.rule }),
            ...(heldPayment(call) ? { payment: heldPayment(call)! } : {}),
          });
          if (opened.created && this.deps.chat) {
            void this.deps.chat.offer(opened.review).catch((error: unknown) => {
              console.error('[CONTROL] a held payment could not be offered to a chat', safeErrorSummary(error));
            });
          }
          return deny(effective, verdict, ref, { ref: opened.review.id, after_seconds: REVIEW_RETRY_AFTER_SECONDS });
        }
      }

      const accountId = request.account?.id ?? null;
      const missionId = request.agent?.mission_id ?? null;

      // Action-count limits: one conditional update per window, all or none.
      const actionRules = limitsOf(effective.definition, 'actions');
      if (actionRules.length > 0 && accountId) {
        stopIfAbandoned(context);
        const counted = await this.deps.limits.consumeActions({
          operatorId: context.operatorId,
          accountId,
          missionId,
          rules: actionRules.map(({ kind, limit }: PolicyLimit) => ({ kind, limit })),
        });
        if (!counted.ok) {
          await undo();
          const evidence = refusalEvidence(effective, {
            verdict: 'deny',
            section: 'spend',
            rule: `limits.${counted.kind}.actions`,
            code: 'limit_reached',
            message: `Your controls allow ${counted.limit} actions per ${counted.kind === 'mission' ? 'Mission' : counted.kind}, and this agent has reached it.`,
            detail: { limit: counted.limit, remaining: counted.remaining },
          });
          return denyWith(evidence, 'Your controls limit how many actions this agent may take in a ' + (counted.kind === 'mission' ? 'Mission' : counted.kind) + ', and it has reached the limit.', ref);
        }
        const refs: readonly ActionLimitRef[] = counted.refs;
        settle.push(async (outcome) => {
          // A counted action that never ran is handed back, as the meter hands it back.
          if (outcome.handedBack) await this.deps.limits.releaseActions(refs);
        });
        stopIfAbandoned(context);
      }

      // Concurrency: an atomic counter with a lease, so a crashed machine never holds a slot.
      const cap = effective.definition.spend.max_concurrent;
      if (cap !== undefined && agentId) {
        stopIfAbandoned(context);
        const lease = await this.deps.concurrency.acquire({ operatorId: context.operatorId, agentId, limit: cap });
        if (!lease) {
          await undo();
          const evidence = refusalEvidence(effective, {
            verdict: 'deny',
            section: 'spend',
            rule: 'max_concurrent',
            code: 'concurrency_reached',
            message: 'This agent already has as many actions running as your controls allow.',
            detail: { limit: cap },
          });
          return denyWith(evidence, 'This agent already has as many actions running at once as your controls allow. Retry when one finishes.', ref);
        }
        settle.push(async () => this.deps.concurrency.release({ operatorId: context.operatorId, agentId, leaseId: lease.leaseId }));
        stopIfAbandoned(context);
      }
    } catch (error) {
      // Whatever was done so far is undone; the engine turns a throw into "hosted controls could not decide".
      await undo().catch(() => undefined);
      console.error('[CONTROL] hosted policy check failed', safeErrorSummary(error));
      throw error;
    }

    return { verdict: 'allow', policyRef: ref, ...(settle.length > 0 ? { settle } : {}) };
  }
}

/**
 * The engine gave up on this decision (its deadline passed) and has told the caller
 * "unavailable": stop before the next side effect. Thrown inside the check's own
 * try, so what was already taken is undone.
 */
function stopIfAbandoned(context: DecisionContext): void {
  if (context.signal?.aborted) throw new Error('control decision abandoned after its deadline');
}

/** Hand back everything an allowed-so-far action had taken, as for an action that never ran. */
async function runUndo(settle: SettleHook[]): Promise<void> {
  const outcome: ActionOutcome = { ok: false, handedBack: true };
  for (const hook of settle.splice(0)) {
    try {
      await hook(outcome);
    } catch (error) {
      console.error('[CONTROL] undoing a hosted check step failed', safeErrorSummary(error));
    }
  }
}

function deny(
  policy: EffectivePolicy,
  refusal: Exclude<ReturnType<typeof evaluatePolicy>, { verdict: 'allow' }>,
  ref: string,
  retry?: { ref: string; after_seconds?: number },
): DecisionResult {
  const evidence = refusalEvidence(policy, refusal);
  return denyWith(evidence, refusal.message, ref, retry);
}

function denyWith(
  evidence: PolicyRefusalEvidence,
  message: string,
  ref: string,
  retry?: { ref: string; after_seconds?: number },
): DecisionResult {
  const code: PolicyReasonCode = (POLICY_REASON_CODES as readonly string[]).includes(evidence.code) ? evidence.code : 'policy_unevaluable';
  return {
    verdict: 'deny',
    reason: { code, message: message.slice(0, 200) },
    ...(retry ? { retry } : {}),
    policyRef: ref,
    evidence,
  };
}
