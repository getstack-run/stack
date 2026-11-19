// decideControl: the one call every action path makes before it spends, sends
// or acts. It asks the customer's decider (see lib/control-socket/engine.ts)
// and either returns, or throws a refusal that is never charged.
//
// Where it goes: after Mission admission (beginAgentRuntime) and after the
// meter, before any budget or wallet hold, credential decryption or provider
// call, so STACK's own refusals (the off switch, a revoked Mission, a closed
// account) never wait on a customer's server. Pinned for every
// beginAgentRuntime site by routes/control-socket-coverage.test.ts.
//
// Who is asked:
//   scope 'account'  an account route: the account's agent, or its owner with an
//                    API key or a member session. Always asked.
//   scope 'agent'    a route an agent reaches with a Passport (models, the
//                    proxy, drop-offs, A2A, skills, delegation): asked only when
//                    the agent belongs to an agent account. An agent outside an
//                    account keeps today's controls and is never asked.
//
// A refusal hands the metered action back (`request.refundAction`, read by the
// meter's refund hook): the action itself is never charged when it is refused. The
// hosted check that refused it is a different meter: it ran, so it is charged
// (the price is per action checked), unless the wallet cannot pay it, in which
// case the denial still stands and is not hidden behind a payment error.
//
// An allowed action may leave something open (a counted action, a reserved
// approval, a lease on concurrency). The decision hands those back as
// `request.controlSettle`, and the hooks of middleware/control-settle.ts (response end, and a client that hung up)
// tell them how the action ended.

import {
  CONTROL_PURPOSE_HEADER,
  CONTROL_REF_HEADER,
  ControlDeniedError,
  ControlSocketUnavailableError,
  ControlUnavailableError,
  ids,
  type ControlActionType,
  type ControlDecisionRequest,
} from '@stack/shared';
import type { FastifyRequest } from 'fastify';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';
import { isSystemOperator } from './action-meter.js';
import { cleanPurpose } from './control-socket/request-builder.js';
import type { SettleHook } from './control-socket/types.js';

export interface ControlDecisionInput {
  action: ControlActionType;
  scope: 'account' | 'agent';
  /** The acting agent: the account's agent for an account route, the Passport's agent otherwise. */
  agentId?: string | null | undefined;
  /** The account, when the route names it. */
  accountId?: string | null | undefined;
  /** What Mission admission returned; null for an owner acting with no Passport. */
  runtime?: { passportJti: string; missionId: string | null } | null | undefined;
  /** A Mission to name when there is no Passport (an owner acting on an account). */
  missionId?: string | null | undefined;
  target: Record<string, unknown>;
  amount?: ControlDecisionRequest['amount'] | undefined;
  /** In-process only; never sent to a remote decider. */
  privileged?: Readonly<Record<string, unknown>> | undefined;
}

type ControlServices = Pick<Services, 'controlDecisions' | 'accountDirectory'>;

function header(request: FastifyRequest, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

/** What was decided: the decision's id, or null when nothing was asked (no decider, an agent outside an account, STACK's own operator). */
export interface ControlDecided {
  decisionId: string | null;
}

/** The question every action path asks. It returns when the action is allowed and throws the refusal when it is not. */
export async function decideControl(
  services: ControlServices,
  request: FastifyRequest,
  input: ControlDecisionInput,
): Promise<void> {
  await decideControlRecorded(services, request, input);
}

/**
 * `decideControl`, for a caller that keeps the decision it was given: it answers the decision's id (null when nothing was
 * asked), so the allowed action can be tied to the decision that allowed it.
 */
export async function decideControlRecorded(
  services: ControlServices,
  request: FastifyRequest,
  input: ControlDecisionInput,
): Promise<ControlDecided> {
  if (isSystemOperator(request.operatorId)) return { decisionId: null };

  let accountId = input.accountId ?? null;
  if (input.scope === 'agent') {
    const actingAgentId = input.agentId ?? request.agentId;
    const account = actingAgentId ? await services.accountDirectory.accountOfAgent(request.operatorId, actingAgentId) : null;
    if (!account) return { decisionId: null };
    accountId = account.accountId;
  }

  const agentId = input.agentId ?? request.agentId ?? null;
  const actorKind = request.agentId ? 'agent' : request.memberId ? 'member' : 'owner';
  try {
    const asked = await services.controlDecisions.ask({
      operatorId: request.operatorId,
      action: input.action,
      accountId,
      agent: agentId
        ? { id: agentId, passportJti: input.runtime?.passportJti ?? null, missionId: input.runtime?.missionId ?? input.missionId ?? null }
        : null,
      actorKind,
      target: input.target,
      amount: input.amount ?? null,
      purpose: cleanPurpose(header(request, CONTROL_PURPOSE_HEADER)),
      retryRef: header(request, CONTROL_REF_HEADER)?.slice(0, 200) ?? null,
      audit: auditCtx(request, {
        ...(agentId ? { agent_id: agentId } : {}),
        ...(input.runtime ? { passport_jti: input.runtime.passportJti } : {}),
      }),
      ...(input.privileged ? { privileged: input.privileged } : {}),
    });
    if (!asked.asked) return { decisionId: null };
    if (asked.verdict === 'allow') {
      if (asked.settle.length > 0) request.controlSettle = [...(request.controlSettle ?? []), ...asked.settle];
      return { decisionId: asked.decisionId };
    }

    request.refundAction = true;
    if (asked.verdict === 'deny') {
      throw new ControlDeniedError(
        asked.decisionId,
        asked.reason?.code ?? null,
        asked.reason?.message ?? null,
        asked.retry,
        asked.evidence ? { ...asked.evidence } : null,
      );
    }
    if (asked.decider === 'hosted') throw new ControlUnavailableError(asked.decisionId);
    throw new ControlSocketUnavailableError(asked.decisionId, asked.cause ?? 'unreachable');
  } catch (error) {
    // Whatever stopped the action here (a refusal, an unpaid check, a failed read of
    // the customer's controls), the action was never done: hand it back.
    request.refundAction = true;
    throw error;
  }
}

export interface DetachedControlInput {
  operatorId: string;
  action: ControlActionType;
  accountId: string;
  agentId: string;
  missionId: string | null;
  target: Record<string, unknown>;
}

/**
 * The same question as `decideControl` for an action no request started: a wake-up
 * (an event of the account's own, delivered to its agent), which the dispatcher puts
 * to the customer's decider. It returns what the decision left open (the settle
 * hooks) and throws the same refusals; it hands nothing back, because there is no
 * request to carry a refund: the caller undoes its own meter.
 */
export async function decideControlDetached(
  services: Pick<Services, 'controlDecisions'>,
  input: DetachedControlInput,
): Promise<{ settle: SettleHook[]; decisionId: string | null }> {
  const asked = await services.controlDecisions.ask({
    operatorId: input.operatorId,
    action: input.action,
    accountId: input.accountId,
    agent: { id: input.agentId, passportJti: null, missionId: input.missionId },
    actorKind: 'agent',
    target: input.target,
    amount: null,
    purpose: null,
    retryRef: null,
    audit: { trace_id: ids.session(), span_id: ids.session(), operator_id: input.operatorId, agent_id: input.agentId, passport_jti: 'none' },
  });
  if (!asked.asked) return { settle: [], decisionId: null };
  if (asked.verdict === 'allow') return { settle: asked.settle, decisionId: asked.decisionId };
  if (asked.verdict === 'deny') {
    throw new ControlDeniedError(
      asked.decisionId,
      asked.reason?.code ?? null,
      asked.reason?.message ?? null,
      asked.retry,
      asked.evidence ? { ...asked.evidence } : null,
    );
  }
  if (asked.decider === 'hosted') throw new ControlUnavailableError(asked.decisionId);
  throw new ControlSocketUnavailableError(asked.decisionId, asked.cause ?? 'unreachable');
}
