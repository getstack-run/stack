// The decision request: who is acting, what they want to do and how much it
// costs, as a small flat record. Never a message body, prompt, code, page text,
// typed text, card number, credential or Passport token; the target of each
// action kind lists exactly what is sent (see ./targets.ts).

import {
  canonicalize,
  CONTROL_PURPOSE_MAX_CHARS,
  sha256,
  type ControlActionType,
  type ControlDecisionRequest,
} from '@stack/shared';

export type DecisionRequestInput = {
  decisionId: string;
  now: Date;
  deadlineMs: number;
  test: boolean;
  operatorId: string;
  socketId: string;
  accountId: string | null;
  agent: { id: string; passportJti: string | null; missionId: string | null } | null;
  actorKind: 'agent' | 'owner' | 'member';
  action: ControlActionType | 'test';
  target: Record<string, unknown>;
  amount: ControlDecisionRequest['amount'];
  purpose: string | null;
  retryRef: string | null;
};

/** Free text from an agent: capped, with control characters removed. Passed on as third-party content. */
export function cleanPurpose(raw: string | undefined | null): string | null {
  if (!raw) return null;
  // eslint-disable-next-line no-control-regex -- stripping them is the point
  const cleaned = raw.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, CONTROL_PURPOSE_MAX_CHARS);
  return cleaned.length > 0 ? cleaned : null;
}

export function buildDecisionRequest(input: DecisionRequestInput): { request: ControlDecisionRequest; body: string } {
  const unsigned = {
    type: 'stack.decision.request' as const,
    version: '1' as const,
    decision_id: input.decisionId,
    created_at: input.now.toISOString(),
    deadline_at: new Date(input.now.getTime() + input.deadlineMs).toISOString(),
    test: input.test,
    operator_id: input.operatorId,
    socket_id: input.socketId,
    account: input.accountId ? { id: input.accountId } : null,
    agent: input.agent
      ? { id: input.agent.id, passport_jti: input.agent.passportJti, mission_id: input.agent.missionId }
      : null,
    actor: { kind: input.actorKind },
    action: { type: input.action },
    target: input.target,
    amount: input.amount,
    purpose: { agent_stated: input.purpose },
    retry_ref: input.retryRef,
  };
  const request = { ...unsigned, request_digest: `sha256:${sha256(canonicalize(unsigned))}` } as ControlDecisionRequest;
  return { request, body: JSON.stringify(request) };
}
