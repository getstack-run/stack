import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ControlDeniedError,
  ControlSocketUnavailableError,
  ControlUnavailableError,
  SpendRefusedError,
} from '@stack/shared';
import type { FastifyRequest } from 'fastify';

const access = vi.hoisted(() => ({ resolve: vi.fn() }));

const { decideControl, decideControlRecorded } = await import('./control-decision.js');

function fakes() {
  const ask = vi.fn(async (_input: Record<string, unknown>) => ({ asked: false as boolean } as Record<string, unknown>));
  return { ask, services: { controlDecisions: { ask }, accountDirectory: { accountOfAgent: access.resolve } } as never };
}

function req(over: Record<string, unknown> = {}, headers: Record<string, string> = {}): FastifyRequest & { refundAction?: boolean } {
  return { id: 'req_1', operatorId: 'op_1', headers, ...over } as never;
}

const base = { target: { a: 1 } };

beforeEach(() => {
  access.resolve.mockReset();
  access.resolve.mockResolvedValue(null);
});

describe('the decision an allowed action keeps', () => {
  const input = { ...base, action: 'meeting.join' as const, scope: 'account' as const, accountId: 'acct_1', agentId: 'agt_acct' };

  it('answers the id of the decision that allowed it, and nothing else', async () => {
    const { ask, services } = fakes();
    ask.mockResolvedValue({ asked: true, verdict: 'allow', decisionId: 'dec_9', settle: [] });
    await expect(decideControlRecorded(services, req(), input)).resolves.toEqual({ decisionId: 'dec_9' });
    await expect(decideControl(services, req(), input)).resolves.toBeUndefined();
  });

  it('answers no id when nothing was asked, and refuses as decideControl does', async () => {
    const { ask, services } = fakes();
    await expect(decideControlRecorded(services, req(), input)).resolves.toEqual({ decisionId: null });
    await expect(decideControlRecorded(services, req({ operatorId: 'op_stack_system' }), input)).resolves.toEqual({ decisionId: null });
    ask.mockResolvedValue({ asked: true, verdict: 'deny', decisionId: 'dec_x', reason: null, retry: null, evidence: null });
    const request = req();
    await expect(decideControlRecorded(services, request, input)).rejects.toBeInstanceOf(ControlDeniedError);
    expect(request.refundAction).toBe(true);
  });
});

describe('who decideControl asks', () => {
  it('never asks about an agent outside an account: today\'s controls stay as they are', async () => {
    const { ask, services } = fakes();
    await decideControl(services, req({ agentId: 'agt_plain' }), { ...base, action: 'proxy.call', scope: 'agent', agentId: 'agt_plain' });
    expect(access.resolve).toHaveBeenCalledWith('op_1', 'agt_plain');
    expect(ask).not.toHaveBeenCalled();
  });

  it('asks about an account agent, with the account the agent belongs to', async () => {
    access.resolve.mockResolvedValue({ accountId: 'acct_9', status: 'open' });
    const { ask, services } = fakes();
    await decideControl(services, req({ agentId: 'agt_acct' }), {
      ...base, action: 'model.call', scope: 'agent', agentId: 'agt_acct', runtime: { passportJti: 'pas_1', missionId: 'ms_1' },
    });
    expect(ask).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_1', action: 'model.call', accountId: 'acct_9', actorKind: 'agent',
      agent: { id: 'agt_acct', passportJti: 'pas_1', missionId: 'ms_1' }, target: { a: 1 },
    }));
  });

  it('asks about an account route whoever calls it: the agent, the owner with a key, a member', async () => {
    const { ask, services } = fakes();
    const input = { ...base, action: 'email.send' as const, scope: 'account' as const, accountId: 'acct_1', agentId: 'agt_acct', missionId: 'ms_acct' };
    await decideControl(services, req({ agentId: 'agt_acct' }), { ...input, runtime: { passportJti: 'pas_1', missionId: 'ms_acct' } });
    await decideControl(services, req(), input);
    await decideControl(services, req({ memberId: 'mem_1' }), input);
    expect(ask.mock.calls.map((c) => c[0]['actorKind'])).toEqual(['agent', 'owner', 'member']);
    expect(ask.mock.calls[1]![0]).toMatchObject({
      accountId: 'acct_1', agent: { id: 'agt_acct', passportJti: null, missionId: 'ms_acct' },
    });
    // No Passport resolution for an account route: the route already named the account.
    expect(access.resolve).not.toHaveBeenCalled();
  });

  it('asks an owner action that names no agent, with no agent in the request', async () => {
    const { ask, services } = fakes();
    await decideControl(services, req(), { ...base, action: 'account.open', scope: 'account' });
    expect(ask).toHaveBeenCalledWith(expect.objectContaining({ action: 'account.open', accountId: null, agent: null, actorKind: 'owner' }));
  });

  it('never asks about STACK\'s own operators', async () => {
    const { ask, services } = fakes();
    await decideControl(services, req({ operatorId: 'op_stack_system' }), { ...base, action: 'email.send', scope: 'account', accountId: 'acct_1' });
    expect(ask).not.toHaveBeenCalled();
  });

  it('passes the agent\'s stated purpose, cleaned and capped, and the approval reference to retry with', async () => {
    const { ask, services } = fakes();
    const headers = { 'x-stack-purpose': `pay\u0000 the invoice ${'x'.repeat(400)}`, 'x-control-ref': 'apr_7' };
    await decideControl(services, req({}, headers), { ...base, action: 'email.send', scope: 'account', accountId: 'acct_1' });
    const sent = ask.mock.calls[0]![0] as { purpose: string; retryRef: string };
    expect(sent.purpose).toHaveLength(200);
    expect(sent.purpose.startsWith('pay  the invoice')).toBe(true);
    expect(sent.retryRef).toBe('apr_7');
  });
});

describe('what a refusal does', () => {
  const input = { ...base, action: 'sms.send' as const, scope: 'account' as const, accountId: 'acct_1' };

  it('an allow, or an unchecked kind, returns and hands nothing back', async () => {
    const { ask, services } = fakes();
    const request = req();
    ask.mockResolvedValueOnce({ asked: true, verdict: 'allow', settle: [] });
    await expect(decideControl(services, request, input)).resolves.toBeUndefined();
    await expect(decideControl(services, request, input)).resolves.toBeUndefined();
    expect(request.refundAction).toBeUndefined();
    expect(request.controlSettle).toBeUndefined();
  });

  it('an allow that left something open hands it to the response hook, in order, across decisions of one request', async () => {
    const { ask, services } = fakes();
    const request = req();
    const first = vi.fn(async () => undefined);
    const second = vi.fn(async () => undefined);
    ask.mockResolvedValueOnce({ asked: true, verdict: 'allow', settle: [first] });
    ask.mockResolvedValueOnce({ asked: true, verdict: 'allow', settle: [second] });
    await decideControl(services, request, input);
    await decideControl(services, request, input);
    expect(request.controlSettle).toEqual([first, second]);
  });

  it('a refusal by a hosted policy names the rule that refused, and the action is handed back', async () => {
    const { ask, services } = fakes();
    const evidence = { policy_id: 'cpl_1', policy_revision: 4, section: 'recipients', rule: 'email', code: 'recipient_not_allowed' };
    ask.mockResolvedValue({
      asked: true, verdict: 'deny', decisionId: 'dec_9', decider: 'hosted', reason: { code: 'recipient_not_allowed', message: 'No.' },
      retry: null, evidence, settle: [],
    });
    const request = req();
    const error = await decideControl(services, request, input).catch((e: unknown) => e) as { code: string; details: Record<string, unknown> };
    expect(error.code).toBe('CONTROL_DENIED');
    expect(error.details).toEqual({ decision_id: 'dec_9', reason_code: 'recipient_not_allowed', rule: evidence });
    expect(request.refundAction).toBe(true);
  });

  it('a denial is 403 CONTROL_DENIED with the reason and the retry reference, and the action is handed back', async () => {
    const { ask, services } = fakes();
    ask.mockResolvedValue({
      asked: true, verdict: 'deny', decisionId: 'dec_1', decider: 'remote',
      reason: { code: 'blocked_recipient', message: 'Not on the allow list' }, retry: { ref: 'apr_2', after_seconds: 60 },
    });
    const request = req();
    const error = await decideControl(services, request, input).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlDeniedError);
    expect(error).toMatchObject({
      code: 'CONTROL_DENIED', statusCode: 403, message: 'Not on the allow list',
      details: { decision_id: 'dec_1', reason_code: 'blocked_recipient', retry: { ref: 'apr_2', after_seconds: 60 } },
    });
    expect(request.refundAction).toBe(true);
  });

  it('no usable answer from the customer\'s server is 403 CONTROL_SOCKET_UNAVAILABLE, never 5xx, and handed back', async () => {
    const { ask, services } = fakes();
    ask.mockResolvedValue({ asked: true, verdict: 'unavailable', decisionId: 'dec_2', decider: 'remote', cause: 'timeout' });
    const request = req();
    const error = await decideControl(services, request, input).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlSocketUnavailableError);
    expect(error).toMatchObject({ code: 'CONTROL_SOCKET_UNAVAILABLE', statusCode: 403, details: { decision_id: 'dec_2', cause: 'timeout' } });
    expect(request.refundAction).toBe(true);
  });

  it('a hosted failure is STACK\'s doing: 503 CONTROL_UNAVAILABLE, listed as STACK-side, handed back', async () => {
    const { ask, services } = fakes();
    ask.mockResolvedValue({ asked: true, verdict: 'unavailable', decisionId: 'dec_3', decider: 'hosted', cause: 'hosted_failure' });
    const request = req();
    const error = await decideControl(services, request, input).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlUnavailableError);
    expect(error).toMatchObject({ code: 'CONTROL_UNAVAILABLE', statusCode: 503 });
    expect((error as ControlUnavailableError).stackSide).toBe(true);
    expect(request.refundAction).toBe(true);
  });

  it('a check that cannot be paid, or a failed read of the customer\'s controls, refuses and hands the action back', async () => {
    const { ask, services } = fakes();
    const request = req();
    ask.mockRejectedValue(new SpendRefusedError('Insufficient balance', 'INSUFFICIENT_BALANCE', { balance_cents: 0, required_cents: 1 }));
    await expect(decideControl(services, request, input)).rejects.toBeInstanceOf(SpendRefusedError);
    expect(request.refundAction).toBe(true);

    const other = req();
    ask.mockRejectedValue(new Error('billing account unreadable'));
    await expect(decideControl(services, other, input)).rejects.toThrow('billing account unreadable');
    expect(other.refundAction).toBe(true);
  });
});
