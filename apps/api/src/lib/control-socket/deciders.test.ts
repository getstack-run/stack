import { describe, expect, it, vi } from 'vitest';
import { HostedDecider, NoneDecider, type HostedCheck } from './deciders.js';
import { buildDecisionRequest } from './request-builder.js';
import type { DecisionContext, DecisionResult } from './types.js';

function context(): DecisionContext {
  const { request, body } = buildDecisionRequest({
    decisionId: 'dec_aaaaaaaaaaaaaaaaaaaaaaaa', now: new Date('2026-10-21T10:00:00Z'), deadlineMs: 2_000, test: false,
    operatorId: 'op_1', socketId: 'csk_1', accountId: 'acct_1', agent: { id: 'agt_1', passportJti: null, missionId: null },
    actorKind: 'agent', action: 'model.call', target: {}, amount: null, purpose: null, retryRef: null,
  });
  return { request, body, operatorId: 'op_1', socket: {} as DecisionContext['socket'] };
}

const check = (name: string, result: () => Promise<DecisionResult>): HostedCheck => ({ name, appliesTo: () => true, evaluate: result });

describe('the hosted decider', () => {
  it('no controls: allows with no check', async () => {
    expect(await new NoneDecider().decide()).toEqual({ verdict: 'allow' });
  });

  it('allows when no check objects, and collects what each allowing check left open', async () => {
    const a = vi.fn(async () => undefined);
    const b = vi.fn(async () => undefined);
    const decided = await new HostedDecider([
      check('a', async () => ({ verdict: 'allow', policyRef: 'cpl_1@2', settle: [a] })),
      check('b', async () => ({ verdict: 'allow', settle: [b] })),
    ]).decide(context());
    expect(decided).toEqual({ verdict: 'allow', policyRef: 'cpl_1@2', settle: [a, b] });
    expect(a).not.toHaveBeenCalled();
  });

  it('the first refusal decides, and what earlier checks left open is handed back at once', async () => {
    const left = vi.fn(async () => undefined);
    const never = vi.fn(async () => ({ verdict: 'allow' }) as DecisionResult);
    const decided = await new HostedDecider([
      check('a', async () => ({ verdict: 'allow', settle: [left] })),
      check('b', async () => ({ verdict: 'deny', reason: { code: 'no', message: null } })),
      check('c', never),
    ]).decide(context());
    expect(decided).toMatchObject({ verdict: 'deny', reason: { code: 'no' } });
    expect(left).toHaveBeenCalledWith({ ok: false, handedBack: true });
    expect(never).not.toHaveBeenCalled();
  });

  it('a check that throws is "could not decide", never an allow, and what was left open is handed back', async () => {
    const left = vi.fn(async () => undefined);
    const decided = await new HostedDecider([
      check('a', async () => ({ verdict: 'allow', settle: [left] })),
      check('b', async () => {
        throw new Error('database down');
      }),
    ]).decide(context());
    expect(decided).toEqual({ verdict: 'unavailable', cause: 'hosted_failure' });
    expect(left).toHaveBeenCalledWith({ ok: false, handedBack: true });
  });

  it('skips a check that does not apply to the kind of action', async () => {
    const skipped = vi.fn(async () => ({ verdict: 'deny', reason: { code: 'no', message: null } }) as DecisionResult);
    const decided = await new HostedDecider([{ name: 'x', appliesTo: () => false, evaluate: skipped }]).decide(context());
    expect(decided).toEqual({ verdict: 'allow' });
    expect(skipped).not.toHaveBeenCalled();
  });
});
