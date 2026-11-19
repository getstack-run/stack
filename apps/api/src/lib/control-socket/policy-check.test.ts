import { describe, expect, it, vi } from 'vitest';
import { normalizePolicy, normalizeRequest, type ControlActionType, type PolicyDefinitionInput } from '@stack/shared';

type Sections = Omit<PolicyDefinitionInput, 'name'>;
import type { ControlReviewService, EffectivePolicy } from '@stack/vault';
import { HostedDecider } from './deciders.js';
import { PolicyHostedCheck, callDigestOf, describeHeldCall, policyRef } from './policy-check.js';
import { buildDecisionRequest } from './request-builder.js';
import { runSettle } from './settle.js';
import type { DecisionContext, DecisionResult } from './types.js';

const OPERATOR = 'op_check';
const AGENT = 'agt_check';
const ACCOUNT = 'acct_check';

function policy(definition: Sections = {}, revision = 3): EffectivePolicy {
  return { id: 'cpl_check', agentId: AGENT, revision, name: 'p', definition: normalizePolicy({ name: 'p', ...definition }), source: 'agent' };
}

function context(
  action: ControlActionType,
  target: Record<string, unknown> = {},
  extras: { retryRef?: string | null; amountCents?: number | null; privileged?: DecisionContext['privileged']; decisionId?: string } = {},
): DecisionContext {
  const { request, body } = buildDecisionRequest({
    decisionId: extras.decisionId ?? 'dec_aaaaaaaaaaaaaaaaaaaaaaaa',
    now: new Date('2026-10-21T10:00:00Z'),
    deadlineMs: 2_000,
    test: false,
    operatorId: OPERATOR,
    socketId: 'csk_x',
    accountId: ACCOUNT,
    agent: { id: AGENT, passportJti: 'jti_1', missionId: 'msn_1' },
    actorKind: 'agent',
    action,
    target,
    amount: extras.amountCents === undefined || extras.amountCents === null ? null : { max_cents: extras.amountCents, currency: 'USD' },
    purpose: null,
    retryRef: extras.retryRef ?? null,
  });
  return {
    request,
    body,
    operatorId: OPERATOR,
    socket: {} as DecisionContext['socket'],
    ...(extras.privileged ? { privileged: extras.privileged } : {}),
  };
}

function fakes(effective: EffectivePolicy | null) {
  const reviews = {
    open: vi.fn(async (input: { callDigest: string }) => ({
      review: { id: 'crv_1', callDigest: input.callDigest } as unknown as Awaited<ReturnType<ControlReviewService['open']>>['review'],
      created: true,
      approvalUrl: 'https://example.test/app/approve/gvr_1',
    })),
    reserve: vi.fn(async () => ({ state: 'unknown' as const, review: null }) as Awaited<ReturnType<ControlReviewService['reserve']>>),
    consume: vi.fn(async () => true),
    release: vi.fn(async () => true),
  };
  const limits = {
    consumeActions: vi.fn(async () => ({ ok: true as const, refs: [{ accountId: ACCOUNT, kind: 'day' as const, periodKey: '2026-10-21', amount: 1 }] })),
    releaseActions: vi.fn(async () => undefined),
  };
  const concurrency = {
    acquire: vi.fn(async () => ({ leaseId: 'lease_1' }) as { leaseId: string } | null),
    release: vi.fn(async () => undefined),
  };
  const policies = { effective: vi.fn(async () => effective) };
  const chat = { offer: vi.fn(async () => ({ sent: 1 })) };
  const check = new PolicyHostedCheck({ policies, reviews, limits, concurrency, chat });
  return { check, reviews, limits, concurrency, policies, chat };
}

const slackCall = (connection: string, channel: string) => {
  const request = normalizeRequest({ service: 'slack', url: 'https://slack.com/api/chat.postMessage', method: 'POST', body: { channel, text: 'hi' } });
  return context(
    'proxy.call',
    { service: 'slack', connection_id: connection, method: 'POST', host: 'slack.com', path: '/api/chat.postMessage' },
    { privileged: { request } },
  );
};

describe('the hosted policy check', () => {
  it('allows when no policy applies, touching nothing', async () => {
    const f = fakes(null);
    expect(await f.check.evaluate(context('model.call', { provider: 'openai', model: 'gpt-4o' }))).toEqual({ verdict: 'allow' });
    expect(f.limits.consumeActions).not.toHaveBeenCalled();
    expect(f.concurrency.acquire).not.toHaveBeenCalled();
  });

  it('refuses by a rule, names the rule and the policy, counts nothing', async () => {
    const f = fakes(policy({
      connections: { mode: 'any', rules: [{ id: 'no-slack', effect: 'deny', access: { connection_id: 'scon_slack' } }] },
      spend: { limits: [{ kind: 'day', unit: 'actions', limit: 5 }], max_concurrent: 2 },
    }));
    const result = await f.check.evaluate(slackCall('scon_slack', 'C1'));
    expect(result).toMatchObject({
      verdict: 'deny',
      reason: { code: 'connection_denied' },
      policyRef: 'cpl_check@3',
      evidence: { policy_id: 'cpl_check', policy_revision: 3, section: 'connections', rule: 'no-slack', code: 'connection_denied' },
    });
    expect(JSON.stringify(result)).not.toContain('"hi"');
    expect(f.limits.consumeActions).not.toHaveBeenCalled();
    expect(f.concurrency.acquire).not.toHaveBeenCalled();
    expect(f.reviews.open).not.toHaveBeenCalled();
  });

  it('allows an unlisted connection and returns nothing to settle when no counter applies', async () => {
    const f = fakes(policy({ connections: { mode: 'any', rules: [{ id: 'no-slack', effect: 'deny', access: { connection_id: 'scon_slack' } }] } }));
    expect(await f.check.evaluate(slackCall('scon_other', 'C1'))).toEqual({ verdict: 'allow', policyRef: 'cpl_check@3' });
  });

  describe('action limits', () => {
    const limited = () => policy({ spend: { limits: [{ kind: 'day', unit: 'actions', limit: 3 }, { kind: 'month', unit: 'actions', limit: 50 }] } });

    it('counts each action in every window and hands it back when it never ran', async () => {
      const f = fakes(limited());
      const result = (await f.check.evaluate(context('model.call', { provider: 'openai', model: 'gpt-4o' }))) as Extract<DecisionResult, { verdict: 'allow' }>;
      expect(f.limits.consumeActions).toHaveBeenCalledWith({
        operatorId: OPERATOR, accountId: ACCOUNT, missionId: 'msn_1',
        rules: [{ kind: 'day', limit: 3 }, { kind: 'month', limit: 50 }],
      });
      expect(result.verdict).toBe('allow');
      await runSettle(result.settle!, { ok: true, handedBack: false });
      expect(f.limits.releaseActions).not.toHaveBeenCalled();
      await runSettle(result.settle!, { ok: false, handedBack: true });
      expect(f.limits.releaseActions).toHaveBeenCalledTimes(1);
    });

    it('refuses at the limit with the window named, and takes nothing else', async () => {
      const f = fakes(limited());
      f.limits.consumeActions.mockResolvedValueOnce({ ok: false, kind: 'day', limit: 3, remaining: 0 } as never);
      const result = await f.check.evaluate(context('model.call', { provider: 'openai', model: 'gpt-4o' }));
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'limit_reached' }, evidence: { section: 'spend', rule: 'limits.day.actions', detail: { limit: 3, remaining: 0 } } });
      expect(f.concurrency.acquire).not.toHaveBeenCalled();
    });
  });

  describe('concurrency', () => {
    it('leases a slot and returns it when the action ends, whatever the outcome', async () => {
      const f = fakes(policy({ spend: { limits: [], max_concurrent: 2 } }));
      const result = (await f.check.evaluate(context('model.call', {}))) as Extract<DecisionResult, { verdict: 'allow' }>;
      expect(f.concurrency.acquire).toHaveBeenCalledWith({ operatorId: OPERATOR, agentId: AGENT, limit: 2 });
      await runSettle(result.settle!, { ok: true, handedBack: false });
      expect(f.concurrency.release).toHaveBeenCalledWith({ operatorId: OPERATOR, agentId: AGENT, leaseId: 'lease_1' });
    });

    it('refuses when every slot is taken, and gives back the action it had counted', async () => {
      const f = fakes(policy({ spend: { limits: [{ kind: 'day', unit: 'actions', limit: 3 }], max_concurrent: 1 } }));
      f.concurrency.acquire.mockResolvedValueOnce(null);
      const result = await f.check.evaluate(context('model.call', {}));
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'concurrency_reached' }, evidence: { rule: 'max_concurrent' } });
      expect(f.limits.releaseActions).toHaveBeenCalledTimes(1);
    });
  });

  describe('held actions', () => {
    const holding = () => policy({ review: { over_cents: 1_000 } });
    const checkout = (extras: Parameters<typeof context>[2] = {}) =>
      context('card.checkout', { merchant_origin: 'https://shop.example', amount_minor: 5_000, currency: 'USD' }, { amountCents: 5_000, ...extras });

    it('refuses with a reference the agent retries with, and opens one review for the exact call', async () => {
      const f = fakes(holding());
      const result = await f.check.evaluate(checkout());
      expect(result).toMatchObject({
        verdict: 'deny',
        reason: { code: 'review_required' },
        retry: { ref: 'crv_1', after_seconds: 30 },
        evidence: { section: 'review', rule: 'over_cents', code: 'review_required' },
      });
      expect(f.reviews.open).toHaveBeenCalledTimes(1);
      const input = (f.reviews.open.mock.calls[0] as unknown as [{ summary: string; callDigest: string; accountId: string }])[0];
      expect(input.accountId).toBe(ACCOUNT);
      expect(input.callDigest).toMatch(/^[0-9a-f]{64}$/);
      // The line a person reads names what and which rule, not call content.
      expect(input.summary).toContain('pay https://shop.example by card');
      expect(input.summary).toContain('review: over_cents');
    });

    it('a held payment is opened with its amount and offered to the owner\'s chat, without waiting for it', async () => {
      const f = fakes(holding());
      let finishOffer: () => void = () => undefined;
      f.chat.offer.mockImplementationOnce(() => new Promise((resolve) => { finishOffer = () => resolve({ sent: 1 }); }));
      // The decision returns while the chat provider is still being talked to.
      const result = await f.check.evaluate(checkout());
      expect(result).toMatchObject({ verdict: 'deny', retry: { ref: 'crv_1' } });
      const input = (f.reviews.open.mock.calls[0] as unknown as [{ payment?: { surface: string; amountCents: number } }])[0];
      expect(input.payment).toEqual({ surface: 'card', amountCents: 5_000 });
      expect(f.chat.offer).toHaveBeenCalledTimes(1);
      finishOffer();
    });

    it('a wallet payment is a payment too; a held send or an amount not in USD is not offered as one', async () => {
      const wallet = fakes(holding());
      await wallet.check.evaluate(context('wallet.payment', { payee: `0x${'a'.repeat(40)}`, amount: '50000000' }, { amountCents: 5_000 }));
      expect((wallet.reviews.open.mock.calls[0] as unknown as [{ payment?: unknown }])[0].payment).toEqual({ surface: 'wallet', amountCents: 5_000 });
      const send = fakes(policy({ actions: { kinds: { 'email.send': 'review' } } }));
      await send.check.evaluate(context('email.send', { recipients: [{ address: 'a@b.example', domain: 'b.example' }] }));
      expect((send.reviews.open.mock.calls[0] as unknown as [{ payment?: unknown }])[0]).not.toHaveProperty('payment');
      const foreign = fakes(policy({ actions: { kinds: { 'card.checkout': 'review' } } }));
      await foreign.check.evaluate(context('card.checkout', { merchant_origin: 'https://shop.example', amount_minor: 5_000, currency: 'EUR' }, { amountCents: null }));
      expect((foreign.reviews.open.mock.calls[0] as unknown as [{ payment?: unknown }])[0]).not.toHaveProperty('payment');
    });

    it('asking again about a review that exists does not ask the chat again, and a chat failure never fails the decision', async () => {
      const again = fakes(holding());
      again.reviews.open.mockImplementationOnce(async (input) => ({
        review: { id: 'crv_1', callDigest: input.callDigest } as never, created: false, approvalUrl: 'https://example.test/app/approve/gvr_1',
      }));
      await again.check.evaluate(checkout());
      expect(again.chat.offer).not.toHaveBeenCalled();
      const failing = fakes(holding());
      failing.chat.offer.mockRejectedValueOnce(new Error('telegram down'));
      const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      expect(await failing.check.evaluate(checkout())).toMatchObject({ verdict: 'deny', retry: { ref: 'crv_1' } });
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('is the same call digest for the same call, and a different one for a different call', () => {
      const a = checkout();
      const b = checkout({ decisionId: 'dec_bbbbbbbbbbbbbbbbbbbbbbbb' });
      const call = { action: 'card.checkout' as const, target: a.request.target, amountCents: 5_000 };
      expect(callDigestOf(a, call, AGENT)).toBe(callDigestOf(b, { ...call, target: b.request.target }, AGENT));
      expect(callDigestOf(a, call, AGENT)).not.toBe(callDigestOf(a, { ...call, amountCents: 5_001 }, AGENT));
      expect(callDigestOf(a, call, AGENT)).not.toBe(callDigestOf(a, call, 'agt_other'));
    });

    it('a pending review keeps refusing, with the same reference', async () => {
      const f = fakes(holding());
      f.reviews.reserve.mockResolvedValueOnce({ state: 'pending', review: null });
      const result = await f.check.evaluate(checkout({ retryRef: 'crv_1' }));
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'review_pending' }, retry: { ref: 'crv_1' } });
      expect(f.reviews.open).not.toHaveBeenCalled();
    });

    it('a declined review is final', async () => {
      const f = fakes(holding());
      f.reviews.reserve.mockResolvedValueOnce({ state: 'rejected', review: null });
      const result = await f.check.evaluate(checkout({ retryRef: 'crv_1' }));
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'review_rejected' } });
      expect(result).not.toHaveProperty('retry');
    });

    it('an approved review is reserved for this operation, spent when the action ran and given back when it did not', async () => {
      const f = fakes(holding());
      f.reviews.reserve.mockResolvedValue({ state: 'reserved', review: { id: 'crv_1' } as never, ownerHash: 'a'.repeat(64) });
      const result = (await f.check.evaluate(checkout({ retryRef: 'crv_1', decisionId: 'dec_cccccccccccccccccccccccc' }))) as Extract<DecisionResult, { verdict: 'allow' }>;
      expect(result.verdict).toBe('allow');
      expect(f.reviews.reserve).toHaveBeenCalledWith(expect.objectContaining({ ref: 'crv_1', agentId: AGENT, operation: 'dec_cccccccccccccccccccccccc' }));
      await runSettle(result.settle!, { ok: true, handedBack: false });
      expect(f.reviews.consume).toHaveBeenCalledWith('crv_1', 'a'.repeat(64));
      expect(f.reviews.release).not.toHaveBeenCalled();
      await runSettle(result.settle!, { ok: false, handedBack: false });
      expect(f.reviews.release).toHaveBeenCalledWith('crv_1', 'a'.repeat(64));
    });

    it('an approval does not lift a limit: a refusal after the reservation gives the approval back', async () => {
      const f = fakes(policy({ review: { over_cents: 1_000 }, spend: { limits: [{ kind: 'day', unit: 'actions', limit: 1 }] } }));
      f.reviews.reserve.mockResolvedValue({ state: 'reserved', review: { id: 'crv_1' } as never, ownerHash: 'b'.repeat(64) });
      f.limits.consumeActions.mockResolvedValueOnce({ ok: false, kind: 'day', limit: 1, remaining: 0 } as never);
      const result = await f.check.evaluate(checkout({ retryRef: 'crv_1' }));
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'limit_reached' } });
      expect(f.reviews.release).toHaveBeenCalledWith('crv_1', 'b'.repeat(64));
      expect(f.reviews.consume).not.toHaveBeenCalled();
    });

    it('a spent or lapsed reference holds the call again with a fresh review', async () => {
      const f = fakes(holding());
      f.reviews.reserve.mockResolvedValueOnce({ state: 'consumed', review: null });
      const result = await f.check.evaluate(checkout({ retryRef: 'crv_old' }));
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'review_required' }, retry: { ref: 'crv_1' } });
      expect(f.reviews.open).toHaveBeenCalledTimes(1);
    });

    it('a refusal outranks a hold: nothing is opened for a call that is refused anyway', async () => {
      const f = fakes(policy({ review: { over_cents: 1_000 }, spend: { max_per_action_cents: 2_000, limits: [] } }));
      const result = await f.check.evaluate(checkout());
      expect(result).toMatchObject({ verdict: 'deny', reason: { code: 'amount_over_limit' } });
      expect(f.reviews.open).not.toHaveBeenCalled();
    });
  });

  it('turns a failure into "could not decide", having undone what it had done', async () => {
    const f = fakes(policy({ spend: { limits: [{ kind: 'day', unit: 'actions', limit: 3 }], max_concurrent: 2 } }));
    f.concurrency.acquire.mockRejectedValueOnce(new Error('redis down'));
    const decided = await new HostedDecider([f.check]).decide(context('model.call', {}));
    expect(decided).toEqual({ verdict: 'unavailable', cause: 'hosted_failure' });
    expect(f.limits.releaseActions).toHaveBeenCalledTimes(1);
  });

  it('describes a held call without its content', () => {
    const line = describeHeldCall(
      { action: 'proxy.call', target: { method: 'POST', host: 'slack.com', path: '/api/chat.postMessage', connection_id: 'scon_slack' }, amountCents: null },
      { section: 'connections', id: 'ask-slack' },
    );
    expect(line).toBe('Your agent wants to POST slack.com/api/chat.postMessage on connection scon_slack. Held by connections: ask-slack.');
    expect(policyRef({ id: 'cpl_x', revision: 7 })).toBe('cpl_x@7');
  });
});
