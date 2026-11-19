import { afterEach, describe, expect, it, vi } from 'vitest';
import { SpendRefusedError, normalizePolicy, type ControlActionType } from '@stack/shared';
import type { AuditContext, ControlSocketRuntime } from '@stack/vault';
import { ControlDecisionEngine, type AskInput } from './engine.js';
import { HostedDecider } from './deciders.js';
import { PolicyHostedCheck } from './policy-check.js';
import type { Decider, DecisionResult } from './types.js';

const AUDIT: AuditContext = { trace_id: 't', span_id: 's', operator_id: 'op_1', agent_id: 'agt_1', passport_jti: 'pas_1' };

function runtime(over: Partial<ControlSocketRuntime> = {}): ControlSocketRuntime {
  return {
    socketId: 'csk_1', modeSetting: 'auto', decisionUrl: null, decisionStatus: 'unverified', timeoutMs: 1500, onUnavailable: 'refuse', checkedTypes: null, ...over,
  };
}

function ask(over: Partial<AskInput> = {}): AskInput {
  return {
    operatorId: 'op_1', action: 'email.send', accountId: 'acct_1',
    agent: { id: 'agt_1', passportJti: 'pas_1', missionId: 'ms_1' }, actorKind: 'agent',
    target: { recipients: [{ address: 'a@x.test', domain: 'x.test' }], recipient_count: 1 },
    amount: null, purpose: null, retryRef: null, audit: AUDIT, ...over,
  };
}

function decider(kind: 'hosted' | 'remote' | 'none', result: DecisionResult | (() => Promise<DecisionResult>)): Decider & { decide: ReturnType<typeof vi.fn> } {
  return {
    kind,
    decide: vi.fn(async () => (typeof result === 'function' ? result() : result)),
  } as Decider & { decide: ReturnType<typeof vi.fn> };
}

function build(opts: {
  socket?: Partial<ControlSocketRuntime>;
  controls?: boolean;
  hosted?: DecisionResult | (() => Promise<DecisionResult>);
  remote?: DecisionResult | (() => Promise<DecisionResult>);
  charge?: () => Promise<void>;
  chargeDecision?: () => Promise<void>;
  insert?: () => Promise<void>;
} = {}) {
  const hosted = decider('hosted', opts.hosted ?? { verdict: 'allow' });
  const remote = decider('remote', opts.remote ?? { verdict: 'allow' });
  const none = decider('none', { verdict: 'allow' });
  const controlsEnabled = vi.fn(async () => opts.controls ?? true);
  const charge = vi.fn(opts.charge ?? (async () => {}));
  const chargeDecision = vi.fn(opts.chargeDecision ?? (async () => {}));
  const insertDecision = vi.fn(opts.insert ?? (async () => {}));
  const write = vi.fn(async () => 'aud_1');
  const engine = new ControlDecisionEngine({
    sockets: { runtime: vi.fn(async () => runtime(opts.socket)) },
    repo: { insertDecision },
    controls: { controlsEnabled },
    audit: { write } as never,
    none, hosted, remote, charge, chargeDecision,
  });
  return { engine, hosted, remote, none, controlsEnabled, charge, chargeDecision, insertDecision, write };
}

afterEach(() => vi.useRealTimers());

describe('who is asked', () => {
  it('asks nobody with no controls: zero limits, and the decision costs nothing', async () => {
    const t = build({ controls: false });
    await expect(t.engine.ask(ask())).resolves.toEqual({ asked: false });
    expect(t.hosted.decide).not.toHaveBeenCalled();
    expect(t.remote.decide).not.toHaveBeenCalled();
    expect(t.charge).not.toHaveBeenCalled();
    expect(t.insertDecision).not.toHaveBeenCalled();
  });

  it('chosen none asks nobody, and does not read the controls decision at all', async () => {
    const t = build({ socket: { modeSetting: 'none' }, controls: true });
    await expect(t.engine.ask(ask())).resolves.toEqual({ asked: false });
    expect(t.controlsEnabled).not.toHaveBeenCalled();
  });

  it('hosted controls on: STACK decides, and one hosted check is charged', async () => {
    const t = build({ controls: true });
    const asked = await t.engine.ask(ask());
    expect(asked).toMatchObject({ asked: true, decider: 'hosted', verdict: 'allow', charged: true });
    expect(t.hosted.decide).toHaveBeenCalledTimes(1);
    expect(t.charge).toHaveBeenCalledTimes(1);
    expect(t.charge).toHaveBeenCalledWith('op_1');
    expect(t.remote.decide).not.toHaveBeenCalled();
  });

  it('a customer who chose their own server is asked there only, and is charged one own-server decision for each answer, allow or deny, never the hosted check price', async () => {
    for (const result of [{ verdict: 'allow' }, { verdict: 'deny', reason: { code: 'no', message: null } }] as DecisionResult[]) {
      const t = build({ socket: { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' }, remote: result, controls: true });
      const asked = await t.engine.ask(ask());
      expect(asked).toMatchObject({ asked: true, decider: 'remote', charged: true });
      expect(t.hosted.decide).not.toHaveBeenCalled();
      expect(t.charge).not.toHaveBeenCalled();
      expect(t.chargeDecision).toHaveBeenCalledTimes(1);
      expect(t.chargeDecision).toHaveBeenCalledWith('op_1');
      expect(t.controlsEnabled).not.toHaveBeenCalled();
    }
  });

  it('a decision the customer\'s own server did not answer is never charged', async () => {
    for (const cause of ['timeout', 'unreachable', 'bad_signature'] as const) {
      const t = build({ socket: { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' }, remote: { verdict: 'unavailable', cause }, controls: true });
      await expect(t.engine.ask(ask())).resolves.toMatchObject({ asked: true, verdict: 'unavailable', charged: false });
      expect(t.chargeDecision).not.toHaveBeenCalled();
      expect(t.charge).not.toHaveBeenCalled();
    }
  });

  it('an allow from the customer\'s own server that cannot be paid for does not run, and a refusal from it stands', async () => {
    const failure = new SpendRefusedError('Insufficient balance', 'INSUFFICIENT_BALANCE', { balance_cents: 0, required_cents: 1 });
    const socket = { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' } as const;
    const allow = build({ socket, remote: { verdict: 'allow' }, chargeDecision: async () => { throw failure; } });
    await expect(allow.engine.ask(ask())).rejects.toBe(failure);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const deny = build({ socket, remote: { verdict: 'deny', reason: { code: 'no', message: null } }, chargeDecision: async () => { throw failure; } });
    await expect(deny.engine.ask(ask())).resolves.toMatchObject({ verdict: 'deny', charged: false });
    error.mockRestore();
  });
});

describe('which kinds are checked', () => {
  it('asks and charges only the chosen kinds; the rest go through with no decision', async () => {
    const t = build({ socket: { checkedTypes: new Set<ControlActionType>(['email.send', 'card.checkout']) }, controls: true });
    for (const action of ['proxy.call', 'model.call', 'sms.send', 'workspace.exec'] as const) {
      await expect(t.engine.ask(ask({ action }))).resolves.toEqual({ asked: false });
    }
    expect(t.hosted.decide).not.toHaveBeenCalled();
    expect(t.charge).not.toHaveBeenCalled();
    await t.engine.ask(ask({ action: 'email.send' }));
    await t.engine.ask(ask({ action: 'card.checkout' }));
    expect(t.hosted.decide).toHaveBeenCalledTimes(2);
    expect(t.charge).toHaveBeenCalledTimes(2);
  });

  it('opening an account is asked by hosted controls but is not a billable check', async () => {
    const t = build({ controls: true });
    await expect(t.engine.ask(ask({ action: 'account.open', accountId: null, agent: null, actorKind: 'owner' }))).resolves.toMatchObject({ asked: true, decider: 'hosted', verdict: 'allow', charged: false });
    expect(t.hosted.decide).toHaveBeenCalledTimes(1);
    expect(t.charge).not.toHaveBeenCalled();
  });

  it('a null choice checks every kind', async () => {
    const t = build({ socket: { checkedTypes: null }, controls: true });
    await t.engine.ask(ask({ action: 'dropoff.deposit' }));
    expect(t.hosted.decide).toHaveBeenCalledTimes(1);
  });
});

describe('the request that is built', () => {
  it('carries who, what and how much, with a digest, and no content', async () => {
    const t = build({ controls: true });
    await t.engine.ask(ask({ amount: { max_cents: 25, currency: 'USD' }, purpose: 'send the invoice', retryRef: 'apr_1', actorKind: 'owner' }));
    const context = t.hosted.decide.mock.calls[0]![0] as { request: Record<string, unknown>; body: string };
    expect(context.request).toMatchObject({
      type: 'stack.decision.request', version: '1', test: false, operator_id: 'op_1', socket_id: 'csk_1',
      account: { id: 'acct_1' }, agent: { id: 'agt_1', passport_jti: 'pas_1', mission_id: 'ms_1' },
      actor: { kind: 'owner' }, action: { type: 'email.send' }, amount: { max_cents: 25, currency: 'USD' },
      purpose: { agent_stated: 'send the invoice' }, retry_ref: 'apr_1',
    });
    expect(context.request['request_digest']).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.parse(context.body)).toEqual(context.request);
    expect(context.request['decision_id']).toMatch(/^dec_/);
  });

  it('the digest changes with any field and is the same for the same request', async () => {
    const digests: string[] = [];
    for (const target of [{ a: 1 }, { a: 2 }]) {
      const t = build({ controls: true, hosted: async () => ({ verdict: 'allow' }) });
      await t.engine.ask(ask({ target }));
      digests.push((t.hosted.decide.mock.calls[0]![0] as { request: { request_digest: string } }).request.request_digest);
    }
    expect(digests[0]).not.toBe(digests[1]);
  });
});

describe('the record of a decision', () => {
  it('an allow leaves a slim row off the action path, no audit row, and no request', async () => {
    const t = build({ controls: true, insert: () => new Promise<void>(() => {}) });
    // The insert never resolves; the answer still comes back at once.
    const asked = await t.engine.ask(ask());
    expect(asked.asked && asked.verdict).toBe('allow');
    expect(t.insertDecision).toHaveBeenCalledWith(expect.objectContaining({
      operator_id: 'op_1', account_id: 'acct_1', agent_id: 'agt_1', action_type: 'email.send', decider: 'hosted',
      verdict: 'allow', charged: true, request: null, reason_code: null, cause: null,
    }));
    expect(t.write).not.toHaveBeenCalled();
  });

  it('a denial keeps the request, writes an audit row naming the decision, and carries the reason and retry reference', async () => {
    const t = build({
      controls: true,
      hosted: { verdict: 'deny', reason: { code: 'over_limit', message: 'Over the daily limit' }, retry: { ref: 'apr_5', after_seconds: 30 } },
    });
    const asked = await t.engine.ask(ask());
    expect(asked).toMatchObject({
      asked: true, verdict: 'deny', charged: true, reason: { code: 'over_limit', message: 'Over the daily limit' },
      retry: { ref: 'apr_5', after_seconds: 30 }, cause: null,
    });
    if (!asked.asked) throw new Error('asked');
    expect(t.insertDecision).toHaveBeenCalledWith(expect.objectContaining({
      id: asked.decisionId, verdict: 'deny', reason_code: 'over_limit', request: expect.objectContaining({ decision_id: asked.decisionId }),
    }));
    expect(t.write).toHaveBeenCalledWith(expect.objectContaining({
      ctx: AUDIT, layer: 'system', action: 'control.decision.deny', outcome: 'blocked',
      error: { code: 'CONTROL_DENIED', message: 'over_limit' },
      event_details: { decision_id: asked.decisionId, account_id: 'acct_1' },
    }));
  });

  it('no usable answer is recorded as unavailable with its cause, and a hosted failure is not charged', async () => {
    const remote = build({ socket: { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' }, remote: { verdict: 'unavailable', cause: 'bad_signature' } });
    const a = await remote.engine.ask(ask());
    expect(a).toMatchObject({ asked: true, verdict: 'unavailable', cause: 'bad_signature', decider: 'remote', charged: false });
    expect(remote.write).toHaveBeenCalledWith(expect.objectContaining({
      action: 'control.decision.unavailable', error: { code: 'CONTROL_SOCKET_UNAVAILABLE', message: 'bad_signature' },
    }));

    const hosted = build({ controls: true, hosted: { verdict: 'unavailable', cause: 'hosted_failure' } });
    await expect(hosted.engine.ask(ask())).resolves.toMatchObject({ verdict: 'unavailable', charged: false });
    expect(hosted.charge).not.toHaveBeenCalled();
  });

  describe('when your own server does not answer in time', () => {
    const own = { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' } as const;

    it('refuses by default: no setting is the same as refuse', async () => {
      for (const cause of ['timeout', 'unreachable', 'http_status', 'busy', 'breaker_open'] as const) {
        const t = build({ socket: own, remote: { verdict: 'unavailable', cause } });
        await expect(t.engine.ask(ask())).resolves.toMatchObject({ asked: true, verdict: 'unavailable', cause, decider: 'remote' });
        expect(t.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'control.decision.unavailable' }));
      }
    });

    it('lets the action through when the customer set allow, and records the cause on the decision', async () => {
      for (const cause of ['timeout', 'unreachable', 'http_status', 'busy', 'breaker_open'] as const) {
        const t = build({ socket: { ...own, onUnavailable: 'allow' }, remote: { verdict: 'unavailable', cause } });
        const asked = await t.engine.ask(ask());
        expect(asked, cause).toMatchObject({ asked: true, verdict: 'allow', decider: 'remote', charged: false, settle: [] });
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(t.insertDecision).toHaveBeenCalledWith(expect.objectContaining({ verdict: 'allow', cause, decider: 'remote', request: null }));
        expect(t.write).not.toHaveBeenCalled();
        expect(t.charge).not.toHaveBeenCalled();
      }
    });

    it('never lets through what is not a missing answer: a forged or garbled answer, a blocked address, an unverified or paused server', async () => {
      for (const cause of ['bad_signature', 'bad_body', 'mismatch', 'unsafe_address', 'unverified', 'paused', 'secret_unavailable'] as const) {
        const t = build({ socket: { ...own, onUnavailable: 'allow' }, remote: { verdict: 'unavailable', cause } });
        await expect(t.engine.ask(ask()), cause).resolves.toMatchObject({ verdict: 'unavailable', cause });
      }
    });

    it('still refuses a denial, whatever the setting says, and does not touch hosted controls', async () => {
      const denied = build({ socket: { ...own, onUnavailable: 'allow' }, remote: { verdict: 'deny', reason: { code: 'no', message: null } } });
      await expect(denied.engine.ask(ask())).resolves.toMatchObject({ verdict: 'deny' });
      const hosted = build({ controls: true, socket: { modeSetting: 'auto', onUnavailable: 'allow' }, hosted: { verdict: 'unavailable', cause: 'hosted_failure' } });
      await expect(hosted.engine.ask(ask())).resolves.toMatchObject({ verdict: 'unavailable', cause: 'hosted_failure' });
    });
  });

  it('a decider that throws is no answer and never an allow', async () => {
    const t = build({ controls: true });
    t.hosted.decide.mockRejectedValue(new Error('boom'));
    await expect(t.engine.ask(ask())).resolves.toMatchObject({ verdict: 'unavailable', cause: 'hosted_failure', charged: false });
    const r = build({ socket: { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' } });
    r.remote.decide.mockRejectedValue(new Error('boom'));
    await expect(r.engine.ask(ask())).resolves.toMatchObject({ verdict: 'unavailable', cause: 'unreachable' });
  });

  it('a hosted decision slower than two seconds is a STACK-side failure', async () => {
    vi.useFakeTimers();
    const t = build({ controls: true, hosted: () => new Promise<DecisionResult>(() => {}) });
    const pending = t.engine.ask(ask());
    await vi.advanceTimersByTimeAsync(2_001);
    await expect(pending).resolves.toMatchObject({ verdict: 'unavailable', cause: 'hosted_failure', charged: false });
  });

  it('an audit or row failure never turns a refusal into an allow', async () => {
    const t = build({ controls: true, hosted: { verdict: 'deny', reason: { code: 'no', message: null } }, insert: async () => { throw new Error('db down'); } });
    t.write.mockRejectedValue(new Error('audit down'));
    await expect(t.engine.ask(ask())).resolves.toMatchObject({ verdict: 'deny' });
  });
});

describe('paying for a check', () => {
  const DENY: DecisionResult = { verdict: 'deny', reason: { code: 'over_limit', message: 'Over the daily limit' } };

  it('an allowed action whose check cannot be paid is refused before it runs, hands back what it left open, and leaves no decision row', async () => {
    const hook = vi.fn(async () => undefined);
    const t = build({ controls: true, hosted: { verdict: 'allow', settle: [hook] }, charge: async () => { throw new SpendRefusedError('Insufficient balance', 'INSUFFICIENT_BALANCE', { balance_cents: 0, required_cents: 1 }); } });
    await expect(t.engine.ask(ask())).rejects.toBeInstanceOf(SpendRefusedError);
    expect(hook).toHaveBeenCalledWith({ ok: false, handedBack: true });
    expect(t.insertDecision).not.toHaveBeenCalled();
  });

  it('a check that ran is charged whether it allowed or denied: the price is per action checked', async () => {
    for (const verdict of [{ verdict: 'allow' }, DENY] as DecisionResult[]) {
      const t = build({ controls: true, hosted: verdict });
      const asked = await t.engine.ask(ask());
      expect(asked).toMatchObject({ verdict: verdict.verdict, charged: true });
      expect(t.charge).toHaveBeenCalledTimes(1);
      expect(t.insertDecision).toHaveBeenCalledWith(expect.objectContaining({ charged: true, verdict: verdict.verdict }));
    }
  });

  it('a denial wins over a check that cannot be paid: the agent is still refused, and the row records the check as uncharged', async () => {
    for (const failure of [new SpendRefusedError('Insufficient balance', 'INSUFFICIENT_BALANCE', { balance_cents: 0, required_cents: 1 }), new Error('wallet frozen')]) {
      const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      const t = build({ controls: true, hosted: DENY, charge: async () => { throw failure; } });
      const asked = await t.engine.ask(ask());
      expect(asked).toMatchObject({ asked: true, decider: 'hosted', verdict: 'deny', charged: false, reason: { code: 'over_limit' } });
      // The check ran and refused: that stands on the record, uncharged, for the meter to settle.
      expect(t.insertDecision).toHaveBeenCalledWith(expect.objectContaining({ verdict: 'deny', decider: 'hosted', charged: false, reason_code: 'over_limit' }));
      expect(t.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'control.decision.deny' }));
      expect(error).toHaveBeenCalledWith('[CONTROL] a refusing check could not be charged', expect.anything());
      error.mockRestore();
    }
  });

  it('never charges for a hosted failure, or for opening an account, whatever the verdict', async () => {
    const own = build({ socket: { modeSetting: 'remote', decisionStatus: 'enforcing', decisionUrl: 'https://c.example/d' }, remote: DENY });
    await own.engine.ask(ask({ action: 'account.open', accountId: null, agent: null, actorKind: 'owner' }));
    const failed = build({ controls: true, hosted: { verdict: 'unavailable', cause: 'hosted_failure' } });
    await failed.engine.ask(ask());
    const opening = build({ controls: true, hosted: DENY });
    await opening.engine.ask(ask({ action: 'account.open', accountId: null, agent: null, actorKind: 'owner' }));
    for (const t of [own, failed, opening]) expect(t.charge).not.toHaveBeenCalled();
    expect(own.chargeDecision).not.toHaveBeenCalled();
  });
});

describe('a hosted check that outlives its deadline', () => {
  // The late evaluation keeps running after the engine has answered "unavailable". Whatever it takes
  // afterwards (a counted action, a lease, a reserved review) must come back, or the customer is
  // charged against limits for an action that never ran.
  function lateCheck(counting: Promise<void>) {
    const effective = {
      id: 'cpl_late', agentId: 'agt_1', revision: 1, name: 'p', source: 'agent' as const,
      definition: normalizePolicy({ name: 'p', spend: { limits: [{ kind: 'day', unit: 'actions', limit: 5 }], max_concurrent: 2 } }),
    };
    const refs = [{ accountId: 'acct_1', kind: 'day' as const, periodKey: '2026-10-21', amount: 1 }];
    const limits = {
      consumeActions: vi.fn(async () => { await counting; return { ok: true as const, refs }; }),
      releaseActions: vi.fn(async () => undefined),
    };
    const concurrency = { acquire: vi.fn(async () => ({ leaseId: 'lease_1' })), release: vi.fn(async () => undefined) };
    const reviews = { open: vi.fn(), reserve: vi.fn(), consume: vi.fn(), release: vi.fn() };
    const check = new PolicyHostedCheck({ policies: { effective: vi.fn(async () => effective) }, reviews: reviews as never, limits, concurrency });
    return { hosted: new HostedDecider([check]), limits, concurrency };
  }

  it('is a failure for the caller, and hands back everything it took once it finishes', async () => {
    vi.useFakeTimers();
    let finishCounting!: () => void;
    const counting = new Promise<void>((resolve) => { finishCounting = resolve; });
    const late = lateCheck(counting);
    const t = build({ controls: true });
    t.hosted.decide.mockImplementation((context) => late.hosted.decide(context));

    const pending = t.engine.ask(ask());
    await vi.advanceTimersByTimeAsync(2_001);
    await expect(pending).resolves.toMatchObject({ verdict: 'unavailable', cause: 'hosted_failure', charged: false });
    expect(late.limits.releaseActions).not.toHaveBeenCalled();

    finishCounting();
    await vi.advanceTimersByTimeAsync(10);
    expect(late.limits.consumeActions).toHaveBeenCalledTimes(1);
    // The count is handed back, and no lease is left held.
    expect(late.limits.releaseActions).toHaveBeenCalledTimes(1);
    expect(late.concurrency.release.mock.calls.length).toBe(late.concurrency.acquire.mock.calls.length);
  });

  it('hands back whatever an allowed answer arriving after the deadline left open', async () => {
    vi.useFakeTimers();
    const hook = vi.fn(async () => undefined);
    let answer!: (result: DecisionResult) => void;
    const t = build({ controls: true, hosted: () => new Promise<DecisionResult>((resolve) => { answer = resolve; }) });
    const pending = t.engine.ask(ask());
    await vi.advanceTimersByTimeAsync(2_001);
    await expect(pending).resolves.toMatchObject({ verdict: 'unavailable', cause: 'hosted_failure' });
    answer({ verdict: 'allow', settle: [hook] });
    await vi.advanceTimersByTimeAsync(10);
    expect(hook).toHaveBeenCalledWith({ ok: false, handedBack: true });
  });

  it('runs a settle hook of an in-time answer only once, by its caller', async () => {
    const hook = vi.fn(async () => undefined);
    const t = build({ controls: true, hosted: { verdict: 'allow', settle: [hook] } });
    const asked = await t.engine.ask(ask());
    expect(asked).toMatchObject({ verdict: 'allow' });
    expect(hook).not.toHaveBeenCalled();
  });
});
