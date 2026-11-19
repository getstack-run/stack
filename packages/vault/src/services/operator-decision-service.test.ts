import { describe, expect, it, vi } from 'vitest';
import { ConflictError, ForbiddenError, NotFoundError } from '@stack/shared';
import { OperatorDecisionService } from './operator-decision-service.js';

type Checkout = {
  id: string;
  operator_id: string;
  mission_id: string | null;
  agent_id: string;
  review_status: string;
};

function fixture(options: {
  checkouts?: Checkout[];
  effectFails?: boolean;
  claimFails?: boolean;
  auditFailsOnce?: boolean;
} = {}) {
  const checkouts = options.checkouts ?? [{
    id: 'cout_one',
    operator_id: 'op_one',
    mission_id: 'ms_one',
    agent_id: 'agt_one',
    review_status: 'flagged',
  }];
  const committed = {
    effects: 0,
    decisions: new Map<string, Record<string, unknown>>(),
  };
  const registerClaim = vi.fn(async (_input: Record<string, unknown>) => {
    if (options.claimFails) throw new Error('claim failed');
    return { claimId: 'pc_decision', envelopeCose: 'cose', subject: 'stack://operator/op_one' };
  });
  let auditAttempts = 0;
  const auditWrite = vi.fn(async () => {
    auditAttempts += 1;
    if (options.auditFailsOnce && auditAttempts === 1) throw new Error('audit failed');
    return 'ae_one';
  });
  const findByIdempotencyKey = async (_operatorId: string, key: string) =>
    committed.decisions.get(key) ?? null;

  const repo = {
    findByIdempotencyKey,
    transaction: async (callback: (ctx: Record<string, unknown>) => Promise<unknown>) => {
      let pendingEffects = 0;
      const pendingDecisions = new Map<string, Record<string, unknown>>();
      const decisions = {
        findByIdempotencyKey,
        findCheckoutSources: async (ids: string[]) => checkouts.filter((row) => ids.includes(row.id)),
        findSecurityEventSources: async () => [],
        applyCheckoutEffect: async () => {
          if (options.effectFails) throw new Error('effect failed');
          pendingEffects += 1;
        },
        applySecurityEventEffect: async () => { pendingEffects += 1; },
        create: async (row: Record<string, unknown>) => {
          pendingDecisions.set(String(row.idempotency_key), row);
          return row;
        },
        createSources: async () => undefined,
      };
      const result = await callback({
        decisions,
        claimPersistence: { insert: vi.fn() },
      });
      committed.effects += pendingEffects;
      for (const [key, value] of pendingDecisions) committed.decisions.set(key, value);
      return result;
    },
  };

  const service = new OperatorDecisionService({
    repo: repo as never,
    claimRegistry: { registerClaim } as never,
    claimVerifier: { verifyClaim: vi.fn() } as never,
    audit: { write: auditWrite } as never,
    now: () => 1_766_000_000_000,
    generateId: () => 'odec_one',
  });

  return { service, registerClaim, auditWrite, committed };
}

const owner = { kind: 'operator_owner' as const, operator_id: 'op_one' };

describe('OperatorDecisionService', () => {
  it('applies one exact mission effect and signs only server-derived facts', async () => {
    const { service, registerClaim, committed } = fixture();
    const result = await service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_approved',
      sourceIds: ['cout_one'],
    });

    expect(result).toMatchObject({
      decision_id: 'odec_one',
      claim_id: 'pc_decision',
      mission_id: 'ms_one',
      action: 'checkout_approved',
      effect: 'checkout_released',
    });
    expect(committed.effects).toBe(1);
    expect(registerClaim).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_one',
      claimType: 'operator_decision',
      subjectOverride: 'operator',
      payload: expect.objectContaining({
        mission_ref: 'ms_one',
        operator_id: 'op_one',
        target_agent_id: 'agt_one',
        source_refs: expect.objectContaining({ checkout_ids: ['cout_one'] }),
      }),
    }), expect.any(Object));
  });

  it.each([
    {
      name: 'foreign source',
      rows: [{ id: 'cout_one', operator_id: 'op_foreign', mission_id: 'ms_one', agent_id: 'agt_one', review_status: 'flagged' }],
      error: NotFoundError,
    },
    {
      name: 'unbound source',
      rows: [{ id: 'cout_one', operator_id: 'op_one', mission_id: null, agent_id: 'agt_one', review_status: 'flagged' }],
      error: ForbiddenError,
    },
    {
      name: 'mixed missions',
      rows: [
        { id: 'cout_one', operator_id: 'op_one', mission_id: 'ms_one', agent_id: 'agt_one', review_status: 'flagged' },
        { id: 'cout_two', operator_id: 'op_one', mission_id: 'ms_two', agent_id: 'agt_one', review_status: 'flagged' },
      ],
      error: ForbiddenError,
    },
  ])('fails closed for $name', async ({ rows, error }) => {
    const { service, registerClaim, committed } = fixture({ checkouts: rows });
    await expect(service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_approved',
      sourceIds: rows.map((row) => row.id),
    })).rejects.toBeInstanceOf(error);
    expect(registerClaim).not.toHaveBeenCalled();
    expect(committed.effects).toBe(0);
  });

  it('rejects duplicate source ids before any effect', async () => {
    const { service, registerClaim, committed } = fixture();
    await expect(service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_approved',
      sourceIds: ['cout_one', 'cout_one'],
    })).rejects.toBeInstanceOf(ForbiddenError);
    expect(registerClaim).not.toHaveBeenCalled();
    expect(committed.effects).toBe(0);
  });

  it.each([
    ['approved clean checkout', 'checkout_approved' as const, 'clean'],
    ['blocked checkout block retry', 'checkout_blocked' as const, 'blocked'],
    ['pending future-policy checkout', 'future_critical_block_enabled' as const, 'pending'],
  ])('rejects a stale %s', async (_name, action, reviewStatus) => {
    const { service, registerClaim, committed } = fixture({ checkouts: [{
      id: 'cout_one',
      operator_id: 'op_one',
      mission_id: 'ms_one',
      agent_id: 'agt_one',
      review_status: reviewStatus,
    }] });
    await expect(service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action,
      sourceIds: ['cout_one'],
    })).rejects.toBeInstanceOf(ConflictError);
    expect(registerClaim).not.toHaveBeenCalled();
    expect(committed.effects).toBe(0);
  });

  it('signs one combined decision for current clearance and future warning blocking', async () => {
    const { service, registerClaim, committed } = fixture();
    const result = await service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'future_warning_block_enabled',
      sourceIds: ['cout_one'],
    });
    expect(result.effect).toBe('checkouts_released_and_agent_warning_policy_set_to_block');
    expect(result.effect_scope).toBe('agent_global');
    expect(registerClaim).toHaveBeenCalledTimes(1);
    expect(committed.effects).toBe(1);
  });

  it('marks checkout blocking as an agent-global effect', async () => {
    const { service } = fixture();
    const result = await service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_blocked',
      sourceIds: ['cout_one'],
    });
    expect(result.effect_scope).toBe('agent_global');
  });

  it('creates no claim when the operational effect fails', async () => {
    const { service, registerClaim, committed } = fixture({ effectFails: true });
    await expect(service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_blocked',
      sourceIds: ['cout_one'],
    })).rejects.toThrow('effect failed');
    expect(registerClaim).not.toHaveBeenCalled();
    expect(committed.effects).toBe(0);
  });

  it('rolls back the operational effect when claim creation fails', async () => {
    const { service, committed } = fixture({ claimFails: true });
    await expect(service.decide({
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_blocked',
      sourceIds: ['cout_one'],
    })).rejects.toThrow('claim failed');
    expect(committed.effects).toBe(0);
  });

  it('returns the same decision on an exact retry', async () => {
    const { service, registerClaim, committed } = fixture();
    const request = {
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_approved' as const,
      sourceIds: ['cout_one'],
    };
    const first = await service.decide(request);
    const second = await service.decide(request);
    expect(second.claim_id).toBe(first.claim_id);
    expect(registerClaim).toHaveBeenCalledTimes(1);
    expect(committed.effects).toBe(1);
  });

  it('rolls back signed state when the required audit write fails and permits a clean retry', async () => {
    const { service, auditWrite, committed } = fixture({ auditFailsOnce: true });
    const request = {
      operatorId: 'op_one',
      authoredBy: owner,
      action: 'checkout_approved' as const,
      sourceIds: ['cout_one'],
      auditContext: {
        trace_id: 'req_one',
        span_id: 'odec_one',
        operator_id: 'op_one',
        agent_id: 'agt_one',
        passport_jti: 'none',
      },
    };
    await expect(service.decide(request as never)).rejects.toThrow('audit failed');
    expect(committed.effects).toBe(0);
    await expect(service.decide(request as never)).resolves.toBeDefined();
    expect(committed.effects).toBe(1);
    expect(auditWrite).toHaveBeenCalledTimes(2);
  });
});
