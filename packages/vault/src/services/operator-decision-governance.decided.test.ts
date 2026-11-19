import { describe, expect, it, vi } from 'vitest';
import { OperatorDecisionService, type GovernanceDecided } from './operator-decision-service.js';

// A governance decision is announced to what waited on it (a held action's review) only after it committed, with what
// it was about; a failure there never undoes it.

const owner = { kind: 'operator_owner' as const, operator_id: 'op_one' };

function fixture(options: { applyFails?: boolean; hookFails?: boolean } = {}) {
  let status = 'pending';
  const seen: Array<GovernanceDecided & { statusAtCall: string }> = [];
  const source = {
    id: 'gvr_one', operator_id: 'op_one', action: 'control_review', resource_id: 'crv_one', summary: 'Pay a merchant',
    requested_via: 'operator_key', status: 'pending', expires_at: new Date(1_800_000_000_000),
    created_at: new Date(1_700_000_000_000), decided_at: null, mission_id: null, agent_id: null,
  };
  const repo = {
    transaction: async (callback: (ctx: { decisions: Record<string, unknown>; claimPersistence: { insert: unknown } }) => Promise<unknown>) => {
      let pendingStatus = status;
      const decisions = {
        findGovernanceApprovalSource: vi.fn(async () => ({ ...source, status })),
        applyGovernanceDecision: vi.fn(async (input: { status: string }) => {
          if (options.applyFails) throw new Error('database went away');
          pendingStatus = input.status;
          return { ...source, status: input.status };
        }),
        findByIdempotencyKey: vi.fn(async () => null),
        create: vi.fn(async (row: Record<string, unknown>) => row),
        createSources: vi.fn(async () => undefined),
      };
      const result = await callback({ decisions, claimPersistence: { insert: vi.fn() } });
      status = pendingStatus;
      return result;
    },
    findByIdempotencyKey: vi.fn(async () => null),
  };
  const service = new OperatorDecisionService({
    repo: repo as never,
    claimRegistry: { registerClaim: vi.fn(async () => ({ claimId: 'pc_1', envelopeCose: 'cose', subject: 's' })) } as never,
    claimVerifier: { verifyClaim: vi.fn() } as never,
    audit: { write: vi.fn(async () => 'ae_1') } as never,
    onGovernanceDecided: async (decided) => {
      seen.push({ ...decided, statusAtCall: status });
      if (options.hookFails) throw new Error('reviews are down');
    },
    now: () => 1_766_000_000_000,
    generateId: () => 'odec_1',
  });
  return { service, seen };
}

describe('a governance decision reaches what waited on it', () => {
  it('after the decision committed, with the approval, its action, what it was for and the decision', async () => {
    for (const decision of ['approve', 'reject'] as const) {
      const { service, seen } = fixture();
      await service.decideGovernance({ operatorId: 'op_one', approvalId: 'gvr_one', decision, authoredBy: owner });
      expect(seen).toEqual([{
        operatorId: 'op_one', approvalId: 'gvr_one', action: 'control_review', resourceId: 'crv_one', decision,
        statusAtCall: decision === 'approve' ? 'approved' : 'rejected',
      }]);
    }
  });

  it('a decision that never committed is announced to nobody', async () => {
    const { service, seen } = fixture({ applyFails: true });
    await expect(service.decideGovernance({ operatorId: 'op_one', approvalId: 'gvr_one', decision: 'approve', authoredBy: owner }))
      .rejects.toThrow();
    expect(seen).toEqual([]);
  });

  it('a failure after the commit is logged and the decision stands', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { service } = fixture({ hookFails: true });
    await expect(service.decideGovernance({ operatorId: 'op_one', approvalId: 'gvr_one', decision: 'reject', authoredBy: owner }))
      .resolves.toBeDefined();
    expect(log).toHaveBeenCalled();
    log.mockRestore();
  });
});
