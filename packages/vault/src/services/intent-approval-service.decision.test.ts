import { describe, expect, it, vi } from 'vitest';
import type { DecisionReachedEvent } from '@stack/shared';
import { IntentApprovalService } from './intent-approval-service.js';

// An intent approval or a fleet review that ends tells the agent waiting on it how: approved, rejected or expired, once,
// only from the call that moved the row, and never at the cost of the decision.

const NOW = new Date('2026-11-03T12:00:00.000Z');

function pendingRow(over: Record<string, unknown> = {}) {
  return {
    id: 'iap_1', operator_id: 'op_1', agent_id: 'agt_1', fleet_policy_id: null, status: 'pending',
    expires_at: new Date(Date.now() + 3_600_000), decided_at: null, ...over,
  };
}

function build(repo: Record<string, unknown>, onDecision?: (event: DecisionReachedEvent) => Promise<void>) {
  const decisions: DecisionReachedEvent[] = [];
  const service = new IntentApprovalService({
    repo: repo as never,
    passportService: {} as never,
    claimRegistry: {} as never,
    onDecision: onDecision ?? (async (event) => { decisions.push(event); }),
  });
  return { service, decisions };
}

describe('the end of an intent approval reaches its agent', () => {
  it('approved and rejected are told to the agent that asked, with the time of the decision', async () => {
    for (const result of ['approved', 'rejected'] as const) {
      const { service, decisions } = build({
        findById: async () => pendingRow(),
        markDecided: async () => pendingRow({ status: result, decided_at: NOW }),
      });
      if (result === 'approved') await service.approve({ id: 'iap_1', operatorId: 'op_1' });
      else await service.reject({ id: 'iap_1', operatorId: 'op_1' });
      expect(decisions).toEqual([{ operatorId: 'op_1', agentId: 'agt_1', kind: 'intent_approval', itemId: 'iap_1', result, occurredAt: NOW }]);
    }
  });

  it('a review a fleet rule asked for is told as a fleet review', async () => {
    const { service, decisions } = build({
      findById: async () => pendingRow({ fleet_policy_id: 'fpl_1' }),
      markDecided: async () => pendingRow({ fleet_policy_id: 'fpl_1', status: 'rejected', decided_at: NOW }),
    });
    await service.reject({ id: 'iap_1', operatorId: 'op_1' });
    expect(decisions.map((d) => [d.kind, d.result])).toEqual([['fleet_review', 'rejected']]);
  });

  it('a decision that lost the race tells nobody', async () => {
    const { service, decisions } = build({ findById: async () => pendingRow(), markDecided: async () => null });
    await expect(service.approve({ id: 'iap_1', operatorId: 'op_1' })).rejects.toThrow();
    expect(decisions).toEqual([]);
  });

  it('the sweep expires what nobody decided in time and tells each agent once', async () => {
    const expirePending = vi.fn(async () => [
      { id: 'iap_1', operator_id: 'op_1', agent_id: 'agt_1', fleet_policy_id: null },
      { id: 'iap_2', operator_id: 'op_1', agent_id: 'agt_2', fleet_policy_id: 'fpl_1' },
    ]);
    const { service, decisions } = build({ expirePending });
    expect(await service.expireDue(NOW, 25)).toBe(2);
    expect(expirePending).toHaveBeenCalledWith(NOW, 25);
    expect(decisions.map((d) => [d.itemId, d.agentId, d.kind, d.result])).toEqual([
      ['iap_1', 'agt_1', 'intent_approval', 'expired'],
      ['iap_2', 'agt_2', 'fleet_review', 'expired'],
    ]);
  });

  it('a hook that fails is logged and the decision stands', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { service } = build(
      { findById: async () => pendingRow(), markDecided: async () => pendingRow({ status: 'approved', decided_at: NOW }) },
      async () => { throw new Error('wakes are down'); },
    );
    await expect(service.approve({ id: 'iap_1', operatorId: 'op_1' })).resolves.toMatchObject({ status: 'approved' });
    expect(log).toHaveBeenCalled();
    log.mockRestore();
  });
});
