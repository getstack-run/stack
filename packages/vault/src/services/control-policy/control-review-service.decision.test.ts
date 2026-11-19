import { describe, expect, it, vi } from 'vitest';
import type { ControlReviewRow, DecisionReachedEvent } from '@stack/shared';
import { ControlReviewService } from './control-review-service.js';

// A held action's review tells the agent waiting on it how it ended: approved, rejected or expired, once, only from the
// call that moved the row, and never at the cost of the decision.

const NOW = new Date('2026-11-03T12:00:00.000Z');

const row = (over: Partial<ControlReviewRow> = {}): ControlReviewRow => ({
  id: 'crv_1', operator_id: 'op_1', account_id: 'acct_1', agent_id: 'agt_1', policy_id: 'cpl_1', policy_revision: 2,
  rule_section: 'review', rule_id: 'over_cents', action_type: 'card.checkout', call_digest: 'c'.repeat(64), summary: 'x',
  governance_approval_id: 'gvr_1', status: 'pending', consuming_owner_hash: null, expires_at: new Date(NOW.getTime() + 3_600_000),
  decided_at: null, created_at: NOW, amount_cents: null, payment_surface: null, ...over,
});

function build(repo: Record<string, unknown>, governance: Record<string, unknown>) {
  const decisions: DecisionReachedEvent[] = [];
  const service = new ControlReviewService({
    repo: repo as never,
    governance: governance as never,
    onDecision: async (event) => { decisions.push(event); },
    now: () => NOW,
  });
  return { service, decisions };
}

const told = (result: string) => ({ operatorId: 'op_1', agentId: 'agt_1', kind: 'control_review', itemId: 'crv_1', result, occurredAt: NOW });

describe('the end of a held action reaches its agent', () => {
  it('a person who approved: the review opens for use and the agent is told approved', async () => {
    const { service, decisions } = build(
      { approve: async () => row({ status: 'approved' }) },
      { findForOperator: async () => ({ status: 'approved' }), consume: async () => undefined },
    );
    expect((await service.sync(row())).status).toBe('approved');
    expect(decisions).toEqual([told('approved')]);
  });

  it('a person who declined, or an approval that ran out: the agent is told rejected or expired', async () => {
    for (const status of ['rejected', 'expired'] as const) {
      const { service, decisions } = build(
        { close: async () => row({ status }) },
        { findForOperator: async () => ({ status }) },
      );
      await service.sync(row());
      expect(decisions).toEqual([told(status)]);
    }
  });

  it('a review read past its time expires and tells the agent', async () => {
    const close = vi.fn(async () => row({ status: 'expired' }));
    const { service, decisions } = build({ close }, { findForOperator: vi.fn() });
    await service.sync(row({ expires_at: new Date(NOW.getTime() - 1) }));
    expect(close).toHaveBeenCalledWith('crv_1', 'expired', NOW);
    expect(decisions).toEqual([told('expired')]);
  });

  it('a call that lost the race to move the row tells nobody: the winner already did', async () => {
    const { service, decisions } = build(
      { close: async () => null, approve: async () => null, get: async () => row({ status: 'rejected' }) },
      { findForOperator: async () => ({ status: 'rejected' }) },
    );
    expect((await service.sync(row())).status).toBe('rejected');
    expect(decisions).toEqual([]);
  });

  it('a review still waiting tells nobody', async () => {
    const { service, decisions } = build({}, { findForOperator: async () => ({ status: 'pending' }) });
    await service.sync(row());
    expect(decisions).toEqual([]);
  });

  it('the sweep expires reviews nobody decided and tells each agent', async () => {
    const expirePendingDue = vi.fn(async () => [row(), row({ id: 'crv_2', agent_id: 'agt_2' })]);
    const { service, decisions } = build({ expirePendingDue }, {});
    expect(await service.expirePending(50)).toBe(2);
    expect(expirePendingDue).toHaveBeenCalledWith(NOW, 50);
    expect(decisions.map((d) => [d.itemId, d.agentId, d.result])).toEqual([['crv_1', 'agt_1', 'expired'], ['crv_2', 'agt_2', 'expired']]);
  });

  it('a decision on the held action\'s approval is carried into the review at once', async () => {
    const { service, decisions } = build(
      { get: async () => row(), close: async () => row({ status: 'rejected' }) },
      { findForOperator: async () => ({ status: 'rejected' }) },
    );
    await service.followDecision('op_1', 'crv_1');
    expect(decisions).toEqual([told('rejected')]);
  });

  it('a hook that fails is logged and never undoes the decision', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const service = new ControlReviewService({
      repo: { close: async () => row({ status: 'rejected' }) } as never,
      governance: { findForOperator: async () => ({ status: 'rejected' }) } as never,
      onDecision: async () => { throw new Error('wakes are down'); },
      now: () => NOW,
    });
    expect((await service.sync(row())).status).toBe('rejected');
    expect(log).toHaveBeenCalled();
    log.mockRestore();
  });
});
