import { describe, expect, it, vi } from 'vitest';
import type { ControlReviewRow } from '@stack/shared';
import { ControlReviewService, ownerHashOf, reviewApprovalPayload } from './control-review-service.js';

const row = (over: Partial<ControlReviewRow> = {}): ControlReviewRow => ({
  id: 'crv_1', operator_id: 'op_1', account_id: 'acct_1', agent_id: 'agt_1', policy_id: 'cpl_1', policy_revision: 2,
  rule_section: 'review', rule_id: 'over_cents', action_type: 'card.checkout', call_digest: 'c'.repeat(64), summary: 'x',
  governance_approval_id: 'gvr_1', status: 'pending', consuming_owner_hash: null, expires_at: new Date(Date.now() + 3_600_000),
  decided_at: null, created_at: new Date(), amount_cents: null, payment_surface: null, ...over,
});

const input = {
  operatorId: 'op_1', accountId: 'acct_1', agentId: 'agt_1', policy: { id: 'cpl_1', revision: 2 }, rule: { section: 'review', id: 'over_cents' },
  action: 'card.checkout', callDigest: 'c'.repeat(64), summary: 'Your agent wants to pay a merchant.',
};

function build(repo: Record<string, unknown>, governance: Record<string, unknown>) {
  return new ControlReviewService({ repo: repo as never, governance: governance as never });
}

describe('opening a held action', () => {
  it('creates the approval a person sees, bound to this review and this exact call', async () => {
    const createPending = vi.fn(async () => ({ row: { id: 'gvr_new', expires_at: new Date(Date.now() + 86_400_000) }, approvalUrl: 'https://dash.example/app/approve/gvr_new', partner: false }));
    const insert = vi.fn(async (values: { id: string }) => ({ row: row({ id: values.id, governance_approval_id: 'gvr_new' }), created: true }));
    const service = build({ findLive: async () => null, insert }, { createPending, approvalUrl: (id: string) => `https://dash.example/app/approve/${id}`, decide: vi.fn() });
    const opened = await service.open(input);
    expect(opened.approvalUrl).toBe('https://dash.example/app/approve/gvr_new');
    const asked = (createPending.mock.calls[0] as unknown as [{ action: string; resourceId: string; payload: Record<string, unknown>; summary: string }])[0];
    expect(asked.action).toBe('control_review');
    expect(asked.resourceId).toBe(opened.review.id);
    expect(asked.payload).toEqual(reviewApprovalPayload({ reviewId: opened.review.id, callDigest: 'c'.repeat(64), policyId: 'cpl_1', policyRevision: 2 }));
    expect(asked.summary).toBe('Your agent wants to pay a merchant.');
  });

  it('returns the review already open for exactly this call, and creates nothing', async () => {
    const createPending = vi.fn();
    const service = build({ findLive: async () => row() }, { createPending, approvalUrl: (id: string) => `https://dash.example/app/approve/${id}` });
    const opened = await service.open(input);
    expect(opened.review.id).toBe('crv_1');
    expect(opened.approvalUrl).toBe('https://dash.example/app/approve/gvr_1');
    expect(createPending).not.toHaveBeenCalled();
  });

  it('when a concurrent identical call opened it first, the approval it just made is closed, not left on the approve page', async () => {
    const decide = vi.fn(async () => undefined);
    const service = build(
      { findLive: async () => null, insert: async () => ({ row: row(), created: false }) },
      {
        createPending: async () => ({ row: { id: 'gvr_orphan', expires_at: new Date() }, approvalUrl: 'https://dash.example/app/approve/gvr_orphan', partner: false }),
        approvalUrl: (id: string) => `https://dash.example/app/approve/${id}`,
        decide,
      },
    );
    const opened = await service.open(input);
    expect(opened.review.id).toBe('crv_1');
    expect(opened.approvalUrl).toBe('https://dash.example/app/approve/gvr_1');
    expect(decide).toHaveBeenCalledWith('gvr_orphan', 'op_1', 'reject');
  });
});

describe('the retry', () => {
  const approvedRow = row({ status: 'approved' });
  const reserve = (over: Record<string, unknown> = {}) => build(
    { get: async () => approvedRow, reserve: async () => row({ status: 'consuming', consuming_owner_hash: ownerHashOf('op-1') }), ...over },
    { findForOperator: async () => undefined },
  );

  it('reserves an approved review for the operation, once', async () => {
    const reserved = await reserve().reserve({ operatorId: 'op_1', ref: 'crv_1', agentId: 'agt_1', callDigest: 'c'.repeat(64), operation: 'op-1' });
    expect(reserved).toMatchObject({ state: 'reserved', ownerHash: ownerHashOf('op-1') });
    const lost = await reserve({ reserve: async () => null }).reserve({ operatorId: 'op_1', ref: 'crv_1', agentId: 'agt_1', callDigest: 'c'.repeat(64), operation: 'op-2' });
    expect(lost.state).toBe('in_use');
  });

  it('is covered only for the agent and the call it was opened for, within its own customer', async () => {
    const service = reserve();
    expect((await service.reserve({ operatorId: 'op_1', ref: 'crv_1', agentId: 'agt_other', callDigest: 'c'.repeat(64), operation: 'x' })).state).toBe('mismatch');
    expect((await service.reserve({ operatorId: 'op_1', ref: 'crv_1', agentId: 'agt_1', callDigest: 'd'.repeat(64), operation: 'x' })).state).toBe('mismatch');
    expect((await reserve({ get: async () => null }).reserve({ operatorId: 'op_other', ref: 'crv_1', agentId: 'agt_1', callDigest: 'c'.repeat(64), operation: 'x' })).state).toBe('unknown');
  });

  it('a status it does not know is never an approval', async () => {
    const service = reserve({ get: async () => row({ status: 'something_new' }) });
    expect((await service.reserve({ operatorId: 'op_1', ref: 'crv_1', agentId: 'agt_1', callDigest: 'c'.repeat(64), operation: 'x' })).state).toBe('unknown');
  });

  it('a lapsed approval expires and is not reserved', async () => {
    const lapsed = row({ status: 'approved', expires_at: new Date(Date.now() - 1_000) });
    const expireDue = vi.fn(async () => 1);
    const reload = row({ status: 'expired' });
    let reads = 0;
    const service = build(
      { get: async () => (reads++ === 0 ? lapsed : reload), expireDue, reserve: vi.fn() },
      { findForOperator: async () => undefined },
    );
    expect((await service.reserve({ operatorId: 'op_1', ref: 'crv_1', agentId: 'agt_1', callDigest: 'c'.repeat(64), operation: 'x' })).state).toBe('expired');
    expect(expireDue).toHaveBeenCalled();
  });
});
