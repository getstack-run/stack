import { describe, expect, it, vi } from 'vitest';
import { ConflictError } from '@stack/shared';
import { registerOperatorReviewRoutes } from './operator-reviews.js';

describe('POST /v1/operator-decisions', () => {
  it('passes only the requested action, source ids, and authenticated author', async () => {
    const decide = vi.fn(async () => ({
      decision_id: 'odec_one',
      claim_id: 'pc_decision',
      mission_id: 'ms_one',
      action: 'checkout_approved',
      effect: 'checkout_released',
      effect_scope: 'mission',
      target_agent_id: 'agt_one',
      decided_at_ms: 1,
      repeated: false,
    }));
    let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | undefined;
    const app = {
      get() {},
      post(path: string, _options: unknown, routeHandler: typeof handler) {
        if (path === '/v1/operator-decisions') handler = routeHandler;
      },
    };
    registerOperatorReviewRoutes(app as never, {
      operatorDecision: { decide },
    } as never);
    const reply = {
      status: vi.fn(() => reply),
      send: vi.fn((value) => value),
    };
    const result = await handler!({
      id: 'req_one',
      operatorId: 'op_one',
      isDashboardSession: true,
      dashboardBrowserSession: { email: 'owner@test.invalid', ownerSessionRevision: '0' },
      body: {
        action: 'checkout_approved',
        source_ids: ['cout_one'],
        authored_by: { kind: 'operator_owner', operator_id: 'op_attacker' },
        effect: 'attacker supplied',
        mission_id: 'ms_attacker',
        decided_at_ms: 0,
        browserSession: { email: 'attacker@test.invalid', ownerSessionRevision: 'attacker' },
      },
    }, reply);

    expect(decide).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_one',
      authoredBy: { kind: 'operator_owner', operator_id: 'op_one' },
      browserSession: { email: 'owner@test.invalid', ownerSessionRevision: '0' },
      action: 'checkout_approved',
      sourceIds: ['cout_one'],
      auditContext: expect.objectContaining({
        trace_id: 'req_one',
        operator_id: 'op_one',
      }),
    }));
    expect(reply.status).toHaveBeenCalledWith(201);
    expect(result).toEqual(expect.objectContaining({ claim_id: 'pc_decision' }));
  });

  it('surfaces stale source conflicts without applying a fallback route', async () => {
    const decide = vi.fn(async () => { throw new ConflictError('stale checkout'); });
    let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | undefined;
    const app = {
      get() {},
      post(path: string, _options: unknown, routeHandler: typeof handler) {
        if (path === '/v1/operator-decisions') handler = routeHandler;
      },
    };
    registerOperatorReviewRoutes(app as never, {
      operatorDecision: { decide },
    } as never);
    await expect(handler!({
      id: 'req_one',
      operatorId: 'op_one',
      isDashboardSession: true,
      dashboardBrowserSession: { email: 'owner@test.invalid', ownerSessionRevision: '0' },
      body: { action: 'checkout_blocked', source_ids: ['cout_stale'] },
    }, { status: vi.fn(), send: vi.fn() })).rejects.toBeInstanceOf(ConflictError);
  });
});

describe('POST /v1/missions/:id/operator-reviews', () => {
  const validBody = {
    overall_judgment: 'The mission met its declared purpose.',
    checkpoint_notes: [{ checkpoint_claim_id: 'pc_checkpoint', note: 'The checkpoint matched.' }],
    decision_rationales: [{ operator_decision_claim_id: 'pc_decision', rationale: 'The operator approved it.' }],
    alert_explanations: [{ detector_claim_id: 'pc_detector', explanation: 'The alert was expected.' }],
    incident_classification: 'no_incident',
    lessons_learned: 'Keep the same mission cap.',
  };

  it.each([
    ['checkpoint note', { checkpoint_notes: [{ checkpoint_claim_id: 'pc_checkpoint', note: '   ' }] }],
    ['decision rationale', { decision_rationales: [{ operator_decision_claim_id: 'pc_decision', rationale: '\n\t' }] }],
    ['alert explanation', { alert_explanations: [{ detector_claim_id: 'pc_detector', explanation: '' }] }],
  ])('rejects a blank %s before it calls the service', async (_name, invalidField) => {
    const create = vi.fn();
    let handler: ((request: unknown, reply: unknown) => Promise<unknown>) | undefined;
    const app = {
      get() {},
      post(path: string, _options: unknown, routeHandler: typeof handler) {
        if (path === '/v1/missions/:id/operator-reviews') handler = routeHandler;
      },
    };
    registerOperatorReviewRoutes(app as never, {
      operatorReview: { create },
      audit: { write: vi.fn() },
    } as never);

    await expect(handler!({
      id: 'req_one',
      params: { id: 'ms_one' },
      operatorId: 'op_one',
      isDashboardSession: true,
      body: { ...validBody, ...invalidField },
    }, { status: vi.fn(), send: vi.fn() })).rejects.toThrow();
    expect(create).not.toHaveBeenCalled();
  });
});
