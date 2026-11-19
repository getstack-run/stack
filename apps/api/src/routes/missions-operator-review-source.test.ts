import { describe, expect, it, vi } from 'vitest';
import { registerOperatorReviewRoutes } from './operator-reviews.js';

function captureRoutes(services: Record<string, unknown>) {
  const routes = new Map<string, (...args: never[]) => unknown>();
  const app = {
    get(path: string, _options: unknown, handler: (...args: never[]) => unknown) {
      routes.set(`GET ${path}`, handler);
    },
    post(path: string, _options: unknown, handler: (...args: never[]) => unknown) {
      routes.set(`POST ${path}`, handler);
    },
  };
  registerOperatorReviewRoutes(app as never, services as never);
  return routes;
}

describe('GET operator-review-source', () => {
  it('returns only the sanitized source contract', async () => {
    const source = {
      mission_id: 'ms_one',
      operator_decisions: [{
        claim_id: 'pc_decision',
        action: 'checkout_approved',
        effect: 'checkout_released',
        effect_scope: 'mission',
        target_agent_id: 'agt_one',
        decided_at_ms: 1,
        source_refs: { checkout_ids: ['cout_one'], security_event_ids: [], detector_claim_ids: [], approval_ids: [] },
      }],
      checkpoints: [{ claim_id: 'pc_checkpoint', submitted_at: 2, services_used: ['github'], actions_count: 1 }],
      alerts: [{ claim_id: 'pc_detector', detector_key: 'scope_drift', severity: 'high', pipeline: 'heuristic', detected_at: 3 }],
    };
    const sourceFn = vi.fn(async () => source);
    const routes = captureRoutes({ operatorReview: { source: sourceFn } });
    const handler = routes.get('GET /v1/missions/:id/operator-review-source')!;
    const result = await handler({
      params: { id: 'ms_one' },
      operatorId: 'op_one',
      isDashboardSession: true,
    } as never);

    expect(result).toEqual(source);
    expect(sourceFn).toHaveBeenCalledWith('ms_one', 'op_one');
    const wire = JSON.stringify(result);
    for (const forbidden of ['email', 'prompt', 'message', 'metadata', 'private_note', 'approval_payload']) {
      expect(wire).not.toContain(forbidden);
    }
  });
});
