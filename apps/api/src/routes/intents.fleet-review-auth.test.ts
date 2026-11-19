import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({ createAuthMiddleware: () => async (request: Record<string, unknown>) => {
  request.operatorId = 'op_one';
  request.isDashboardSession = (request.headers as Record<string, string>).authorization === 'Bearer human';
} }));
import { registerIntentsRoutes } from './intents.js';

describe('fleet exact review custody', () => {
  it.each(['operator-key', 'human'])('limits exact review to the human session (%s)', async token => {
    const readFleetReview = vi.fn(async () => ({ request: { body: { channel: 'C123' } } }));
    const row = { id: 'ia_one', operator_id: 'op_one', agent_id: 'agt_one', passport_jti: 'ppt_one', intent_claim_id: 'pc_one',
      simulated_claim_id: null, status: 'pending', requested_at: new Date(), expires_at: new Date(Date.now() + 60_000),
      decided_at: null, decided_by_member_id: null, notes: null, block_future: false,
      fleet_policy_id: 'flp_one', fleet_policy_revision: 1, fleet_mission_id: 'ms_one' };
    const app = Fastify();
    app.setErrorHandler(errorHandler);
    registerIntentsRoutes(app, { intentApproval: { findById: async () => row, readFleetReview }, passportClaimsRepo: {
      findByClaimId: async () => ({ operator_id: 'op_one', passport_id: 'ppt_one', type: 'intent_claim', body_json: {
        type: 'intent_claim', intent_type: 'http_call', agent_id: 'agt_one', named_intent: 'stack:proxy:execute',
        target: 'slack', action: 'POST', parameters: {}, estimated_cost: { wallet_cents: null, tokens: null, gas_gwei: null },
        accountability: 'enforced', reason: null, requires: [], user_subject: null, mission_ref: 'ms_one', submitted_at: Date.now(),
        policy_decision: { origin: 'fleet_policy', policy_id: 'flp_one', policy_revision: 1, mission_id: 'ms_one', rule_id: 'review', request_hash: 'a'.repeat(64), effect: 'review' },
      } }),
    } } as never);
    try {
      const response = await app.inject({ method: 'GET', url: '/v1/intents/ia_one?review=1', headers: { authorization: `Bearer ${token}` } });
      expect(response.statusCode).toBe(token === 'human' ? 200 : 403);
      expect(readFleetReview).toHaveBeenCalledTimes(token === 'human' ? 1 : 0);
      if (token === 'human') expect(response.json()).toMatchObject({ fleet_policy_id: 'flp_one', fleet_mission_id: 'ms_one', intent: { matched_rule: 'review' }, fleet_request: { request: { body: { channel: 'C123' } } } });
      const plain = await app.inject({ method: 'GET', url: '/v1/intents/ia_one', headers: { authorization: 'Bearer operator-key' } });
      expect(plain.statusCode).toBe(200);
      expect(plain.json()).not.toHaveProperty('fleet_request');
    } finally { await app.close(); }
  });
});
