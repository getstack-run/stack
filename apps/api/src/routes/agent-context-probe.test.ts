// An agent never decides anything about itself: the two routes that settle an agent's warnings and an approval's fate
// are refused to a caller that carries an agent context, whatever credential brought it, and nothing behind them runs.
// Through the real routes and the real gate (only authentication is stood in for), not the route options.

import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../middleware/auth.js')>();
  return {
    ...original,
    createAuthMiddleware: () => async (request: Record<string, unknown>) => {
      const headers = request['headers'] as Record<string, string | undefined>;
      request['operatorId'] = 'op_owner';
      request['operatorTier'] = 'enterprise';
      request['isAdmin'] = false;
      request['isPlatformStaff'] = false;
      request['isPartner'] = false;
      // An agent's own token (an agent JWT, or a Passport used as inbound auth) sets the agent on the request.
      if (headers['x-test-agent']) request['agentId'] = headers['x-test-agent'];
      // The Console's own session is the person: dismissing warnings from it needs no further approval.
      if (headers['x-test-dashboard']) request['isDashboardSession'] = true;
      if (headers['x-test-oauth']) {
        request['oauthScope'] = 'governance:decide reviews:write';
        request['oauthClientId'] = 'client_1';
      }
    },
  };
});

import { registerOperatorReviewRoutes } from './operator-reviews.js';
import { registerGovernanceRoutes } from './governance.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const dismissOpenForAgent = vi.fn(async () => []);
  const getById = vi.fn(async () => ({ id: 'agt_one' }));
  const decideGovernance = vi.fn(async () => ({ approval: { id: 'gvr_one', status: 'rejected' } }));
  const getDetailForOperator = vi.fn(async () => ({ approval: { id: 'gvr_one', action: 'agent_setup', status: 'pending' }, payload_hash: 'a'.repeat(64), approval_url: 'u' }));
  const write = vi.fn(async () => undefined);
  const services = {
    securityEvent: { dismissOpenForAgent },
    agent: { getById },
    audit: { write },
    operatorDecision: { decideGovernance },
    governanceApprovals: { getDetailForOperator, belongsTo: vi.fn(), getDetailForPartnerTenant: vi.fn() },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerOperatorReviewRoutes(app, services as never);
  registerGovernanceRoutes(app, services as never);
  await app.ready();
  return { app, dismissOpenForAgent, decideGovernance, getDetailForOperator };
}

describe('an agent context on the routes that settle warnings and approvals', () => {
  it('cannot dismiss an agent\'s warnings, its own included, and nothing is resolved', async () => {
    const { app, dismissOpenForAgent } = await makeApp();
    for (const agent of ['agt_one', 'agt_other']) {
      const response = await app.inject({ method: 'POST', url: '/v1/agents/agt_one/dismiss-warnings', headers: { 'x-test-agent': agent }, payload: {} });
      expect(response.statusCode, response.body).toBe(403);
    }
    expect(dismissOpenForAgent).not.toHaveBeenCalled();
    // The owner's own call goes through.
    const owner = await app.inject({ method: 'POST', url: '/v1/agents/agt_one/dismiss-warnings', headers: { 'x-test-dashboard': '1' }, payload: {} });
    expect(owner.statusCode, owner.body).toBe(200);
    expect(dismissOpenForAgent).toHaveBeenCalledTimes(1);
  });

  it('cannot decide an approval in the chat, a rejection included, and nothing is decided or even read', async () => {
    const { app, decideGovernance, getDetailForOperator } = await makeApp();
    const payload = { decision: 'reject' };
    const response = await app.inject({
      method: 'POST', url: '/v1/governance/approvals/gvr_one/chat-decision', headers: { 'x-test-agent': 'agt_one', 'x-test-oauth': '1' }, payload,
    });
    expect(response.statusCode, response.body).toBe(403);
    expect(decideGovernance).not.toHaveBeenCalled();
    expect(getDetailForOperator).not.toHaveBeenCalled();
    // A person's own token may reject (an approval is never attested without the MCP server).
    const owner = await app.inject({
      method: 'POST', url: '/v1/governance/approvals/gvr_one/chat-decision', headers: { 'x-test-oauth': '1' }, payload,
    });
    expect(owner.statusCode, owner.body).toBe(200);
    expect(decideGovernance).toHaveBeenCalledTimes(1);
  });
});
