import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';

/**
 * Deleting an agent that has an account goes through the account close path,
 * which also ends the Mission, grants and pieces; a bare agent delete would
 * revoke passports only.
 */

const principal: Record<string, unknown> = {};
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request['operatorId'] = 'op_owner';
    request['operatorTier'] = 'pro';
    Object.assign(request, principal);
  },
  createEnrollmentAuthMiddleware: () => async () => undefined,
  claimEnrollmentTicket: vi.fn(),
  enrollmentTicketClaimKey: vi.fn(),
  releaseEnrollmentTicketClaim: vi.fn(),
}));

const { registerAgentRoutes } = await import('./agents.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
  for (const key of Object.keys(principal)) delete principal[key];
});

async function makeApp(account: { id: string; operator_id: string } | null) {
  const close = vi.fn(async () => ({ account: { id: account?.id, status: 'closing' }, transitioned: true }));
  const agentDelete = vi.fn(async () => ({ id: 'agt_one', status: 'revoked' }));
  const revokeAllForAgent = vi.fn(async () => ({ revoked_count: 0 }));
  const services = {
    agentAccounts: { findOpenAccountByAgent: vi.fn(async () => account), close },
    agent: { delete: agentDelete, getById: vi.fn(async () => ({ id: 'agt_one', status: 'revoked' })) },
    passport: { revokeAllForAgent },
    audit: { write: vi.fn(async () => 'aud_one') },
  } as unknown as Services;
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerAgentRoutes(app, services);
  await app.ready();
  const del = () => app.inject({ method: 'DELETE', url: '/v1/agents/agt_one', headers: { authorization: 'Bearer operator' } });
  return { del, close, agentDelete, revokeAllForAgent };
}

describe('DELETE /v1/agents/:id for an agent with an account', () => {
  it('closes the account instead of the bare agent delete', async () => {
    const { del, close, agentDelete, revokeAllForAgent } = await makeApp({ id: 'acct_one', operator_id: 'op_owner' });
    const response = await del();
    expect(response.statusCode).toBe(200);
    expect(close).toHaveBeenCalledWith({ operatorId: 'op_owner', accountId: 'acct_one' });
    expect(agentDelete).not.toHaveBeenCalled();
    expect(revokeAllForAgent).not.toHaveBeenCalled();
  });

  it('needs the admin role to close the account, as DELETE /v1/accounts/:id does', async () => {
    principal['memberId'] = 'mem_one';
    principal['memberRole'] = 'standard';
    const { del, close, agentDelete } = await makeApp({ id: 'acct_one', operator_id: 'op_owner' });
    expect((await del()).statusCode).toBe(403);
    expect(close).not.toHaveBeenCalled();
    expect(agentDelete).not.toHaveBeenCalled();
  });

  it('refuses a read-only member to retire an agent that has no account', async () => {
    principal['memberId'] = 'mem_one';
    principal['memberRole'] = 'readonly';
    const { del, agentDelete, revokeAllForAgent } = await makeApp(null);
    expect((await del()).statusCode).toBe(403);
    expect(agentDelete).not.toHaveBeenCalled();
    expect(revokeAllForAgent).not.toHaveBeenCalled();
  });

  it.each(['standard', 'admin'])('lets a %s member retire an agent that has no account', async (role) => {
    principal['memberId'] = 'mem_one';
    principal['memberRole'] = role;
    const { del, agentDelete } = await makeApp(null);
    expect((await del()).statusCode).toBe(200);
    expect(agentDelete).toHaveBeenCalledTimes(1);
  });

  it('keeps the plain delete for an agent without an account', async () => {
    const { del, close, agentDelete, revokeAllForAgent } = await makeApp(null);
    expect((await del()).statusCode).toBe(200);
    expect(close).not.toHaveBeenCalled();
    expect(agentDelete).toHaveBeenCalledWith('agt_one', 'op_owner');
    expect(revokeAllForAgent).toHaveBeenCalledWith('agt_one', 'Agent deleted');
  });
});
