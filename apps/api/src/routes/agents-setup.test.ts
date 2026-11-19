import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConflictError, ForbiddenError, GovernanceApprovalRequiredError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../middleware/auth.js')>();
  return {
    ...original,
    createAuthMiddleware: () => async (request: Record<string, unknown>) => {
      request['operatorId'] = 'op_owner';
      request['operatorTier'] = 'enterprise';
      request['isAdmin'] = false;
      request['isPlatformStaff'] = false;
      request['isPartner'] = false;
      const headers = request['headers'] as Record<string, string | undefined>;
      if (headers['x-test-dashboard']) request['isDashboardSession'] = true;
      if (headers['x-test-member-role']) {
        request['memberId'] = 'mem_one';
        request['memberRole'] = headers['x-test-member-role'];
      }
    },
  };
});

import { registerAgentRoutes } from './agents.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const CONNECTION = 'scon_grocer';
const body = {
  agent: { name: 'grocery-bot', eval_traffic: true },
  grants: [
    {
      service_connection_id: CONNECTION,
      scopes: ['read', 'write'],
      constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }],
    },
  ],
  allowed_hosts: [{ service_connection_id: CONNECTION, allowed_hosts: ['api.grocer.example'] }],
};

async function makeApp(options: { several?: boolean; nameTaken?: boolean; grantError?: Error; failHostsFor?: string; before?: Record<string, string[]> } = {}) {
  const registered = { id: 'agt_new', name: 'grocery-bot', operator_id: 'op_owner' };
  const serviceConnection = {
    // The connection's name is offered only while the account holds two or more connections of the service.
    checkSetup: vi.fn(async () => new Map([[CONNECTION, { id: CONNECTION, provider: 'custom_grocer', ...(options.several ? { name: 'Grocery account' } : {}) }]])),
    grantAgentAccess: vi.fn(async (_op: string, input: { service_connection_id: string }) => {
      if (options.grantError) throw options.grantError;
      return { id: 'grant_1', service_connection_id: input.service_connection_id };
    }),
    setAllowedHosts: vi.fn(async (connectionId: string) => {
      if (options.failHostsFor === connectionId) throw new ForbiddenError('connection changed');
      return {};
    }),
    allowedHostsOf: vi.fn(async (connectionId: string) => options.before?.[connectionId] ?? []),
    restoreAllowedHosts: vi.fn(async () => true),
    revokeAgentAccess: vi.fn(async () => undefined),
  };
  const agent = {
    assertCanRegister: vi.fn(async () => {
      if (options.nameTaken) throw new ConflictError('Agent "grocery-bot" already exists');
    }),
    register: vi.fn(async () => registered),
    delete: vi.fn(async () => undefined),
  };
  const governanceApprovals = {
    requireApproval: vi.fn(async () => {
      throw new GovernanceApprovalRequiredError('gvr_setup', 'https://getstack.run/app/approve/gvr_setup');
    }),
    consume: vi.fn(async () => undefined),
  };
  const audit = { write: vi.fn(async () => undefined) };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerAgentRoutes(app, { serviceConnection, agent, governanceApprovals, audit } as never);
  await app.ready();
  return { app, serviceConnection, agent, governanceApprovals, audit };
}

describe('POST /v1/agents/setup', () => {
  it('asks once, with every part of the request in one approval, and runs none of it until it is approved', async () => {
    const { app, serviceConnection, agent, governanceApprovals } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', payload: body });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: 'GOVERNANCE_APPROVAL_REQUIRED', details: { approval_id: 'gvr_setup' } } });
    expect(governanceApprovals.requireApproval).toHaveBeenCalledTimes(1);
    const asked = (governanceApprovals.requireApproval.mock.calls[0] as unknown as [Record<string, unknown>])[0];
    expect(asked).toMatchObject({ action: 'agent_setup', resourceId: 'grocery-bot', summary: 'Set up agent grocery-bot: register it, 1 service grant, 1 host list' });
    // The card lists the posture as it will be, the grant's constraints in full and the host list.
    expect(asked['preview']).toMatchObject({
      agent: { name: 'grocery-bot', accountability_mode: 'logged', eval_traffic: true },
      grants: [{ service: 'custom_grocer', scopes: ['read', 'write'], constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }] }],
      allowed_hosts: [{ service: 'custom_grocer', hosts: ['api.grocer.example'] }],
    });
    // With one connection of the service the preview names no connection, as before names existed.
    expect(JSON.stringify(asked['preview'])).not.toContain('connection_name');
    // The payload the approval binds carries all of it, eval_traffic included.
    expect(asked['payload']).toMatchObject(body);
    expect(agent.register).not.toHaveBeenCalled();
    expect(serviceConnection.grantAgentAccess).not.toHaveBeenCalled();
    expect(serviceConnection.setAllowedHosts).not.toHaveBeenCalled();
  });

  it('names the connection in the preview, beside the id, when the account holds several of the service, and binds nothing of the name', async () => {
    const { app, governanceApprovals } = await makeApp({ several: true });
    await app.inject({ method: 'POST', url: '/v1/agents/setup', payload: body });
    const asked = (governanceApprovals.requireApproval.mock.calls[0] as unknown as [Record<string, unknown>])[0];
    // The name is read when the approval is asked and kept in the preview beside the id.
    expect(asked['preview']).toMatchObject({
      grants: [{ service_connection_id: CONNECTION, connection_name: 'Grocery account' }],
      allowed_hosts: [{ service_connection_id: CONNECTION, connection_name: 'Grocery account' }],
    });
    // The id is what is acted on: the payload carries nothing of the name.
    expect(asked['payload']).toMatchObject(body);
    expect(JSON.stringify(asked['payload'])).not.toContain('Grocery account');
  });

  it('with the approval, registers the agent, makes the grant and sets the hosts, each as approved', async () => {
    const { app, serviceConnection, agent, governanceApprovals, audit } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', headers: { 'x-governance-approval': 'gvr_setup' }, payload: body });
    expect(response.statusCode).toBe(201);
    expect(governanceApprovals.consume).toHaveBeenCalledTimes(1);
    expect(governanceApprovals.consume).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent_setup', resourceId: 'grocery-bot', approvalId: 'gvr_setup' }));
    expect(agent.register).toHaveBeenCalledWith('op_owner', 'enterprise', expect.objectContaining({ name: 'grocery-bot', eval_traffic: true }));
    expect(serviceConnection.grantAgentAccess).toHaveBeenCalledWith(
      'op_owner',
      expect.objectContaining({ agent_id: 'agt_new', service_connection_id: CONNECTION, scopes: ['read', 'write'] }),
      expect.objectContaining({ authorityExpansionApproved: true }),
    );
    expect(serviceConnection.setAllowedHosts).toHaveBeenCalledWith(CONNECTION, 'op_owner', ['api.grocer.example'], undefined, true);
    expect(response.json()).toMatchObject({ agent: { id: 'agt_new' }, grants: [{ id: 'grant_1', service_connection_id: CONNECTION }], allowed_hosts: body.allowed_hosts });
    expect(audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.setup', outcome: 'success' }));
  });

  it('a person in their own session is the decision: it runs at once', async () => {
    const { app, governanceApprovals, agent } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', headers: { 'x-test-dashboard': '1' }, payload: body });
    expect(response.statusCode).toBe(201);
    expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
    expect(agent.register).toHaveBeenCalledTimes(1);
  });

  it('refuses before anyone is asked when the name is taken or a connection or scope cannot work', async () => {
    const taken = await makeApp({ nameTaken: true });
    const clash = await taken.app.inject({ method: 'POST', url: '/v1/agents/setup', payload: body });
    expect(clash.statusCode).toBe(409);
    expect(taken.governanceApprovals.requireApproval).not.toHaveBeenCalled();

    const bad = await makeApp();
    bad.serviceConnection.checkSetup.mockRejectedValueOnce(new ForbiddenError('scope escalation'));
    const refused = await bad.app.inject({ method: 'POST', url: '/v1/agents/setup', payload: body });
    expect(refused.statusCode).toBe(403);
    expect(bad.governanceApprovals.requireApproval).not.toHaveBeenCalled();
  });

  it('leaves nothing half made: a failed grant retires the agent and ends its grants before the error is shown', async () => {
    const { app, serviceConnection, agent } = await makeApp({ grantError: new ForbiddenError('connection changed') });
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', headers: { 'x-governance-approval': 'gvr_setup' }, payload: body });
    expect(response.statusCode).toBe(403);
    expect(serviceConnection.revokeAgentAccess).toHaveBeenCalledWith('agt_new', 'op_owner');
    expect(agent.delete).toHaveBeenCalledWith('agt_new', 'op_owner');
    expect(serviceConnection.setAllowedHosts).not.toHaveBeenCalled();
  });

  it('puts back the hosts it widened when a later part fails, and leaves alone a connection it never wrote', async () => {
    const two = {
      ...body,
      allowed_hosts: [
        { service_connection_id: 'scon_a', allowed_hosts: ['a.example'] },
        { service_connection_id: 'scon_b', allowed_hosts: ['b.example'] },
      ],
    };
    const { app, serviceConnection, agent } = await makeApp({ failHostsFor: 'scon_b', before: { scon_a: ['old.example'], scon_b: ['older.example'] } });
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', headers: { 'x-governance-approval': 'gvr_setup' }, payload: two });
    expect(response.statusCode).toBe(403);
    // The first connection was widened and is restored to what it was; the second was never written.
    expect(serviceConnection.restoreAllowedHosts).toHaveBeenCalledTimes(1);
    expect(serviceConnection.restoreAllowedHosts).toHaveBeenCalledWith('scon_a', 'op_owner', ['old.example'], ['a.example'], undefined);
    expect(serviceConnection.revokeAgentAccess).toHaveBeenCalledWith('agt_new', 'op_owner');
    expect(agent.delete).toHaveBeenCalledWith('agt_new', 'op_owner');
  });

  it('restores nothing when a grant fails before any host was written', async () => {
    const { app, serviceConnection } = await makeApp({ grantError: new ForbiddenError('connection changed') });
    await app.inject({ method: 'POST', url: '/v1/agents/setup', headers: { 'x-governance-approval': 'gvr_setup' }, payload: body });
    expect(serviceConnection.restoreAllowedHosts).not.toHaveBeenCalled();
  });

  it.each([
    ['nothing to do', { agent: { name: 'bot' } }],
    ['a connection listed twice', { agent: { name: 'bot' }, grants: [{ service_connection_id: CONNECTION, scopes: ['a'] }, { service_connection_id: CONNECTION, scopes: ['b'] }] }],
    ['no agent name', { agent: {}, grants: [{ service_connection_id: CONNECTION, scopes: ['a'] }] }],
    ['a grant with no scope', { agent: { name: 'bot' }, grants: [{ service_connection_id: CONNECTION, scopes: [] }] }],
  ])('rejects a request with %s as invalid', async (_label, payload) => {
    const { app, governanceApprovals } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', payload });
    expect(response.statusCode).toBe(400);
    expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
  });

  it('is refused to a read-only member, as granting access is', async () => {
    const { app, governanceApprovals } = await makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/agents/setup', headers: { 'x-test-member-role': 'viewer' }, payload: body });
    expect(response.statusCode).toBe(403);
    expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
  });
});
