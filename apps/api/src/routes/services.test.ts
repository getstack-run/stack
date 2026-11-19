import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConflictError, GovernanceApprovalRequiredError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request['operatorId'] = 'op_owner';
    request['operatorTier'] = 'enterprise';
    request['isAdmin'] = false;
    request['isPlatformStaff'] = false;
    request['isPartner'] = false;
    const headers = request['headers'] as Record<string, string | undefined>;
    if (headers['x-test-member-id']) {
      request['memberId'] = headers['x-test-member-id'];
      request['memberRole'] = headers['x-test-member-role'] ?? 'standard';
    }
    if (headers['x-test-allowed-connections'] !== undefined) {
      request['allowedConnections'] = JSON.parse(headers['x-test-allowed-connections']);
    }
  },
}));

const grantNotice = vi.hoisted(() => ({ value: null as Record<string, unknown> | null }));
vi.mock('../lib/control-policy/grant-notice.js', () => ({ grantControlPolicyNotice: async () => grantNotice.value }));
const grantListing = vi.hoisted(() => ({ value: null as Record<string, unknown> | null }));
vi.mock('../lib/control-policy/grant-listing.js', async (importOriginal) => ({ ...(await importOriginal<typeof import('../lib/control-policy/grant-listing.js')>()), planGrantListing: async () => grantListing.value }));

import { registerServiceRoutes } from './services.js';

const apps: ReturnType<typeof Fastify>[] = [];
const connection = {
  id: 'scon_agentmail',
  operator_id: 'op_owner',
  service_id: 'svc_agentmail',
  provider: 'agentmail',
  scopes: ['*'],
  credential_ref: 'kms:key',
  credential_encrypted: 'kms-envelope-secret',
  connected_by: null,
  member_id: null,
  status: 'active',
  proxy_enabled: true,
  allowed_hosts: ['api.agentmail.to'],
  verification_status: 'unhealthy',
  verified_at: null,
  connected_at: new Date('2026-08-16T10:00:00.000Z'),
  expires_at: null,
  mcp_url: null as string | null,
};

afterEach(async () => {
  grantNotice.value = null;
  grantListing.value = null;
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp(options?: {
  connectError?: Error;
  dataFlowWidens?: boolean;
  proxyWeakens?: boolean;
  hostsWiden?: boolean;
  policyApplyError?: Error;
  /** The account holds a second connection of this service, so an approval shows this connection by the name its owner gave it. */
  named?: string;
  catalogue?: Array<Record<string, unknown>>;
}) {
  const serviceConnection = {
    listAvailableServices: vi.fn(async () => options?.catalogue ?? []),
    assertConnectionAccess: vi.fn(() => undefined),
    listConnectedServices: vi.fn(async () => [connection]),
    connect: vi.fn(async () => {
      if (options?.connectError) throw options.connectError;
      return connection;
    }),
    connectCustom: vi.fn(async () => connection),
    connectApplication: vi.fn(async () => connection),
    configureService: vi.fn(async () => ({})),
    getServiceConfigurations: vi.fn(async () => []),
    disableService: vi.fn(async () => ({})),
    getGrantsByConnection: vi.fn(async () => []),
    disconnect: vi.fn(async () => ({ ...connection, status: 'revoked' })),
    grantAccessWidens: vi.fn(async () => options?.dataFlowWidens ?? false),
    grantAgentAccess: vi.fn(async () => ({})),
    revokeAgentAccess: vi.fn(async () => undefined),
    getAgentPermissions: vi.fn(async () => []),
    proxyChangeWeakens: vi.fn(async () => options?.proxyWeakens ?? false),
    setProxyEnabled: vi.fn(async () => ({ ...connection, proxy_enabled: false })),
    allowedHostsChangeWidens: vi.fn(async () => options?.hostsWiden ?? false),
    // With one connection of the service the account's name for it is not offered; with several it is.
    checkSetup: vi.fn(async () => new Map([[
      connection.id,
      { id: connection.id, provider: connection.provider, ...(options?.named ? { name: options.named } : {}) },
    ]])),
    connectionNameWhenSeveral: vi.fn(async () => options?.named ?? null),
    setAllowedHosts: vi.fn(async () => ({ ...connection, allowed_hosts: ['api.example.com'] })),
  };
  const services = {
    serviceConnection,
    providerOAuth: {
      // STACK's own Google app asks for the first scope of a Google service only; every other service has no list.
      stackAppScopes: vi.fn((provider: string, scopes: string[]) => (provider.startsWith('google_') ? scopes.slice(0, 1) : null)),
    },
    connectionVerifier: {
      verify: vi.fn(async () => ({
        status: 'unhealthy',
        message: 'Access denied or insufficient permission (403)',
        checked_at: '2026-08-16T10:00:00.000Z',
      })),
    },
    audit: { write: vi.fn(async () => undefined) },
    analytics: { fireOnce: vi.fn(() => undefined) },
    passport: { revokeAllForAgent: vi.fn(async () => undefined) },
    agent: { getById: vi.fn(async () => ({})) },
    controlPolicies: {
      apply: vi.fn(async () => {
        if (options?.policyApplyError) throw options.policyApplyError;
        return { id: 'cpl_agent', revision: 4 };
      }),
    },
    governanceApprovals: {
      requireApproval: vi.fn(async () => {
        throw new GovernanceApprovalRequiredError(
          'gov_data_flow',
          'https://getstack.run/app/approve/gov_data_flow',
        );
      }),
      consume: vi.fn(async () => undefined),
    },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerServiceRoutes(app, services as never);
  await app.ready();
  return { app, serviceConnection, governanceApprovals: services.governanceApprovals, controlPolicies: services.controlPolicies, audit: services.audit };
}

function expectSafeConnection(body: Record<string, unknown>) {
  expect(body).not.toHaveProperty('credential_encrypted');
  expect(body).not.toHaveProperty('credential_ref');
  expect(body).toMatchObject({
    id: connection.id,
    credential_present: true,
  });
  expect(JSON.stringify(body)).not.toContain('kms-envelope-secret');
  expect(JSON.stringify(body)).not.toContain('kms:key');
}

describe('service connection route safety', () => {
  const grantPayload = {
    agent_id: 'agt_support',
    service_connection_id: connection.id,
    scopes: ['*'],
    allow_data_from: ['guestbook'],
  };

  it.each([
    ['/v1/services/connect', { service_id: 'svc_agentmail', scopes: ['*'], oauth_token: 'synthetic' }, 'connect'],
    ['/v1/services/custom', { name: 'Synthetic', credential: 'synthetic', allowed_hosts: ['api.example.test'] }, 'connectCustom'],
  ] as const)('refuses a standard member connecting for a different member via %s', async (url, payload, method) => {
    const { app, serviceConnection } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url,
      headers: {
        'x-test-member-id': 'mem_current',
        'x-test-member-role': 'standard',
      },
      payload: { ...payload, member_id: 'mem_teammate' },
    });
    expect(response.statusCode).toBe(403);
    expect(serviceConnection[method]).not.toHaveBeenCalled();
  });

  it('binds a standard member connection to the authenticated member', async () => {
    const { app, serviceConnection } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/connect',
      headers: {
        'x-test-member-id': 'mem_current',
        'x-test-member-role': 'standard',
      },
      payload: {
        service_id: 'svc_agentmail',
        scopes: ['*'],
        oauth_token: 'synthetic',
        member_id: 'mem_current',
      },
    });
    expect(response.statusCode).toBe(201);
    expect(serviceConnection.connect).toHaveBeenCalledWith(
      'op_owner',
      'enterprise',
      expect.any(Object),
      'mem_current',
      'mem_current',
    );
  });

  it('lists service configurations for a connection-restricted member instead of refusing', async () => {
    const { app, serviceConnection } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/services/configurations',
      headers: { 'x-test-member-id': 'mem_reviewer', 'x-test-allowed-connections': '[]' },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual([]);
    expect(serviceConnection.getServiceConfigurations).toHaveBeenCalledWith('op_owner', []);
    expect(serviceConnection.assertConnectionAccess).not.toHaveBeenCalled();
  });

  it('lists truthful connection state without credential storage fields', async () => {
    const { app } = await makeApp();
    const response = await app.inject({ method: 'GET', url: '/v1/services/connected' });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>[];
    expect(body).toHaveLength(1);
    expectSafeConnection(body[0]!);
    expect(body[0]).toMatchObject({
      proxy_enabled: connection.proxy_enabled,
      allowed_hosts: connection.allowed_hosts,
    });
  });

  it('lists each connection with the address of its MCP endpoint: the one it carries, else the default of a service STACK knows, else null', async () => {
    const { app, serviceConnection } = await makeApp();
    serviceConnection.listConnectedServices.mockResolvedValueOnce([
      { ...connection, id: 'scon_a', provider: 'rentahuman', mcp_url: null },
      { ...connection, id: 'scon_b', provider: 'custom_acme', mcp_url: 'https://mcp.acme.example/rpc' },
      { ...connection, id: 'scon_c', provider: 'agentmail', mcp_url: null },
    ]);
    const body = (await app.inject({ method: 'GET', url: '/v1/services/connected' })).json() as Array<{ id: string; mcp_url: string | null }>;
    expect(body.map((c) => [c.id, c.mcp_url])).toEqual([
      ['scon_a', 'https://rentahuman.ai/api/mcp'],
      ['scon_b', 'https://mcp.acme.example/rpc'],
      ['scon_c', null],
    ]);
    expect(JSON.stringify(body)).not.toContain('kms-envelope-secret');
  });

  it('gives each catalogue row the scopes STACK\'s own app will request: a Google service\'s held to the list, null for any other service', async () => {
    const { app } = await makeApp({ catalogue: [
      { id: 'svc_drive', provider: 'google_drive', scopes_available: ['drive', 'drive.file'] },
      { id: 'svc_slack', provider: 'slack', scopes_available: ['chat:write'] },
    ] });
    const response = await app.inject({ method: 'GET', url: '/v1/services' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual([
      { id: 'svc_drive', provider: 'google_drive', scopes_available: ['drive', 'drive.file'], stack_app_scopes: ['drive'] },
      { id: 'svc_slack', provider: 'slack', scopes_available: ['chat:write'], stack_app_scopes: null },
    ]);
  });

  it('rejects an empty application credential', async () => {
    const { app, serviceConnection } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/connect-application',
      payload: { service_id: 'svc_agentmail', credential: {} },
    });

    expect(response.statusCode).toBe(400);
    expect(serviceConnection.connectApplication).not.toHaveBeenCalled();
  });

  it('does not return credential storage fields after connection creation', async () => {
    const { app } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/connect-application',
      payload: { service_id: 'svc_agentmail', credential: { api_key: 'am_secret' } },
    });

    expect(response.statusCode).toBe(201);
    expectSafeConnection(response.json());
  });

  it('sanitizes OAuth, custom, and disconnect connection responses', async () => {
    const { app } = await makeApp();
    const oauth = await app.inject({
      method: 'POST',
      url: '/v1/services/connect',
      payload: { service_id: 'svc_agentmail', scopes: ['*'], oauth_token: 'secret-input' },
    });
    const custom = await app.inject({
      method: 'POST',
      url: '/v1/services/custom',
      payload: {
        name: 'Example',
        credential: 'secret-input',
        allowed_hosts: ['api.example.com'],
      },
    });
    const disconnected = await app.inject({
      method: 'DELETE',
      url: `/v1/services/${connection.id}/disconnect`,
    });

    expect(oauth.statusCode).toBe(201);
    expect(custom.statusCode).toBe(201);
    expect(disconnected.statusCode).toBe(200);
    expectSafeConnection(oauth.json());
    expectSafeConnection(custom.json());
    expectSafeConnection(disconnected.json());
  });

  it('does not return credential storage fields after policy updates', async () => {
    const { app } = await makeApp();
    const proxy = await app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/proxy-toggle`,
      payload: { proxy_enabled: false },
    });
    const hosts = await app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/allowed-hosts`,
      payload: { allowed_hosts: ['api.example.com'] },
    });

    expectSafeConnection(proxy.json());
    expectSafeConnection(hosts.json());
    expect(proxy.json()).toMatchObject({ proxy_enabled: false });
    expect(hosts.json()).toMatchObject({ allowed_hosts: ['api.example.com'] });
  });

  it('maps a principal conflict to 409 without returning credential input', async () => {
    const { app } = await makeApp({
      connectError: new ConflictError('An active connection already exists for this service principal'),
    });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/connect',
      payload: { service_id: 'svc_agentmail', scopes: ['*'], oauth_token: 'secret-input' },
    });

    expect(response.statusCode).toBe(409);
    expect(response.body).not.toContain('secret-input');
  });

  it('returns the safe 403 verification result without a provider body', async () => {
    const { app } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/verify`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: 'unhealthy',
      message: 'Access denied or insufficient permission (403)',
    });
  });

  it('requires human governance approval before widening a standing data-flow grant', async () => {
    const { app, serviceConnection, governanceApprovals } = await makeApp({ dataFlowWidens: true });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/grant',
      payload: grantPayload,
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      error: {
        code: 'GOVERNANCE_APPROVAL_REQUIRED',
        details: {
          approval_id: 'gov_data_flow',
          approval_url: 'https://getstack.run/app/approve/gov_data_flow',
        },
      },
    });
    expect(serviceConnection.grantAgentAccess).not.toHaveBeenCalled();
    expect(governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'service_grant_expand',
      resourceId: `agt_support:${connection.id}`,
      payload: grantPayload,
    }));
  });

  it('binds an approved widening to the exact agent, connection, and payload', async () => {
    const { app, serviceConnection, governanceApprovals } = await makeApp({ dataFlowWidens: true });
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/grant',
      headers: { 'x-governance-approval': 'gov_data_flow' },
      payload: grantPayload,
    });

    expect(response.statusCode).toBe(201);
    expect(serviceConnection.grantAgentAccess).toHaveBeenCalledWith(
      'op_owner',
      grantPayload,
      { authorityExpansionApproved: true, allowedConnections: undefined },
    );
    expect(governanceApprovals.consume).toHaveBeenCalledWith({
      approvalId: 'gov_data_flow',
      operatorId: 'op_owner',
      action: 'service_grant_expand',
      resourceId: `agt_support:${connection.id}`,
      payload: grantPayload,
      memberId: null,
    });
  });

  describe('a widening and the policy listing it needs are one approval', () => {
    const listing = {
      plan: { change: 'loosen', needsApproval: true, expectedRevision: 3, next: {} },
      ref: { policy_id: 'cpl_agent', expected_revision: 3, definition_digest: 'd'.repeat(64) },
    };

    it('asks once, for a payload that names the exact policy change, and says so on the card', async () => {
      grantListing.value = listing;
      const { app, serviceConnection, governanceApprovals, controlPolicies } = await makeApp({ dataFlowWidens: true });
      const response = await app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
      expect(response.statusCode).toBe(403);
      expect(governanceApprovals.requireApproval).toHaveBeenCalledTimes(1);
      expect(governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
        action: 'service_grant_expand',
        payload: { ...grantPayload, policy_listing: listing.ref },
        summary: expect.stringMatching(/list the service in the agent's policy/),
        preview: expect.objectContaining({ service: 'agentmail', policy_listing: { policy_id: 'cpl_agent', expected_revision: 3 }, scopes: ['*'] }),
      }));
      expect(serviceConnection.grantAgentAccess).not.toHaveBeenCalled();
      expect(controlPolicies.apply).not.toHaveBeenCalled();
    });

    it('with the approval, makes the grant and applies exactly that policy change, authorized by it', async () => {
      grantListing.value = listing;
      const { app, serviceConnection, governanceApprovals, controlPolicies, audit } = await makeApp({ dataFlowWidens: true });
      const response = await app.inject({
        method: 'POST',
        url: '/v1/services/grant',
        headers: { 'x-governance-approval': 'gov_data_flow' },
        payload: grantPayload,
      });
      expect(response.statusCode).toBe(201);
      expect(governanceApprovals.consume).toHaveBeenCalledTimes(1);
      expect(governanceApprovals.consume).toHaveBeenCalledWith(expect.objectContaining({
        payload: { ...grantPayload, policy_listing: listing.ref },
      }));
      expect(serviceConnection.grantAgentAccess).toHaveBeenCalledTimes(1);
      expect(controlPolicies.apply).toHaveBeenCalledWith(listing.plan, expect.objectContaining({ authorized: true, approvalId: 'gov_data_flow', actor: 'operator_key' }));
      expect(response.json()).toMatchObject({ policy_listed: { policy_id: 'cpl_agent', revision: 4 } });
      expect(audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'control_policy.loosen', payload_hash: listing.ref.definition_digest }));
    });

    it('does not touch the policy when the grant needs no approval, or when no listing applies', async () => {
      grantListing.value = listing;
      const narrowing = await makeApp({ dataFlowWidens: false });
      const narrowed = await narrowing.app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
      expect(narrowed.statusCode).toBe(201);
      expect(narrowing.controlPolicies.apply).not.toHaveBeenCalled();

      grantListing.value = null;
      const plain = await makeApp({ dataFlowWidens: true });
      await plain.app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
      expect(plain.governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({ payload: grantPayload, summary: 'Expand this agent service grant' }));
    });

    it('keeps the grant when the policy cannot be changed, and says nothing was listed', async () => {
      const quiet = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      grantListing.value = listing;
      grantNotice.value = { policy_id: 'cpl_agent', policy_revision: 3, revision_needed: 4, action_needed: 'list_connection' };
      const { app, serviceConnection } = await makeApp({ dataFlowWidens: true, policyApplyError: new Error('revision moved') });
      const response = await app.inject({
        method: 'POST',
        url: '/v1/services/grant',
        headers: { 'x-governance-approval': 'gov_data_flow' },
        payload: grantPayload,
      });
      quiet.mockRestore();
      expect(response.statusCode).toBe(201);
      expect(serviceConnection.grantAgentAccess).toHaveBeenCalledTimes(1);
      expect(response.json()).not.toHaveProperty('policy_listed');
      expect(response.json()).toMatchObject({ control_policy: { revision_needed: 4 } });
    });
  });

  it('answers a grant with what the policy of the agent still needs, and with nothing extra when it needs nothing', async () => {
    const plain = await makeApp();
    const none = await plain.app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
    expect(none.statusCode).toBe(201);
    expect(none.json()).not.toHaveProperty('control_policy');

    grantNotice.value = { policy_id: 'cpl_a', policy_revision: 3, revision_needed: 4, action_needed: 'list_connection' };
    const withNotice = await makeApp();
    const granted = await withNotice.app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
    expect(granted.statusCode).toBe(201);
    expect(granted.json()).toMatchObject({ control_policy: { policy_id: 'cpl_a', policy_revision: 3, revision_needed: 4 } });
  });

  it('names the connection in the proxy-disable approval as its owner named it, in quotes, only when the account has several of the service, else by id', async () => {
    const named = await makeApp({ proxyWeakens: true, named: 'Work' });
    await named.app.inject({ method: 'POST', url: `/v1/services/${connection.id}/proxy-toggle`, payload: { proxy_enabled: false } });
    expect(named.governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'service_proxy_disable',
      payload: { connection_id: connection.id, proxy_enabled: false },
      summary: 'Disable proxy enforcement for connection "Work"',
    }));
    const unnamed = await makeApp({ proxyWeakens: true });
    await unnamed.app.inject({ method: 'POST', url: `/v1/services/${connection.id}/proxy-toggle`, payload: { proxy_enabled: false } });
    expect(unnamed.governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      summary: `Disable proxy enforcement for connection ${connection.id}`,
    }));
  });

  it('requires approval to disable proxy enforcement but not to enable it', async () => {
    const weakening = await makeApp({ proxyWeakens: true });
    const denied = await weakening.app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/proxy-toggle`,
      payload: { proxy_enabled: false },
    });
    expect(denied.statusCode).toBe(403);
    expect(weakening.serviceConnection.setProxyEnabled).not.toHaveBeenCalled();
    expect(weakening.governanceApprovals.requireApproval).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'service_proxy_disable',
        payload: { connection_id: connection.id, proxy_enabled: false },
      }),
    );

    const tightening = await makeApp({ proxyWeakens: false });
    const allowed = await tightening.app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/proxy-toggle`,
      payload: { proxy_enabled: true },
    });
    expect(allowed.statusCode).toBe(200);
    expect(tightening.governanceApprovals.requireApproval).not.toHaveBeenCalled();
  });

  it('asks for a widened grant with no connection name when the account has one connection of the service', async () => {
    const { app, governanceApprovals } = await makeApp({ dataFlowWidens: true });
    await app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
    const asked = (governanceApprovals.requireApproval.mock.calls[0] as unknown as [{ preview: Record<string, unknown> }])[0];
    expect(asked.preview).toMatchObject({ service_connection_id: connection.id, service: 'agentmail' });
    expect(asked.preview).not.toHaveProperty('connection_name');
  });

  it('asks for a widened grant with the connection named as its owner named it, beside the id, when the account has several of the service, and binds only the request', async () => {
    const { app, serviceConnection, governanceApprovals } = await makeApp({ dataFlowWidens: true, named: 'Work' });
    const response = await app.inject({ method: 'POST', url: '/v1/services/grant', payload: grantPayload });
    expect(response.statusCode).toBe(403);
    expect(serviceConnection.grantAgentAccess).not.toHaveBeenCalled();
    expect(governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'service_grant_expand',
      resourceId: `agt_support:${connection.id}`,
      payload: grantPayload,
      summary: 'Expand this agent service grant',
      preview: expect.objectContaining({ service_connection_id: connection.id, connection_name: 'Work', service: 'agentmail' }),
    }));
  });

  it('asks for widened credential destinations with the connection by its name, in quotes, when the account has several of the service; the id is still what the approval binds', async () => {
    const { app, serviceConnection, governanceApprovals } = await makeApp({ hostsWiden: true, named: 'Work' });
    const response = await app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/allowed-hosts`,
      payload: { allowed_hosts: ['api.additional.invalid'] },
    });
    expect(response.statusCode).toBe(403);
    expect(serviceConnection.setAllowedHosts).not.toHaveBeenCalled();
    expect(governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'service_allowed_hosts_expand',
      resourceId: connection.id,
      payload: { connection_id: connection.id, allowed_hosts: ['api.additional.invalid'] },
      summary: 'Expand credential destinations for connection "Work" to: api.additional.invalid',
    }));
  });

  it('shows the id in that summary when the account has one connection of the service', async () => {
    const { app, governanceApprovals } = await makeApp({ hostsWiden: true });
    await app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/allowed-hosts`,
      payload: { allowed_hosts: ['api.additional.invalid'] },
    });
    expect(governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      summary: `Expand credential destinations for connection ${connection.id} to: api.additional.invalid`,
    }));
  });

  it('requires approval only when credential destinations expand', async () => {
    const { app, serviceConnection, governanceApprovals } = await makeApp({ hostsWiden: true });
    const response = await app.inject({
      method: 'POST',
      url: `/v1/services/${connection.id}/allowed-hosts`,
      payload: { allowed_hosts: ['api.additional.invalid'] },
    });
    expect(response.statusCode).toBe(403);
    expect(serviceConnection.setAllowedHosts).not.toHaveBeenCalled();
    expect(governanceApprovals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'service_allowed_hosts_expand',
      payload: {
        connection_id: connection.id,
        allowed_hosts: ['api.additional.invalid'],
      },
    }));
  });
});
