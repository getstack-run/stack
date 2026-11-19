import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GovernanceApprovalRequiredError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    // A token ending in -console is the Console's own signed-in session: the person is there.
    const raw = String((request['headers'] as { authorization?: string }).authorization ?? '').replace(/^Bearer /, '');
    request['isDashboardSession'] = raw.endsWith('-console');
    const token = raw.replace(/-console$/, '');
    request['operatorId'] = token === 'foreign' ? 'op_other' : 'op_owner';
    request['operatorTier'] = 'enterprise';
    request['isAdmin'] = false;
    request['isPlatformStaff'] = false;
    request['isPartner'] = false;
    if (['admin', 'standard', 'readonly'].includes(token)) {
      request['memberId'] = `mem_${token}`;
      request['memberRole'] = token;
    }
    if (token === 'agent') request['agentId'] = 'agt_owner';
  },
}));

import { registerIdentityRoutes } from './identity.js';

const apps: ReturnType<typeof Fastify>[] = [];
const requirementInput = {
  layer: 'humanity',
  requires_claim: 'verified_human',
  minimum_assurance: 'substantial',
  accepted_providers: ['stripe_identity'],
};
const requirementRow = {
  id: 'sir_owner',
  operator_id: 'op_owner',
  service_id: 'svc_owner',
  ...requirementInput,
  required_scopes: null,
  requires_pii: false,
  lawful_basis: null,
};

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const identity = {
    getServiceRequirements: vi.fn(async () => [requirementRow]),
    setServiceRequirement: vi.fn(async () => requirementRow),
    replaceServiceRequirement: vi.fn(async (_operatorId, _serviceId, input) =>
      input === null ? [] : [requirementRow]),
    deleteServiceRequirement: vi.fn(async () => undefined),
  };
  const governanceApprovals = {
    requireApproval: vi.fn(async () => { throw new GovernanceApprovalRequiredError('gvr_new', 'https://getstack.run/app/approve/gvr_new', 'operator'); }),
    consume: vi.fn(async () => undefined),
  };
  const serviceConnection = {
    findActiveByServiceId: vi.fn(async (operatorId: string, serviceId: string) =>
      operatorId === 'op_owner' && serviceId === 'svc_owner' ? { id: 'scon_owner' } : undefined),
  };
  const services = {
    identity,
    serviceConnection,
    governanceApprovals,
    audit: { write: vi.fn(async () => undefined) },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerIdentityRoutes(app, services as never);
  await app.ready();
  return { app, identity, serviceConnection, governanceApprovals };
}

describe('service identity requirement routes', () => {
  it('keeps GET as a raw operator-scoped array', async () => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: 'Bearer readonly' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual([requirementRow]);
    expect(identity.getServiceRequirements).toHaveBeenCalledWith('op_owner', 'svc_owner');
  });

  it.each(['standard', 'readonly'])('denies POST policy writes to a %s member', async (token) => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: `Bearer ${token}` },
      payload: requirementInput,
    });

    expect(response.statusCode).toBe(403);
    expect(identity.setServiceRequirement).not.toHaveBeenCalled();
  });

  it.each(['owner', 'admin'])('allows %s to append a compatible requirement', async (token) => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: `Bearer ${token}` },
      payload: requirementInput,
    });

    expect(response.statusCode).toBe(201);
    expect(identity.setServiceRequirement).toHaveBeenCalledOnce();
  });

  it('atomically replaces the service policy with the canonical wrapper', async () => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: 'Bearer admin' },
      payload: { requirement: requirementInput },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ requirements: [requirementRow] });
    expect(identity.replaceServiceRequirement).toHaveBeenCalledWith(
      'op_owner',
      'svc_owner',
      expect.objectContaining(requirementInput),
    );
  });

  it('denies atomic policy replacement to a standard member', async () => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: 'Bearer standard' },
      payload: { requirement: requirementInput },
    });

    expect(response.statusCode).toBe(403);
    expect(identity.replaceServiceRequirement).not.toHaveBeenCalled();
  });

  it('removes all service requirements when PUT receives null, from the Console\'s own session', async () => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: 'Bearer owner-console' },
      payload: { requirement: null },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ requirements: [] });
    expect(identity.replaceServiceRequirement).toHaveBeenCalledWith('op_owner', 'svc_owner', null);
  });

  it('hides a service that the operator does not own', async () => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/services/svc_foreign/requirements',
      headers: { authorization: 'Bearer owner' },
      payload: { requirement: requirementInput },
    });

    expect(response.statusCode).toBe(404);
    expect(identity.replaceServiceRequirement).not.toHaveBeenCalled();
  });

  it('binds DELETE to the operator, service, and requirement id', async () => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'DELETE',
      url: '/v1/services/svc_owner/requirements/sir_owner',
      headers: { authorization: 'Bearer admin-console' },
    });

    expect(response.statusCode).toBe(204);
    expect(identity.deleteServiceRequirement).toHaveBeenCalledWith(
      'op_owner',
      'svc_owner',
      'sir_owner',
    );
  });

  it.each(['owner', 'admin'])('lets %s remove every requirement from a key or an OAuth token, asking nobody', async (token) => {
    const { app, identity, governanceApprovals } = await makeApp();
    const response = await app.inject({
      method: 'PUT',
      url: '/v1/services/svc_owner/requirements',
      headers: { authorization: `Bearer ${token}` },
      payload: { requirement: null },
    });
    expect(response.statusCode).toBe(200);
    expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
    expect(identity.replaceServiceRequirement).toHaveBeenCalledWith('op_owner', 'svc_owner', null);
  });

  it('replaces a requirement with a weaker, an equal or a stricter one, asking nobody', async () => {
    for (const requirement of [{ ...requirementInput, minimum_assurance: 'low' }, requirementInput, { ...requirementInput, minimum_assurance: 'high' }]) {
      const { app, identity, governanceApprovals } = await makeApp();
      expect((await app.inject({
        method: 'PUT', url: '/v1/services/svc_owner/requirements', headers: { authorization: 'Bearer admin' }, payload: { requirement },
      })).statusCode).toBe(200);
      expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
      expect(identity.replaceServiceRequirement).toHaveBeenCalledTimes(1);
    }
  });

  it('removes a requirement with DELETE from a key or an OAuth token, asking nobody', async () => {
    const { app, identity, governanceApprovals } = await makeApp();
    const response = await app.inject({
      method: 'DELETE', url: '/v1/services/svc_owner/requirements/sir_owner', headers: { authorization: 'Bearer admin' },
    });
    expect(response.statusCode).toBe(204);
    expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
    expect(identity.deleteServiceRequirement).toHaveBeenCalledWith('op_owner', 'svc_owner', 'sir_owner');
  });

  it('lets an append through free, since adding a requirement only tightens', async () => {
    const { app, governanceApprovals } = await makeApp();
    expect((await app.inject({
      method: 'POST', url: '/v1/services/svc_owner/requirements', headers: { authorization: 'Bearer admin' }, payload: requirementInput,
    })).statusCode).toBe(201);
    expect(governanceApprovals.requireApproval).not.toHaveBeenCalled();
  });

  it.each(['standard', 'readonly', 'agent'])('denies DELETE to %s', async (token) => {
    const { app, identity } = await makeApp();
    const response = await app.inject({
      method: 'DELETE',
      url: '/v1/services/svc_owner/requirements/sir_owner',
      headers: { authorization: `Bearer ${token}` },
    });

    expect(response.statusCode).toBe(403);
    expect(identity.deleteServiceRequirement).not.toHaveBeenCalled();
  });
});
