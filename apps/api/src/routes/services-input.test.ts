import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';

/**
 * Service connection routes read their bodies through schemas. A malformed
 * body is a 400 with the standard validation envelope; a valid one still
 * reaches the service with the same arguments as before.
 */

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    request['operatorId'] = 'op_owner';
    request['operatorTier'] = 'pro';
    request['memberId'] = 'mem_self';
    request['memberRole'] = 'admin';
  },
}));
vi.mock('../middleware/governance-stepup.js', () => ({ enforceGovernanceStepUp: vi.fn(async () => undefined) }));

const { registerServiceRoutes } = await import('./services.js');

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const connection = { id: 'scon_1', provider: 'slack', status: 'active' };
  const serviceConnection = {
    assertConnectionAccess: vi.fn(),
    connect: vi.fn(async () => connection),
    connectCustom: vi.fn(async () => connection),
    proxyChangeWeakens: vi.fn(async () => false),
    setProxyEnabled: vi.fn(async () => connection),
    allowedHostsChangeWidens: vi.fn(async () => false),
    setAllowedHosts: vi.fn(async () => connection),
  };
  const services = {
    serviceConnection,
    audit: { write: vi.fn(async () => undefined) },
    analytics: { fireOnce: vi.fn() },
  } as unknown as Services;
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerServiceRoutes(app, services);
  await app.ready();
  return { app, serviceConnection };
}

function post(app: ReturnType<typeof Fastify>, url: string, payload?: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: { authorization: 'Bearer operator', 'content-type': 'application/json' },
    ...(payload === undefined ? {} : { payload: JSON.stringify(payload) }),
  });
}

function expectValidationError(res: { statusCode: number; json: () => { error: { code: string } } }) {
  expect(res.statusCode).toBe(400);
  expect(res.json().error.code).toBe('VALIDATION_ERROR');
}

describe('POST /v1/services/connect', () => {
  it.each([
    ['an array', []],
    ['an object without scopes', { service_id: 'svc_slack', oauth_token: 'xoxb' }],
    ['an object without oauth_token', { service_id: 'svc_slack', scopes: ['chat:write'] }],
    ['a non-string oauth_token', { service_id: 'svc_slack', scopes: ['chat:write'], oauth_token: 5 }],
  ])('rejects %s', async (_label, payload) => {
    const { app, serviceConnection } = await makeApp();
    expectValidationError(await post(app, '/v1/services/connect', payload));
    expect(serviceConnection.connect).not.toHaveBeenCalled();
  });

  it('connects with the token and without the extra body fields', async () => {
    const { app, serviceConnection } = await makeApp();
    const res = await post(app, '/v1/services/connect', {
      service_id: 'svc_slack',
      scopes: ['chat:write'],
      oauth_token: 'xoxb-fixture',
      member_id: 'mem_self',
      unrelated: true,
    });
    expect(res.statusCode).toBe(201);
    expect(serviceConnection.connect).toHaveBeenCalledWith(
      'op_owner',
      'pro',
      { service_id: 'svc_slack', scopes: ['chat:write'], oauth_token: 'xoxb-fixture' },
      'mem_self',
      'mem_self',
    );
  });

  it('still refuses to connect on behalf of another member', async () => {
    const { app, serviceConnection } = await makeApp();
    const res = await post(app, '/v1/services/connect', {
      service_id: 'svc_slack',
      scopes: ['chat:write'],
      oauth_token: 'xoxb-fixture',
      member_id: 'mem_other',
    });
    expect(res.statusCode).toBe(403);
    expect(serviceConnection.connect).not.toHaveBeenCalled();
  });
});

describe('POST /v1/services/custom', () => {
  it.each([
    ['an array', []],
    ['an object without a name', { credential: 'k' }],
    ['a name of the wrong type', { name: 7 }],
  ])('rejects %s', async (_label, payload) => {
    const { app, serviceConnection } = await makeApp();
    expectValidationError(await post(app, '/v1/services/custom', payload));
    expect(serviceConnection.connectCustom).not.toHaveBeenCalled();
  });

  it('connects a valid custom service', async () => {
    const { app, serviceConnection } = await makeApp();
    const res = await post(app, '/v1/services/custom', { name: 'internal-api', credential: 'k', allowed_hosts: ['api.example.test'] });
    expect(res.statusCode).toBe(201);
    expect(serviceConnection.connectCustom).toHaveBeenCalledWith(
      'op_owner',
      'pro',
      { name: 'internal-api', credential: 'k', allowed_hosts: ['api.example.test'] },
      'mem_self',
      'mem_self',
    );
  });

  it('still refuses to connect on behalf of another member', async () => {
    const { app, serviceConnection } = await makeApp();
    const res = await post(app, '/v1/services/custom', { name: 'internal-api', member_id: 'mem_other' });
    expect(res.statusCode).toBe(403);
    expect(serviceConnection.connectCustom).not.toHaveBeenCalled();
  });
});

describe('POST /v1/services/:id/proxy-toggle', () => {
  it.each([
    ['an array', []],
    ['an empty object', {}],
    ['a non-boolean value', { proxy_enabled: 'yes' }],
  ])('rejects %s', async (_label, payload) => {
    const { app, serviceConnection } = await makeApp();
    expectValidationError(await post(app, '/v1/services/scon_1/proxy-toggle', payload));
    expect(serviceConnection.setProxyEnabled).not.toHaveBeenCalled();
  });

  it('applies a valid toggle', async () => {
    const { app, serviceConnection } = await makeApp();
    const res = await post(app, '/v1/services/scon_1/proxy-toggle', { proxy_enabled: false });
    expect(res.statusCode).toBe(200);
    expect(serviceConnection.setProxyEnabled).toHaveBeenCalledWith('scon_1', 'op_owner', false, undefined, false);
  });
});

describe('POST /v1/services/:id/allowed-hosts', () => {
  it.each([
    ['an array', []],
    ['an empty object', {}],
    ['a non-array value', { allowed_hosts: 'api.example.test' }],
    ['an array holding a non-string', { allowed_hosts: ['api.example.test', 3] }],
  ])('rejects %s', async (_label, payload) => {
    const { app, serviceConnection } = await makeApp();
    expectValidationError(await post(app, '/v1/services/scon_1/allowed-hosts', payload));
    expect(serviceConnection.setAllowedHosts).not.toHaveBeenCalled();
  });

  it('applies a valid host list', async () => {
    const { app, serviceConnection } = await makeApp();
    const res = await post(app, '/v1/services/scon_1/allowed-hosts', { allowed_hosts: ['api.example.test'] });
    expect(res.statusCode).toBe(200);
    expect(serviceConnection.setAllowedHosts).toHaveBeenCalledWith('scon_1', 'op_owner', ['api.example.test'], undefined, false);
  });
});
