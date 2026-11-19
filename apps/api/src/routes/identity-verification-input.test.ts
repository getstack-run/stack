import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';
import { registerIdentityRoutes } from './identity.js';

// The real auth middleware needs the full service graph; these tests are about
// how the routes read their body, so authenticate as a fixed operator.
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: { operatorId: string }) => {
    request.operatorId = 'op_owner';
  },
}));

const apps: Array<ReturnType<typeof Fastify>> = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

const syncable = { keys: ['stripe_identity'] as string[] };

function harness() {
  syncable.keys = ['stripe_identity'];
  const syncProviderSessions = vi.fn(async (_operatorId: string, _providerKey: string) => ({ synced: 0 }));
  const completeWithToken = vi.fn(async (_operatorId: string, _provider: string, _ref: string, _token: string) => ({
    success: false,
    claims: [],
  }));
  const services = {
    identity: { syncProviderSessions, completeWithToken, syncableProviderKeys: () => syncable.keys },
    audit: { write: vi.fn(async () => undefined) },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerIdentityRoutes(app, services as unknown as Services);
  return { app, syncProviderSessions, completeWithToken };
}

function post(app: ReturnType<typeof Fastify>, url: string, payload?: unknown) {
  return app.inject({
    method: 'POST',
    url,
    ...(payload === undefined ? {} : { headers: { 'content-type': 'application/json' }, payload: JSON.stringify(payload) }),
  });
}

describe('POST /v1/identity/verify/sync body', () => {
  it('answers a non-string provider_key with 400 VALIDATION_ERROR', async () => {
    const { app, syncProviderSessions } = harness();
    const response = await post(app, '/v1/identity/verify/sync', { provider_key: 9 });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(syncProviderSessions).not.toHaveBeenCalled();
  });

  it.each([
    ['no body', undefined, 'stripe_identity'],
    ['an empty object', {}, 'stripe_identity'],
    ['a null provider_key', { provider_key: null }, 'stripe_identity'],
    ['a provider_key', { provider_key: 'turnstile' }, 'turnstile'],
  ])('syncs with %s', async (_name, payload, providerKey) => {
    const { app, syncProviderSessions } = harness();
    const response = await post(app, '/v1/identity/verify/sync', payload);
    expect(response.statusCode).toBe(200);
    expect(syncProviderSessions).toHaveBeenCalledWith('op_owner', providerKey);
  });
});

describe('POST /v1/identity/verify/sync with no provider named', () => {
  it('says so plainly when the installation has no provider that can be synced, and syncs nothing', async () => {
    const { app, syncProviderSessions } = harness();
    syncable.keys = [];
    const response = await post(app, '/v1/identity/verify/sync', {});
    expect(response.statusCode).toBe(409);
    expect(response.json().error.message).toBe('No identity verification provider is registered on this installation');
    expect(syncProviderSessions).not.toHaveBeenCalled();
  });

  it('asks the caller to name one when several could be synced', async () => {
    const { app, syncProviderSessions } = harness();
    syncable.keys = ['one', 'two'];
    const response = await post(app, '/v1/identity/verify/sync', {});
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('INVALID_REQUEST');
    expect(syncProviderSessions).not.toHaveBeenCalled();
  });

  it('still takes the key the caller names, whatever is registered', async () => {
    const { app, syncProviderSessions } = harness();
    syncable.keys = [];
    const response = await post(app, '/v1/identity/verify/sync', { provider_key: 'one' });
    expect(response.statusCode).toBe(200);
    expect(syncProviderSessions).toHaveBeenCalledWith('op_owner', 'one');
  });
});

describe('POST /v1/identity/verify/token body', () => {
  // This route has its own documented error code, so it answers itself.
  it.each([
    ['no body', undefined],
    ['an empty object', {}],
    ['a missing token', { provider_key: 'turnstile', session_ref: 'ref' }],
    ['an empty session_ref', { provider_key: 'turnstile', session_ref: '', token: 't' }],
    ['a non-string token', { provider_key: 'turnstile', session_ref: 'ref', token: 1 }],
  ])('answers %s with 400 INVALID_INPUT', async (_name, payload) => {
    const { app, completeWithToken } = harness();
    const response = await post(app, '/v1/identity/verify/token', payload);
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: { code: 'INVALID_INPUT', message: 'provider_key, session_ref, and token are required' },
    });
    expect(completeWithToken).not.toHaveBeenCalled();
  });

  it('reaches the provider for a complete body', async () => {
    const { app, completeWithToken } = harness();
    const response = await post(app, '/v1/identity/verify/token', {
      provider_key: 'turnstile', session_ref: 'ref_1', token: 'widget-token', extra: true,
    });
    expect(response.statusCode).toBe(200);
    expect(completeWithToken).toHaveBeenCalledWith('op_owner', 'turnstile', 'ref_1', 'widget-token');
  });
});
