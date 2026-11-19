import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Services } from '../config/services.js';
import { createErrorHandler } from '../middleware/error-handler.js';
import { ProviderOAuthError } from '../services/provider-oauth-service.js';
import type { ConsoleBridge } from '../lib/browser-session.js';

// The proxy secret and the session middleware need the full service graph;
// these tests are about how the routes fail, so the Console's proxy check
// passes and the session is whatever the test header says.
const consoleBridge: ConsoleBridge = {
  proxyAuth: () => async () => undefined,
  privateResponse: (reply) => reply.header('Cache-Control', 'private, no-store'),
  connectLinkPrincipal: () => ({ operatorId: 'op_owner', operatorTier: 'pro' }),
  connectLinks: {
    resolveForSession: async () => { throw new Error('no connect link in this test'); },
    completeWithOAuth: async () => undefined,
  },
};
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: {
    operatorId: string;
    operatorTier: string;
    isDashboardSession?: boolean;
    memberId?: string;
    memberRole?: string;
    headers: Record<string, string | string[] | undefined>;
  }) => {
    request.operatorId = 'op_owner';
    request.operatorTier = 'pro';
    request.isDashboardSession = request.headers['x-test-session'] !== 'none';
    if (request.headers['x-test-member']) {
      request.memberId = 'mem_1';
      request.memberRole = String(request.headers['x-test-member']);
    }
  },
}));

const { registerProviderOAuthRoutes } = await import('./provider-oauth.js');

const apps: Array<ReturnType<typeof Fastify>> = [];
afterEach(async () => Promise.all(apps.splice(0).map((app) => app.close())));

function harness(providerOAuth: Record<string, unknown> = {}) {
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerProviderOAuthRoutes(app, { providerOAuth, consoleBridge } as unknown as Services);
  return app;
}

const callbackBody = { code: 'c', state: 's' };

describe('provider OAuth routes without a Console', () => {
  it('answer NOT_CONFIGURED before any credential is read', async () => {
    const app = Fastify();
    apps.push(app);
    app.setErrorHandler(createErrorHandler());
    registerProviderOAuthRoutes(app, { providerOAuth: {}, consoleBridge: null } as unknown as Services);
    for (const url of ['/internal/provider-oauth/authorize', '/internal/provider-oauth/callback']) {
      const response = await app.inject({ method: 'POST', url, payload: { provider: 'github', code: 'c', state: 's' } });
      expect(response.statusCode).toBe(404);
      expect(response.json().error.code).toBe('NOT_CONFIGURED');
    }
  });
});

describe('provider OAuth route errors', () => {
  it('refuses a request that is not a dashboard session with 401 UNAUTHORIZED and no-store headers', async () => {
    const response = await harness().inject({
      method: 'POST', url: '/internal/provider-oauth/authorize', headers: { 'x-test-session': 'none' },
      payload: { provider: 'github' },
    });
    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe('UNAUTHORIZED');
    expect(response.headers['cache-control']).toContain('no-store');
  });

  it('refuses a read-only member with 403 FORBIDDEN', async () => {
    const response = await harness().inject({
      method: 'POST', url: '/internal/provider-oauth/authorize', headers: { 'x-test-member': 'readonly' },
      payload: { provider: 'github' },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe('FORBIDDEN');
  });

  it('answers a malformed authorize body with 400 VALIDATION_ERROR', async () => {
    const authorize = vi.fn();
    const response = await harness({ authorize }).inject({
      method: 'POST', url: '/internal/provider-oauth/authorize', payload: { provider: 'Not Valid!' },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
    expect(authorize).not.toHaveBeenCalled();
  });

  it('carries the reason and the page to return to when a connection fails', async () => {
    const callback = vi.fn(async () => { throw new ProviderOAuthError('token_exchange_failed', 503).withReturnTo('connect'); });
    const response = await harness({ callback }).inject({
      method: 'POST', url: '/internal/provider-oauth/callback', payload: callbackBody,
    });
    expect(response.statusCode).toBe(503);
    expect(response.json().error).toMatchObject({
      code: 'token_exchange_failed',
      details: { return_to: 'connect' },
    });
    expect(response.headers['cache-control']).toContain('no-store');
  });

  it('omits return_to when the failure happened before the state was read', async () => {
    const callback = vi.fn(async () => { throw new ProviderOAuthError('invalid_state', 401); });
    const response = await harness({ callback }).inject({
      method: 'POST', url: '/internal/provider-oauth/callback', payload: callbackBody,
    });
    expect(response.statusCode).toBe(401);
    expect(response.json().error.code).toBe('invalid_state');
    expect(response.json().error.details).toBeUndefined();
  });

  it('answers an unexpected failure with a generic 500 that leaks nothing', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const callback = vi.fn(async () => { throw new Error('connect ECONNREFUSED 10.0.0.5:5432'); });
      const response = await harness({ callback }).inject({
        method: 'POST', url: '/internal/provider-oauth/callback', payload: callbackBody,
      });
      expect(response.statusCode).toBe(500);
      expect(response.json().error).toEqual({ code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' });
    } finally {
      errorSpy.mockRestore();
    }
  });
});
