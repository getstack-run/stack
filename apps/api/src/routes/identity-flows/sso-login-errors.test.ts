import { afterEach, describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { hostedFeatureGate } from '../../config/licence-service.js';
import type { Services } from '../../config/services.js';
import { createErrorHandler } from '../../middleware/error-handler.js';
import { handleOidcCallback, redeemSsoHandoff, startSsoLogin } from './sso-login.js';

/**
 * The SSO routes answer a browser. Each refusal is a thrown StackError the
 * central handler serialises into the API error envelope, and the cookie
 * header set before a refusal still reaches the browser.
 */

const STATE = 'oidc_state_value';
const BINDING_HASH = 'a'.repeat(64);

function servicesStub(options: {
  provider?: unknown;
  loginState?: string | null;
} = {}) {
  return {
    identity: { getProvider: vi.fn(() => ('provider' in options ? options.provider : { acceptCallback: vi.fn(async () => ({})) })) },
    redis: { get: vi.fn(async () => options.loginState ?? null), del: vi.fn(async () => 1), set: vi.fn(async () => 'OK') },
    oidcIdpConfigRepo: { findBySsoSlug: vi.fn(async () => null) },
    features: hostedFeatureGate,
  } as unknown as Services;
}

describe('SSO login errors', () => {
  const apps: Array<ReturnType<typeof Fastify>> = [];
  afterEach(async () => {
    while (apps.length) await apps.pop()!.close();
  });

  function build(services: Services) {
    const app = Fastify();
    app.setErrorHandler(createErrorHandler());
    apps.push(app);
    app.get('/callback', (request, reply) => handleOidcCallback(request, reply, services));
    app.get<{ Params: { slug: string }; Querystring: { browser_binding?: string } }>(
      '/start/:slug', (request, reply) => startSsoLogin(request, reply, services));
    app.post('/handoff', (request, reply) => redeemSsoHandoff(request, reply));
    return app;
  }

  it('refuses a start without a browser binding with 400 BROWSER_BINDING_REQUIRED', async () => {
    const res = await build(servicesStub()).inject({ method: 'GET', url: '/start/acme' });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('BROWSER_BINDING_REQUIRED');
  });

  it('refuses a callback without code or state with 400 SSO_CALLBACK_INVALID', async () => {
    const res = await build(servicesStub()).inject({ method: 'GET', url: '/callback?code=abc' });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('SSO_CALLBACK_INVALID');
  });

  it('refuses a callback carrying more than one code with 400 VALIDATION_ERROR', async () => {
    const res = await build(servicesStub()).inject({ method: 'GET', url: `/callback?code=a&code=b&state=${STATE}` });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('VALIDATION_ERROR');
  });

  it('relays an upstream error as 400 SSO_UPSTREAM_ERROR with the provider description', async () => {
    const res = await build(servicesStub()).inject({
      method: 'GET', url: '/callback?error=access_denied&error_description=user%20cancelled',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatchObject({ code: 'SSO_UPSTREAM_ERROR', message: 'user cancelled' });
  });

  it('answers a missing OIDC provider with 503 SSO_PROVIDER_UNAVAILABLE', async () => {
    const res = await build(servicesStub({ provider: undefined })).inject({
      method: 'GET', url: `/callback?code=abc&state=${STATE}`,
    });
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe('SSO_PROVIDER_UNAVAILABLE');
  });

  it('answers a state the provider rejects with 400 SSO_STATE_INVALID', async () => {
    const provider = { acceptCallback: vi.fn(async () => { throw new Error('state unknown'); }) };
    const res = await build(servicesStub({ provider })).inject({
      method: 'GET', url: `/callback?code=abc&state=${STATE}`,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatchObject({ code: 'SSO_STATE_INVALID', message: 'state unknown' });
  });

  it('answers unreadable login state with 400 SSO_STATE_INVALID', async () => {
    const res = await build(servicesStub({ loginState: '{not json' })).inject({
      method: 'GET', url: `/callback?code=abc&state=${STATE}`,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('SSO_STATE_INVALID');
  });

  it('refuses a callback from another browser with 400 SSO_STATE_NOT_BOUND and still clears the state cookie', async () => {
    const loginState = JSON.stringify({ config_id: 'cfg_1', browser_binding_hash: BINDING_HASH });
    const res = await build(servicesStub({ loginState })).inject({
      method: 'GET', url: `/callback?code=abc&state=${STATE}`,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('SSO_STATE_NOT_BOUND');
    expect(res.headers['set-cookie']).toContain('stack_sso_state=; HttpOnly');
    expect(res.headers['set-cookie']).toContain('Max-Age=0');
  });

  it('keeps the legacy handoff redemption inert with 404 NOT_FOUND', async () => {
    const res = await build(servicesStub()).inject({ method: 'POST', url: '/handoff', payload: {} });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('NOT_FOUND');
  });
});
