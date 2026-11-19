import Fastify, { type FastifyInstance } from 'fastify';
import { NO_BROWSER_SESSIONS } from '../../lib/browser-session.js';
import { describe, expect, it } from 'vitest';
import type { Services } from '../../config/services.js';
import { handleDeviceDecision } from './device-decision.js';
import { handleRevocation } from './revocation.js';
import { handleTokenRequest } from './token-endpoint.js';
import { readOAuthParams, sendOAuthError } from './responses.js';

/**
 * OAuth endpoints answer in the flat shape the specifications fix (RFC 6749
 * section 5.2, RFC 8628, RFC 7591), not in the API error envelope. Every such
 * answer is written by `sendOAuthError`.
 */

describe('sendOAuthError', () => {
  async function send(status: number, error: string, description?: string) {
    const app = Fastify();
    app.get('/e', (_request, reply) => sendOAuthError(reply, status, error, description));
    const response = await app.inject({ method: 'GET', url: '/e' });
    await app.close();
    return response;
  }

  it('sends error and error_description at the top level with the given status', async () => {
    const response = await send(400, 'invalid_grant', 'code expired');
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: 'invalid_grant', error_description: 'code expired' });
  });

  it('omits error_description when there is none', async () => {
    const response = await send(401, 'access_denied');
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: 'access_denied' });
  });
});

describe('readOAuthParams', () => {
  it('reads single string values and treats an absent body as no parameters', () => {
    expect(readOAuthParams({ grant_type: 'refresh_token', client_id: 'c' })).toEqual({ grant_type: 'refresh_token', client_id: 'c' });
    expect(readOAuthParams(undefined)).toEqual({});
    expect(readOAuthParams(null)).toEqual({});
  });

  it('refuses repeated, non-string and non-object parameters', () => {
    expect(readOAuthParams({ resource: ['a', 'b'] })).toBeNull();
    expect(readOAuthParams({ client_id: 7 })).toBeNull();
    expect(readOAuthParams('grant_type=refresh_token')).toBeNull();
    expect(readOAuthParams(['x'])).toBeNull();
  });
});

describe('OAuth routes keep the flat wire shape', () => {
  const services = { browserSessions: NO_BROWSER_SESSIONS } as unknown as Services;

  function appWith(register: (app: FastifyInstance) => void) {
    const app = Fastify();
    register(app);
    return app;
  }

  it('answers the token endpoint with invalid_request for a parameter that is not a string', async () => {
    const app = appWith((a) => a.post('/oauth/token', (request, reply) => handleTokenRequest(services, request, reply)));
    const response = await app.inject({ method: 'POST', url: '/oauth/token', payload: { grant_type: ['refresh_token'] } });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: 'invalid_request',
      error_description: 'request parameters must each be a single string value',
    });
    await app.close();
  });

  it('answers the token endpoint with unsupported_grant_type for an unknown grant', async () => {
    const app = appWith((a) => a.post('/oauth/token', (request, reply) => handleTokenRequest(services, request, reply)));
    const response = await app.inject({ method: 'POST', url: '/oauth/token', payload: { grant_type: 'password' } });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: 'unsupported_grant_type' });
    await app.close();
  });

  it('answers revocation of a malformed request with invalid_request', async () => {
    const app = appWith((a) => a.post('/oauth/revoke', (request, reply) => handleRevocation(
      { services, db: {} as Services['db'], clientMetadata: {} as never }, request, reply,
    )));
    const response = await app.inject({ method: 'POST', url: '/oauth/revoke', payload: { token: 5 } });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe('invalid_request');
    await app.close();
  });

  it('answers the device decision endpoint without a user_code with invalid_request', async () => {
    const app = appWith((a) => a.post('/oauth/device/approve', (request, reply) => handleDeviceDecision(services, request, reply, 'approve')));
    for (const payload of [{}, { user_code: '' }]) {
      const response = await app.inject({ method: 'POST', url: '/oauth/device/approve', payload });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: 'invalid_request', error_description: 'user_code required' });
    }
    await app.close();
  });

  it('answers the device decision endpoint without a session with access_denied', async () => {
    const app = appWith((a) => a.post('/oauth/device/deny', (request, reply) => handleDeviceDecision(services, request, reply, 'deny')));
    const response = await app.inject({ method: 'POST', url: '/oauth/device/deny', payload: { user_code: 'WDJB-MJHT' } });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: 'access_denied' });
    await app.close();
  });
});

describe('no OAuth route builds the error object by hand', () => {
  it('has no inline { error: ... } send outside responses.ts', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const { dirname, join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const dir = dirname(fileURLToPath(import.meta.url));
    const offenders = readdirSync(dir)
      .filter((name) => name.endsWith('.ts') && !name.endsWith('.test.ts') && name !== 'responses.ts')
      .filter((name) => /\.send\(\s*\{\s*error\s*:/.test(readFileSync(join(dir, name), 'utf8')));
    expect(offenders).toEqual([]);
  });
});
