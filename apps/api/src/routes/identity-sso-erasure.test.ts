import Fastify from 'fastify';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { createErrorHandler } from '../middleware/error-handler.js';
import { registerIdentityRoutes } from './identity.js';

describe('legacy public SSO handoff redemption', () => {
  const app = Fastify();
  app.setErrorHandler(createErrorHandler());

  afterAll(async () => {
    await app.close();
  });

  it('returns no identity and cannot consume a new browser-bound handoff', async () => {
    const getdel = vi.fn();
    registerIdentityRoutes(app, {
      redis: { getdel },
    } as never);
    await app.ready();

    const response = await app.inject({
      method: 'POST',
      url: '/v1/identity/sso/handoff',
      payload: { ref: 'ssoh_synthetic' },
    });

    expect(response.statusCode).toBe(404);
    expect(response.json().error.code).toBe('NOT_FOUND');
    expect(getdel).not.toHaveBeenCalled();
  });
});
