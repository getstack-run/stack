import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { PASSPORT_TOKEN_MAX_CHARS } from '@stack/shared';
import { API_HTTP_OPTIONS } from './http-options.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

describe('the API server', () => {
  it('reads a request whose headers carry a Passport of the longest length STACK signs', async () => {
    const app = Fastify({ http: API_HTTP_OPTIONS });
    apps.push(app);
    app.get('/echo', async (request) => ({ length: String(request.headers['x-passport-token'] ?? '').length }));
    const address = await app.listen({ port: 0, host: '127.0.0.1' });
    const response = await fetch(`${address}/echo`, { headers: { 'x-passport-token': 'p'.repeat(PASSPORT_TOKEN_MAX_CHARS) } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ length: PASSPORT_TOKEN_MAX_CHARS });
  });
});
