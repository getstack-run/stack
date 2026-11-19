import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { registerStagingNoindex } from './staging-noindex.js';

async function app(enabled: boolean) {
  const instance = Fastify();
  registerStagingNoindex(instance, enabled);
  // A child context, as every route module is registered in one.
  await instance.register(async (child) => {
    child.get('/ok', async () => ({ ok: true }));
    child.get('/fails', async () => {
      throw new Error('boom');
    });
    child.post('/refused', async (_request, reply) => reply.status(403).send({ error: { code: 'FORBIDDEN' } }));
  });
  await instance.ready();
  return instance;
}

describe('the staging noindex header', () => {
  const env = { staging: process.env['STACK_STAGING'], list: process.env['STAGING_SIGNIN_ALLOWLIST'] };
  afterEach(() => {
    for (const [name, value] of [['STACK_STAGING', env.staging], ['STAGING_SIGNIN_ALLOWLIST', env.list]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it('is on every answer of a staging deployment: success, refusal, error and not found', async () => {
    const instance = await app(true);
    for (const request of [
      { method: 'GET' as const, url: '/ok' },
      { method: 'POST' as const, url: '/refused' },
      { method: 'GET' as const, url: '/fails' },
      { method: 'GET' as const, url: '/nowhere' },
    ]) {
      const response = await instance.inject(request);
      expect(response.headers['x-robots-tag'], `${request.method} ${request.url}`).toBe('noindex, nofollow');
    }
    await instance.close();
  });

  it('is absent outside staging, so production answers are unchanged', async () => {
    const instance = await app(false);
    for (const url of ['/ok', '/nowhere']) {
      const response = await instance.inject({ method: 'GET', url });
      expect(response.headers['x-robots-tag']).toBeUndefined();
    }
    await instance.close();
  });

  it('follows STACK_STAGING when the caller names nothing', async () => {
    process.env['STACK_STAGING'] = 'true';
    process.env['STAGING_SIGNIN_ALLOWLIST'] = 'tester@example.com';
    const on = Fastify();
    registerStagingNoindex(on);
    on.get('/ok', async () => ({ ok: true }));
    expect((await on.inject({ method: 'GET', url: '/ok' })).headers['x-robots-tag']).toBe('noindex, nofollow');
    await on.close();
    delete process.env['STACK_STAGING'];
    const off = Fastify();
    registerStagingNoindex(off);
    off.get('/ok', async () => ({ ok: true }));
    expect((await off.inject({ method: 'GET', url: '/ok' })).headers['x-robots-tag']).toBeUndefined();
    await off.close();
  });

  it('is registered on the API before any plugin or route', () => {
    const start = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'start.ts'), 'utf8');
    const hook = start.indexOf('registerStagingNoindex(app)');
    expect(hook).toBeGreaterThan(0);
    for (const later of ['app.register(cors', 'app.register(helmet', 'app.register(rateLimit', 'ext.plugins(app)']) {
      expect(start.indexOf(later), later).toBeGreaterThan(hook);
    }
  });
});
