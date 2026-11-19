import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createDb, operators, serviceConnections, services, securityEvents } from '@stack/shared';
import { eq } from 'drizzle-orm';
import { ServiceRepository } from '../repositories/service-repo.js';
import { ServiceConnectionService, standaloneServiceConnectionHooks } from './service-connection-service.js';

vi.mock('@stack/shared', async importOriginal => ({
  ...await importOriginal<object>(),
  assertPublicUrl: async (url: string) => new URL(url),
  publicFetch: (url: string, init: RequestInit) => globalThis.fetch(url, init),
}));

const databaseUrl = process.env['STACK_FLEET_TEST_DATABASE_URL'];
if (databaseUrl) {
  const url = new URL(databaseUrl);
    if (!['127.0.0.1', 'localhost'].includes(url.hostname) || !['/stack_fleet_verification', '/stack_fleet_e2e_20260924'].includes(url.pathname)) {
    throw new Error('Renewal integration test requires the isolated local fleet fixture');
  }
}

(databaseUrl ? describe : describe.skip)('PostgreSQL connection renewal', () => {
  const db = createDb(databaseUrl ?? 'postgresql://unused:unused@127.0.0.1:56369/stack_fleet_verification');
  const suffix = randomUUID().replaceAll('-', '');
  const operator = `op_renew_${suffix}`;
  const provider = `custom_renew_${suffix}`;
  const serviceId = `svc_renew_${suffix}`;
  const connectionId = `scon_renew_${suffix}`;
  const encode = (value: string) => Buffer.from(value).toString('base64');
  const initial = { access_token: 'synthetic-old', refresh_token: 'synthetic-rotate-once', expires_at: 1 };
  const kms = { encrypt: async (value: string) => ({ ciphertext: encode(value), keyRef: 'fixture-key' }),
    decrypt: async (value: string) => Buffer.from(value, 'base64').toString() };
  const repo = new ServiceRepository(db);
  beforeAll(async () => {
    await db.insert(operators).values({ id: operator, email: `${operator}@test.invalid`, api_key_hash: suffix });
    await db.insert(services).values({ id: serviceId, operator_id: operator, provider, name: 'Renewal fixture',
      description: 'Synthetic provider', available: false, oauth_auth_url: '', oauth_token_url: 'https://synthetic.example.test/token', scopes_available: ['read'] });
    await repo.createConnection({ id: connectionId, operator_id: operator, provider, service_id: serviceId,
      scopes: ['read'], credential_ref: 'fixture-key', credential_encrypted: encode(JSON.stringify(initial)), allowed_hosts: ['synthetic.example.test'] });
  });
  afterAll(async () => {
    vi.unstubAllGlobals();
    await db.delete(securityEvents).where(eq(securityEvents.operator_id, operator));
    await db.delete(serviceConnections).where(eq(serviceConnections.id, connectionId));
    await db.delete(services).where(eq(services.id, serviceId));
    await db.delete(operators).where(eq(operators.id, operator));
  });

  it('keeps one durable reconnect event when notification delivery fails', async () => {
    await db.update(serviceConnections).set({ status: 'active', credential_encrypted: encode(JSON.stringify(initial)) })
      .where(eq(serviceConnections.id, connectionId));
    const providerCall = vi.fn(async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }));
    vi.stubGlobal('fetch', providerCall);
    const instances = Array.from({ length: 20 }, () => {
      return new ServiceConnectionService(new ServiceRepository(db), {} as never, kms as never, undefined, {
        ...standaloneServiceConnectionHooks,
        reconnectRequired: async () => { throw new Error('Synthetic delivery unavailable'); },
      });
    });
    const results = await Promise.allSettled(instances.map(service => service.retrieveCredentialByConnectionId(operator, connectionId)));
    expect(results.every(result => result.status === 'rejected')).toBe(true);
    const events = await db.select().from(securityEvents).where(eq(securityEvents.operator_id, operator));
    expect(events).toHaveLength(1);
    expect(events[0]!.metadata).toMatchObject({ connection_id: connectionId, status: 'reconnect_required', action: 'reconnect' });
    expect(JSON.stringify(events)).not.toContain('synthetic-rotate-once');
    expect((await repo.findConnectionById(connectionId))!.status).toBe('expired');
    expect(providerCall).toHaveBeenCalledOnce();
  });

  it('50 independent service instances consume one rotating token and read the committed successor', async () => {
    await db.update(serviceConnections).set({ status: 'active', credential_encrypted: encode(JSON.stringify(initial)) })
      .where(eq(serviceConnections.id, connectionId));
    const providerCall = vi.fn(async (_url: string, init: RequestInit) => {
      expect(new URLSearchParams(init.body as string).get('refresh_token')).toBe('synthetic-rotate-once');
      await new Promise(resolve => setTimeout(resolve, 100));
      return new Response(JSON.stringify({ access_token: 'synthetic-new', refresh_token: 'synthetic-successor', expires_in: 3600 }));
    });
    vi.stubGlobal('fetch', providerCall);
    const results = await Promise.all(Array.from({ length: 50 }, () =>
      new ServiceConnectionService(new ServiceRepository(db), {} as never, kms as never, undefined, standaloneServiceConnectionHooks)
        .retrieveCredentialByConnectionId(operator, connectionId)));
    expect(providerCall).toHaveBeenCalledOnce();
    expect(results.every(result => 'credentials' in result && result.credentials.access_token === 'synthetic-new')).toBe(true);
    const stored = await repo.findConnectionById(connectionId);
    expect(stored!.credential_version).toBe(2);
    expect(JSON.parse(Buffer.from(stored!.credential_encrypted, 'base64').toString()).refresh_token).toBe('synthetic-successor');
  });
});
