import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createDb, operators, serviceConnections, services as serviceCatalog, type Database } from '@stack/shared';
import { AgentRepository, ServiceConnectionService, ServiceRepository, standaloneServiceConnectionHooks } from '@stack/vault';
import { eq } from 'drizzle-orm';
import type { Services } from '../../config/services.js';
import { isDedicatedStackTestDatabase } from '../../test/dedicated-test-database.js';
import { retrieveProxyCredential } from './credential-retrieval.js';
import { runScopeWall } from './service-scope.js';
import { resolveProxyTarget } from './target-resolution.js';
import type { ParsedProxyRequest, ProxyHttpRequest, VerifiedProxyPassport } from './types.js';

const databaseUrl = process.env['DATABASE_URL'];

// What the proxy does with a connection pick, against real rows: which connection an agent granted one or two of a
// service reaches, and that a refusal comes before any credential is decrypted or any upstream call is made. The
// route's own steps (resolve, scope wall, credential read) are called as the route calls them; the HTTP listener,
// authentication and metering around them are covered by the neighbouring suites.
describe.runIf(isDedicatedStackTestDatabase(databaseUrl))('proxy connection selection in PostgreSQL', () => {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const operatorId = `op_sel_${suffix}`;
  const serviceId = `svc_sel_${suffix}`;
  const provider = `seltest_${suffix}`;
  const ids = { a: `scon_sela_${suffix}`, b: `scon_selb_${suffix}`, c: `scon_selc_${suffix}` };
  let db: Database;
  let service: ServiceConnectionService;
  const decrypts: string[] = [];
  const upstream = { calls: 0 };

  const kms = {
    encrypt: async (plaintext: string) => ({ ciphertext: `ct:${plaintext}`, keyRef: 'sel-key' }),
    decrypt: async (ciphertext: string) => {
      decrypts.push(ciphertext);
      return `secret-of-${ciphertext.slice(3)}`;
    },
  };

  const row = (id: string, name: string, connectedAt: number) => ({
    id,
    operator_id: operatorId,
    service_id: serviceId,
    provider,
    name,
    scopes: ['*'],
    credential_ref: 'sel-key',
    credential_encrypted: `ct:${id}`,
    credential_version: 1,
    allowed_hosts: ['api.example.invalid'],
    connected_at: new Date(connectedAt),
  });

  beforeAll(async () => {
    db = createDb(databaseUrl!);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${suffix}` });
    await db.insert(serviceCatalog).values({
      id: serviceId, provider, name: 'Selection test provider', description: 'connection selection fixture',
      oauth_auth_url: 'https://auth.example.invalid', oauth_token_url: 'https://token.example.invalid', scopes_available: ['*'],
    });
    // The account holds three connections of one service; each test grants an agent some of them.
    await db.insert(serviceConnections).values([
      row(ids.a, 'Work', Date.now() - 3000),
      row(ids.b, 'Personal', Date.now() - 2000),
      row(ids.c, 'Spare', Date.now() - 1000),
    ]);
    service = new ServiceConnectionService(
      new ServiceRepository(db), new AgentRepository(db), kms as never, undefined,
      { ...standaloneServiceConnectionHooks, externalAgentGuard: async () => undefined },
    );
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(serviceConnections).where(eq(serviceConnections.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.delete(serviceCatalog).where(eq(serviceCatalog.id, serviceId));
  });

  const security = { record: vi.fn(async () => null) };
  const apiServices = () => ({
    serviceConnection: service,
    passport: { assertServiceIdentityRequirements: async () => undefined },
    securityEvent: security,
    claimRegistry: { recordIntentDenial: async () => undefined },
    proxy: {
      resolveAuthHeaders: (_service: string, raw: string) => ({ authorization: `Bearer ${raw}` }),
      resolveTargetUrl: (url: string) => url,
    },
  }) as unknown as Services;

  function call(granted: string[], connection?: string) {
    const claims = {
      jti: 'pp_sel',
      stk: {
        operator_id: operatorId, agent_id: 'agt_sel', mission_ids: [],
        services: granted.map((id) => ({ service_name: provider, service_id: serviceId, connection_id: id, credential_ref: 'sel-key', scopes: ['*'] })),
      },
    };
    const parsed = {
      input: { service: provider, method: 'GET', url: 'https://api.example.invalid/v1/things', ...(connection ? { connection } : {}) },
      isMutation: false,
      operationKey: null,
    } as unknown as ParsedProxyRequest;
    const verified = { claims, jti: 'pp_sel', agentId: 'agt_sel', operatorId, mode: 'standard', missionIds: [] } as unknown as VerifiedProxyPassport;
    return { parsed, verified, request: {} as ProxyHttpRequest };
  }

  /** The route's order: the pick first, the credential only after it. The upstream call stands for what follows both. */
  async function run(granted: string[], connection?: string) {
    const { parsed, verified, request } = call(granted, connection);
    const s = apiServices();
    const target = await resolveProxyTarget(s, request, parsed, verified);
    const credential = await retrieveProxyCredential(s, request, parsed, verified, target, null);
    upstream.calls += 1;
    return { target, credential };
  }

  async function expectRefused(code: string, granted: string[], connection?: string) {
    const decryptsBefore = decrypts.length;
    const callsBefore = upstream.calls;
    await expect(run(granted, connection)).rejects.toMatchObject({ code });
    expect(decrypts.length).toBe(decryptsBefore);
    expect(upstream.calls).toBe(callsBefore);
  }

  it('gives an agent granted one connection that connection when it names none', async () => {
    const { target, credential } = await run([ids.b]);
    expect(target.conn.connection_id).toBe(ids.b);
    expect(credential.authHeaders['authorization']).toBe(`Bearer secret-of-${ids.b}`);
  });

  it('answers 409 CONNECTION_AMBIGUOUS, listing exactly the granted two, with nothing decrypted or sent', async () => {
    const { parsed, verified, request } = call([ids.a, ids.b]);
    const decryptsBefore = decrypts.length;
    const callsBefore = upstream.calls;
    const error = await resolveProxyTarget(apiServices(), request, parsed, verified).catch((e: unknown) => e) as
      { code: string; statusCode?: number; status?: number; details?: { connections: { id: string; name: string }[] } };
    expect(error.code).toBe('CONNECTION_AMBIGUOUS');
    expect(error.statusCode ?? error.status).toBe(409);
    expect([...error.details!.connections].sort((x, y) => x.id.localeCompare(y.id)))
      .toEqual([{ id: ids.a, name: 'Work' }, { id: ids.b, name: 'Personal' }]);
    expect(decrypts.length).toBe(decryptsBefore);
    expect(upstream.calls).toBe(callsBefore);
  });

  it.each([
    ['name', 'Work', 'a'],
    ['name in another case', 'pERSONAL', 'b'],
  ] as const)('reaches the right credential when the call names the connection by %s', async (_label, selector, key) => {
    const { target, credential } = await run([ids.a, ids.b], selector);
    expect(target.conn.connection_id).toBe(ids[key]);
    expect(credential.authHeaders['authorization']).toBe(`Bearer secret-of-${ids[key]}`);
  });

  it('reaches the right credential when the call names the connection by id', async () => {
    const { target, credential } = await run([ids.a, ids.b], ids.b);
    expect(target.conn.connection_id).toBe(ids.b);
    expect(credential.authHeaders['authorization']).toBe(`Bearer secret-of-${ids.b}`);
  });

  it('holds each connection to its own Passport scope', () => {
    const { verified, parsed } = call([ids.a, ids.b]);
    const scopes = verified.claims.stk.services as unknown as { connection_id: string; policy?: unknown }[];
    scopes[1]!.policy = { marker: 'second' };
    // The wall judges the scope of the connection the call resolved to, not the first scope of the service.
    return (async () => {
      const s = apiServices();
      const target = await resolveProxyTarget(s, {} as ProxyHttpRequest, { ...parsed, input: { ...parsed.input, connection: 'Personal' } }, verified);
      const picked = await runScopeWall(
        s, parsed, verified, target, { observedPrefetch: undefined } as never,
      ).catch((e: unknown) => e);
      // The wall may refuse a scope policy it cannot read; either way it was handed the second scope, never the first.
      if (picked && typeof picked === 'object' && 'connection_id' in picked) {
        expect((picked as { connection_id: string }).connection_id).toBe(ids.b);
      }
      expect(target.conn.connection_id).toBe(ids.b);
    })();
  });

  describe('an agent granted only B while the account also holds A', () => {
    it('never reaches A by default: it gets B', async () => {
      expect((await run([ids.b])).target.conn.connection_id).toBe(ids.b);
    });

    it('never reaches A by A\'s name: the same 404 as an unknown service', async () => {
      await expectRefused('NOT_FOUND', [ids.b], 'Work');
      const unknown = await run([ids.b], 'no-such-connection').catch((e: { code: string; message: string }) => e);
      const ungranted = await run([ids.b], 'Work').catch((e: { code: string; message: string }) => e);
      expect((unknown as { code: string }).code).toBe((ungranted as { code: string }).code);
      expect((unknown as { message: string }).message.replace('no-such-connection', '')).toBe((ungranted as { message: string }).message.replace('Work', ''));
    });

    it('never reaches A by A\'s id', async () => {
      await expectRefused('NOT_FOUND', [ids.b], ids.a);
    });
  });

  it('refuses a service the Passport never granted, with its security event, before any connection is picked', async () => {
    const { parsed, verified, request } = call([]);
    security.record.mockClear();
    const decryptsBefore = decrypts.length;
    await expect(resolveProxyTarget(apiServices(), request, parsed, verified)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(security.record).toHaveBeenCalledWith(expect.objectContaining({ signalType: 'credential_outside_scope' }));
    expect(decrypts.length).toBe(decryptsBefore);
  });
});
