import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createDb, EntityObservationClaim, flowSourceLabel, operators, serviceConnections, services as serviceCatalog, type Database } from '@stack/shared';
import { AgentRepository, ServiceConnectionService, ServiceRepository, standaloneServiceConnectionHooks } from '@stack/vault';
import { eq } from 'drizzle-orm';
import type { Services } from '../../config/services.js';
import { isDedicatedStackTestDatabase } from '../../test/dedicated-test-database.js';
import { retrieveProxyCredential } from './credential-retrieval.js';
import { observeEntities } from './signed-claims.js';
import { runScopeWall } from './service-scope.js';
import { resolveProxyTarget } from './target-resolution.js';
import type { ParsedProxyRequest, ProxyHttpRequest, UpstreamResult, VerifiedProxyPassport } from './types.js';

const databaseUrl = process.env['DATABASE_URL'];

// The data-flow rule over two connections of one service, against real rows: what a call reads through one connection
// is recorded under that connection, and a write through the other carrying it is a movement between two sources.
// The route's own steps are called as the route calls them (resolve, observe, scope wall, credential read); the
// upstream call stands for what follows them all.
describe.runIf(isDedicatedStackTestDatabase(databaseUrl))('data flow between two connections of one service in PostgreSQL', () => {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const operatorId = `op_dfl_${suffix}`;
  const serviceId = `svc_dfl_${suffix}`;
  const provider = `dfltest_${suffix}`;
  const ids = { work: `scon_dflw_${suffix}`, personal: `scon_dflp_${suffix}` };
  let db: Database;
  let service: ServiceConnectionService;
  const decrypts: string[] = [];
  const upstream = { calls: 0 };
  /** What the producer recorded as read, exactly as the trail stores it. */
  const recorded: Array<{ entities: string[]; fingerprints: string[]; sourceService: string }> = [];

  const kms = {
    encrypt: async (plaintext: string) => ({ ciphertext: `ct:${plaintext}`, keyRef: 'dfl-key' }),
    decrypt: async (ciphertext: string) => {
      decrypts.push(ciphertext);
      return `secret-of-${ciphertext.slice(3)}`;
    },
  };

  const row = (id: string, name: string, connectedAt: number) => ({
    id, operator_id: operatorId, service_id: serviceId, provider, name, scopes: ['*'], credential_ref: 'dfl-key',
    credential_encrypted: `ct:${id}`, credential_version: 1, allowed_hosts: ['api.example.invalid'], connected_at: new Date(connectedAt),
  });

  beforeAll(async () => {
    db = createDb(databaseUrl!);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${suffix}` });
    await db.insert(serviceCatalog).values({
      id: serviceId, provider, name: 'Data flow test provider', description: 'connection data flow fixture',
      oauth_auth_url: 'https://auth.example.invalid', oauth_token_url: 'https://token.example.invalid', scopes_available: ['*'],
    });
    await db.insert(serviceConnections).values([row(ids.work, 'Work', Date.now() - 2000), row(ids.personal, 'Personal', Date.now() - 1000)]);
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
    claimRegistry: {
      recordIntentDenial: async () => undefined,
      registerClaim: async (input: { payload: { entities: string[]; content_fingerprints: string[]; source_service: string } }) => {
        recorded.push({
          entities: input.payload.entities, fingerprints: input.payload.content_fingerprints, sourceService: input.payload.source_service,
        });
      },
    },
    passportClaimsRepo: { findObservedContentForFlow: async () => recorded },
    accountDetection: { forAgent: async () => null },
    entitlements: { controlsEnabled: async () => true },
    proxy: {
      resolveAuthHeaders: (_service: string, raw: string) => ({ authorization: `Bearer ${raw}` }),
      resolveTargetUrl: (url: string) => url,
    },
  }) as unknown as Services;

  const CONTACT = 'alice.johnson@example.org';

  function call(
    method: 'GET' | 'POST', connection: string, body?: unknown,
    scopes: Array<{ connection_id: string; allow_data_from?: string[] }> = [{ connection_id: ids.work }, { connection_id: ids.personal }],
  ) {
    const claims = {
      jti: 'pp_dfl',
      stk: {
        operator_id: operatorId, agent_id: 'agt_dfl', mission_ids: [],
        services: scopes.map((scope) => ({
          service_name: provider, service_id: serviceId, credential_ref: 'dfl-key', scopes: ['*'], ...scope,
        })),
      },
    };
    const parsed = {
      input: { service: provider, method, url: 'https://api.example.invalid/v1/things', connection, ...(body ? { body } : {}) },
      isMutation: method !== 'GET',
      operationKey: null,
    } as unknown as ParsedProxyRequest;
    const verified = { claims, jti: 'pp_dfl', agentId: 'agt_dfl', operatorId, mode: 'standard', missionIds: [] } as unknown as VerifiedProxyPassport;
    return { parsed, verified, request: {} as ProxyHttpRequest };
  }

  /** A read through a connection: the call goes out, and what came back is recorded as the route records it. */
  async function readThrough(connection: string) {
    const { parsed, verified, request } = call('GET', connection);
    const s = apiServices();
    const target = await resolveProxyTarget(s, request, parsed, verified);
    const injection = await retrieveProxyCredential(s, request, parsed, verified, target, null);
    upstream.calls += 1;
    await observeEntities(s, parsed, verified, injection, { status: 200, body: { contacts: [CONTACT] } } as unknown as UpstreamResult);
    return target.conn.connection_id;
  }

  /** A write through a connection: the wall first, the credential and the upstream call only after it. */
  async function writeThrough(connection: string, allowDataFrom?: string[]) {
    const { parsed, verified, request } = call('POST', connection, { attendee: CONTACT }, [
      { connection_id: ids.work },
      { connection_id: ids.personal, ...(allowDataFrom ? { allow_data_from: allowDataFrom } : {}) },
    ]);
    const s = apiServices();
    const target = await resolveProxyTarget(s, request, parsed, verified);
    await runScopeWall(s, parsed, verified, target, { observedPrefetch: Promise.resolve(recorded) } as never);
    await retrieveProxyCredential(s, request, parsed, verified, target, null);
    upstream.calls += 1;
    return target.conn.connection_id;
  }

  it('records a read under the connection it went through', async () => {
    expect(await readThrough('Work')).toBe(ids.work);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]!.sourceService).toBe(`${provider}@${ids.work}`);
    expect(recorded[0]!.entities.length).toBeGreaterThan(0);
  });

  it('refuses a write through the other connection carrying that content: nothing decrypted, nothing sent', async () => {
    const decryptsBefore = decrypts.length;
    const callsBefore = upstream.calls;
    security.record.mockClear();
    const error = await writeThrough('Personal').catch((e: unknown) => e) as { code: string; message: string };
    expect(error.code).toBe('FORBIDDEN');
    expect(error.message).toContain(`content read from another connection of "${provider}"`);
    expect(error.message).toContain('allow_data_from');
    expect(decrypts.length).toBe(decryptsBefore);
    expect(upstream.calls).toBe(callsBefore);
    // The event names services, and the two connections beside them.
    expect(security.record).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({
        data_flow_from: provider, data_flow_to: provider,
        data_flow_from_connection: ids.work, data_flow_to_connection: ids.personal, data_flow_refused: true,
      }),
    }));
  });

  it('allows the same write through the connection the content was read through', async () => {
    const callsBefore = upstream.calls;
    expect(await writeThrough('Work')).toBe(ids.work);
    expect(upstream.calls).toBe(callsBefore + 1);
  });

  it('allows the write through the other connection when its grant names the service', async () => {
    const callsBefore = upstream.calls;
    expect(await writeThrough('Personal', [provider])).toBe(ids.personal);
    expect(upstream.calls).toBe(callsBefore + 1);
  });

  it('allows it for the one connection a full label names, and refuses it for another label', async () => {
    expect(await writeThrough('Personal', [`${provider}@${ids.work}`])).toBe(ids.personal);
    await expect(writeThrough('Personal', [`${provider}@scon_someone_else`])).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

// A custom provider id is `custom_` and a slug of up to 100 characters. Its source label would then pass the 128
// characters of `source_service` in the published observation claim, the claim would be rejected and the read never
// recorded, so the rule would not see it. The label carries a key for the service instead.
describe.runIf(isDedicatedStackTestDatabase(databaseUrl))('data flow between two connections of a custom service with the longest name in PostgreSQL', () => {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const operatorId = `op_dfx_${suffix}`;
  const serviceId = `svc_dfx_${suffix}`;
  const provider = `custom_${`dfx${suffix}`.padEnd(100, 'q').slice(0, 100)}`;
  const connectionId = (tag: string) => `scon_${`${tag}${suffix.replace(/\W/g, '')}`.padEnd(21, '0').slice(0, 21)}`;
  const ids = { work: connectionId('w'), personal: connectionId('p') };
  let db: Database;
  let service: ServiceConnectionService;
  const decrypts: string[] = [];
  const upstream = { calls: 0 };
  const recorded: Array<{ entities: string[]; fingerprints: string[]; sourceService: string; payload: unknown }> = [];

  const kms = {
    encrypt: async (plaintext: string) => ({ ciphertext: `ct:${plaintext}`, keyRef: 'dfx-key' }),
    decrypt: async (ciphertext: string) => {
      decrypts.push(ciphertext);
      return `secret-of-${ciphertext.slice(3)}`;
    },
  };
  const row = (id: string, name: string, connectedAt: number) => ({
    id, operator_id: operatorId, service_id: serviceId, provider, name, scopes: ['*'], credential_ref: 'dfx-key',
    credential_encrypted: `ct:${id}`, credential_version: 1, allowed_hosts: ['api.example.invalid'], connected_at: new Date(connectedAt),
  });

  beforeAll(async () => {
    db = createDb(databaseUrl!);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${suffix}` });
    await db.insert(serviceCatalog).values({
      id: serviceId, operator_id: operatorId, provider, name: 'Long custom service', description: 'long name data flow fixture',
      oauth_auth_url: 'https://auth.example.invalid', oauth_token_url: 'https://token.example.invalid', scopes_available: ['*'], available: false,
    });
    await db.insert(serviceConnections).values([row(ids.work, 'Work', Date.now() - 2000), row(ids.personal, 'Personal', Date.now() - 1000)]);
    service = new ServiceConnectionService(
      new ServiceRepository(db), new AgentRepository(db), kms as never, undefined,
      { ...standaloneServiceConnectionHooks, externalAgentGuard: async () => undefined },
    );
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(serviceConnections).where(eq(serviceConnections.operator_id, operatorId));
    await db.delete(serviceCatalog).where(eq(serviceCatalog.id, serviceId));
    await db.delete(operators).where(eq(operators.id, operatorId));
  });

  const security = { record: vi.fn(async () => null) };
  const apiServices = () => ({
    serviceConnection: service,
    passport: { assertServiceIdentityRequirements: async () => undefined },
    securityEvent: security,
    claimRegistry: {
      recordIntentDenial: async () => undefined,
      registerClaim: async (input: { payload: { entities: string[]; content_fingerprints: string[]; source_service: string } }) => {
        recorded.push({
          entities: input.payload.entities, fingerprints: input.payload.content_fingerprints,
          sourceService: input.payload.source_service, payload: input.payload,
        });
      },
    },
    passportClaimsRepo: { findObservedContentForFlow: async () => recorded },
    accountDetection: { forAgent: async () => null },
    entitlements: { controlsEnabled: async () => true },
    proxy: {
      resolveAuthHeaders: (_service: string, raw: string) => ({ authorization: `Bearer ${raw}` }),
      resolveTargetUrl: (url: string) => url,
    },
  }) as unknown as Services;

  const CONTACT = 'alice.johnson@example.org';

  function call(method: 'GET' | 'POST', connection: string, body?: unknown) {
    const claims = {
      jti: 'pp_dfx',
      stk: {
        operator_id: operatorId, agent_id: 'agt_dfx', mission_ids: [],
        services: [ids.work, ids.personal].map((id) => ({
          service_name: provider, service_id: serviceId, credential_ref: 'dfx-key', scopes: ['*'], connection_id: id,
        })),
      },
    };
    const parsed = {
      input: { service: provider, method, url: 'https://api.example.invalid/v1/things', connection, ...(body ? { body } : {}) },
      isMutation: method !== 'GET',
      operationKey: null,
    } as unknown as ParsedProxyRequest;
    const verified = { claims, jti: 'pp_dfx', agentId: 'agt_dfx', operatorId, mode: 'standard', missionIds: [] } as unknown as VerifiedProxyPassport;
    return { parsed, verified, request: {} as ProxyHttpRequest };
  }

  it('records a read through one connection under a label the claim schema accepts', async () => {
    expect(provider).toHaveLength(107);
    const { parsed, verified, request } = call('GET', 'Work');
    const s = apiServices();
    const target = await resolveProxyTarget(s, request, parsed, verified);
    const injection = await retrieveProxyCredential(s, request, parsed, verified, target, null);
    upstream.calls += 1;
    await observeEntities(s, parsed, verified, injection, { status: 200, body: { contacts: [CONTACT] } } as unknown as UpstreamResult);

    expect(recorded).toHaveLength(1);
    const observation = recorded[0]!;
    expect(observation.entities.length).toBeGreaterThan(0);
    expect(observation.sourceService.length).toBeLessThanOrEqual(128);
    expect(observation.sourceService).toBe(flowSourceLabel(provider, ids.work));
    expect(observation.sourceService).toMatch(new RegExp(`^custom~[0-9a-f]{40}@${ids.work}$`));
    expect(EntityObservationClaim.safeParse(observation.payload).success).toBe(true);
  });

  it('refuses a write through the other connection carrying it: nothing decrypted, nothing sent, the real name shown', async () => {
    const decryptsBefore = decrypts.length;
    const callsBefore = upstream.calls;
    security.record.mockClear();
    const { parsed, verified, request } = call('POST', 'Personal', { attendee: CONTACT });
    const s = apiServices();
    const target = await resolveProxyTarget(s, request, parsed, verified);
    const error = await runScopeWall(s, parsed, verified, target, { observedPrefetch: Promise.resolve(recorded) } as never)
      .catch((e: unknown) => e) as { code: string; message: string };
    expect(error.code).toBe('FORBIDDEN');
    expect(error.message).toContain(`content read from another connection of "${provider}"`);
    expect(error.message).not.toContain('custom~');
    expect(decrypts.length).toBe(decryptsBefore);
    expect(upstream.calls).toBe(callsBefore);
    expect(security.record).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({
        data_flow_from: provider, data_flow_to: provider,
        data_flow_from_connection: ids.work, data_flow_to_connection: ids.personal, data_flow_refused: true,
      }),
    }));
  });
});
