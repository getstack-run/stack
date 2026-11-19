import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDb, operators, serviceConnections, services as serviceCatalog, teamMembers, type Database } from '@stack/shared';
import { AgentRepository, ServiceConnectionService, ServiceRepository, standaloneServiceConnectionHooks } from '@stack/vault';
import { eq } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { Services } from '../config/services.js';
import { connectionEligibility } from '../lib/agent-runtime.js';
import { isDedicatedStackTestDatabase } from '../test/dedicated-test-database.js';
import { admitCaller } from './llm-gateway/admit-call.js';
import { retrieveProviderCredential } from './llm-gateway/credential-retrieval.js';
import type { LlmHandlerConfig } from './llm-gateway/provider-configs.js';

const databaseUrl = process.env['DATABASE_URL'];

// Every kind of caller against real rows, through the helper that decides what it may be offered and the one resolver
// that picks: an owner key, a team member, a fleet Passport, and the model gateway on the customer's own key. The
// gateway is run through its real admission and credential-read stages; the HTTP listener and the stages around them
// (metering, billing hold, the upstream call) are covered by their own suites.
describe.runIf(isDedicatedStackTestDatabase(databaseUrl))('connection selection by caller in PostgreSQL', () => {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const operatorId = `op_cal_${suffix}`;
  const serviceId = `svc_cal_${suffix}`;
  const memberId = `mem_cal_${suffix}`;
  let db: Database;
  let service: ServiceConnectionService;

  const kms = {
    encrypt: async (plaintext: string) => ({ ciphertext: `ct:${plaintext}`, keyRef: 'cal-key' }),
    decrypt: async (ciphertext: string) => `secret-of-${ciphertext.slice(3)}`,
  };
  let clock = Date.now() - 100_000;
  const row = (provider: string, id: string, name: string, member: string | null = null) => ({
    id: `scon_${id}_${suffix}`, operator_id: operatorId, service_id: serviceId, provider, name, scopes: ['*'],
    credential_ref: 'cal-key', credential_encrypted: `ct:scon_${id}_${suffix}`, credential_version: 1,
    member_id: member, connected_at: new Date((clock += 1000)),
  });
  const id = (key: string) => `scon_${key}_${suffix}`;

  const owner = `owner_${suffix}`;
  const team = `team_${suffix}`;
  const fleet = `fleet_${suffix}`;
  const gw = `gateway_${suffix}`;

  beforeAll(async () => {
    db = createDb(databaseUrl!);
    await db.insert(operators).values({ id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${suffix}` });
    await db.insert(serviceCatalog).values({
      id: serviceId, provider: `calcat_${suffix}`, name: 'Caller test provider', description: 'caller selection fixture',
      oauth_auth_url: 'https://auth.example.invalid', oauth_token_url: 'https://token.example.invalid', scopes_available: ['*'],
    });
    await db.insert(teamMembers).values({ id: memberId, operator_id: operatorId, email: `${memberId}@test.invalid`, name: 'Member', status: 'active' });
    await db.insert(serviceConnections).values([
      // owner key: one provider with one shared row, one with two
      row(`${owner}_one`, 'o1', 'default'),
      row(`${owner}_two`, 'o2a', 'Work'), row(`${owner}_two`, 'o2b', 'Home'),
      // team member: own row and a shared row; two own rows; own and shared of another provider
      row(`${team}_own`, 't1own', 'Mine', memberId), row(`${team}_own`, 't1shared', 'Shared'),
      row(`${team}_two`, 't2a', 'First', memberId), row(`${team}_two`, 't2b', 'Second', memberId),
      // fleet
      row(fleet, 'f1', 'Alpha'), row(fleet, 'f2', 'Beta'),
      // gateway
      row(gw, 'g1', 'Prod'), row(gw, 'g2', 'Staging'),
    ]);
    service = new ServiceConnectionService(
      new ServiceRepository(db), new AgentRepository(db), kms as never, undefined,
      { ...standaloneServiceConnectionHooks, externalAgentGuard: async () => undefined },
    );
  });

  afterAll(async () => {
    if (!db) return;
    await db.delete(serviceConnections).where(eq(serviceConnections.operator_id, operatorId));
    await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.delete(serviceCatalog).where(eq(serviceCatalog.id, serviceId));
  });

  const pick = (request: Partial<FastifyRequest>, provider: string, selector?: string, claims?: never) =>
    service.resolveProxyConnection(operatorId, provider, connectionEligibility(request as FastifyRequest, provider, claims), selector);

  describe('owner API key', () => {
    it('gets the one shared connection with no name', async () => {
      expect((await pick({}, `${owner}_one`)).connection_id).toBe(id('o1'));
    });
    it('is told which two to choose from when the account holds two, and reaches each by name or id', async () => {
      await expect(pick({}, `${owner}_two`)).rejects.toMatchObject({ code: 'CONNECTION_AMBIGUOUS', statusCode: 409 });
      expect((await pick({}, `${owner}_two`, 'home')).connection_id).toBe(id('o2b'));
      expect((await pick({}, `${owner}_two`, id('o2a'))).connection_id).toBe(id('o2a'));
    });
  });

  describe('team member', () => {
    const member = (allowed?: string[]) => ({ memberId, ...(allowed ? { allowedConnections: allowed } : {}) });
    it('takes their own connection over the shared one', async () => {
      expect((await pick(member(), `${team}_own`)).connection_id).toBe(id('t1own'));
      expect((await pick(member(), `${team}_own`, 'Shared')).connection_id).toBe(id('t1shared'));
    });
    it('is asked to choose between two of their own', async () => {
      await expect(pick(member(), `${team}_two`)).rejects.toMatchObject({ code: 'CONNECTION_AMBIGUOUS' });
      expect((await pick(member(), `${team}_two`, 'second')).connection_id).toBe(id('t2b'));
    });
    it('respects allowed_connections: a connection outside the list is not offered, by default or by name', async () => {
      expect((await pick(member([id('t1shared')]), `${team}_own`)).connection_id).toBe(id('t1shared'));
      await expect(pick(member([id('t1shared')]), `${team}_own`, 'Mine')).rejects.toMatchObject({ code: 'NOT_FOUND' });
      await expect(pick(member([]), `${team}_own`)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    });
  });

  describe('fleet Passport with two scopes of one provider', () => {
    const claims = (ids: (string | undefined)[]) => ({
      jti: 'pp_fleet',
      stk: {
        operator_id: operatorId, agent_id: 'agt_fleet', fleet: { policy_id: 'flp' }, mission_ids: ['ms_1'],
        services: ids.map((connection_id) => ({ service_name: fleet, service_id: serviceId, credential_ref: 'cal-key', scopes: ['*'], ...(connection_id ? { connection_id } : {}) })),
      },
    }) as never;
    it('no longer throws: it is ambiguous without a name and reaches the named one', async () => {
      const c = claims([id('f1'), id('f2')]);
      await expect(pick({}, fleet, undefined, c)).rejects.toMatchObject({ code: 'CONNECTION_AMBIGUOUS' });
      expect((await pick({}, fleet, 'beta', c)).connection_id).toBe(id('f2'));
    });
    it('cannot reach a connection its scopes do not name', async () => {
      await expect(pick({}, fleet, 'Beta', claims([id('f1')]))).rejects.toMatchObject({ code: 'NOT_FOUND' });
    });
    it('is refused when a scope names no connection', () => {
      expect(() => pick({}, fleet, undefined, claims([id('f1'), undefined]))).toThrow(/forbidden|permission|not allowed/i);
    });
  });

  describe('model gateway on the customer\'s own key', () => {
    const config = { provider: gw, schema: {}, action: 'llm.test.chat', namedIntent: 'test:llm:chat' } as unknown as LlmHandlerConfig;
    const authorityBoundaries: { serviceConnectionId: string }[] = [];
    const services = {
      serviceConnection: undefined as unknown as ServiceConnectionService,
      passport: { verify: async (token: string) => JSON.parse(token) },
      modelAccessPolicy: { resolve: async () => ({ kind: 'own' }) },
      securityEvent: { record: async () => null },
      authority: {
        evaluateRuntimeAuthority: async (input: { boundary: { serviceConnectionId: string } }) => {
          authorityBoundaries.push(input.boundary);
          return { allowed: true, authorityUseId: 'ause_1' };
        },
      },
    } as unknown as Services;

    const passport = (...ids: string[]) => JSON.stringify({
      jti: 'pp_gw',
      stk: {
        operator_id: operatorId, agent_id: 'agt_gw', mission_ids: ['ms_1'], accountability: 'standard',
        services: ids.map((connection_id) => ({ service_name: gw, service_id: serviceId, credential_ref: 'cal-key', scopes: ['*'], connection_id })),
      },
    });
    const request = (granted: string[], header?: string) => ({
      headers: { 'x-passport-token': passport(...granted), ...(header ? { 'x-stack-connection': header } : {}) },
      body: { model: 'm', stream: false },
    }) as unknown as FastifyRequest;
    const call = (granted: string[], header?: string) => {
      (services as { serviceConnection: unknown }).serviceConnection = service;
      return admitCaller(services, request(granted, header), config, {
        body: { model: 'm' }, method: 'POST', upstream: new URL('https://llm.example.invalid/v1/chat'),
      });
    };

    it('refuses an unnamed call when two connections are granted, before the authority is asked', async () => {
      authorityBoundaries.length = 0;
      await expect(call([id('g1'), id('g2')])).rejects.toMatchObject({ code: 'CONNECTION_AMBIGUOUS', statusCode: 409 });
      expect(authorityBoundaries).toHaveLength(0);
    });

    it('asks the authority about, and sends the key of, the connection the header names (the same one)', async () => {
      authorityBoundaries.length = 0;
      const admitted = await call([id('g1'), id('g2')], 'staging');
      expect(authorityBoundaries.map((b) => b.serviceConnectionId)).toEqual([id('g2')]);
      expect(admitted.authorityConnectionId).toBe(id('g2'));
      const key = await retrieveProviderCredential(services, request([id('g1'), id('g2')]), config, admitted, null);
      expect(key).toBe(`secret-of-${id('g2')}`);
    });

    it('never reaches the second connection when only one is granted, by default or by name', async () => {
      const admitted = await call([id('g1')]);
      expect(admitted.authorityConnectionId).toBe(id('g1'));
      await expect(call([id('g1')], 'Staging')).rejects.toMatchObject({ code: 'FORBIDDEN' });
    });
  });
});
