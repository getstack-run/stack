import Fastify from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { agents, PassportExpiredError, PassportRevokedError, passports } from '@stack/shared';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';
import { errorHandler } from '../middleware/error-handler.js';
import { ENGINE_ROUTE_SCOPES } from '../middleware/oauth-scope.js';
import {
  createProxyConcurrencyScenario,
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const headers = request['headers'] as Record<string, string | undefined>;
    request['operatorId'] = headers['x-test-operator'] ?? 'op_owner';
    request['operatorTier'] = 'enterprise';
    request['isAdmin'] = false;
    request['isPlatformStaff'] = false;
    request['isPartner'] = false;
    if (headers['x-test-agent']) request['agentId'] = headers['x-test-agent'];
    if (headers['x-test-member']) {
      request['memberId'] = headers['x-test-member'];
      request['allowedConnections'] = headers['x-test-connections']?.split(',') ?? [];
    }
    if (headers['x-test-oauth-client']) request['oauthClientId'] = headers['x-test-oauth-client'];
  },
}));

import { registerProxyOperationRoutes } from './proxy-operations.js';

const OPERATION_ID = 'operation_aaaaaaaaaaaaa';
const apps: ReturnType<typeof Fastify>[] = [];

class RateStore {
  counts = new Map<string, number>();

  multi() {
    let key = '';
    return {
      incr: (nextKey: string) => {
        key = nextKey;
        return this.multiFor(key);
      },
      expire: () => this.multiFor(key),
      exec: async () => [[null, this.counts.get(key) ?? 0], [null, 1]] as Array<[null, number]>,
    };
  }

  private multiFor(key: string) {
    const pipeline = {
      incr: (nextKey: string) => {
        key = nextKey;
        return pipeline;
      },
      expire: () => {
        this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
        return pipeline;
      },
      exec: async () => [[null, this.counts.get(key) ?? 0], [null, 1]] as Array<[null, number]>,
    };
    return pipeline;
  }
}

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

function claims(overrides?: { operatorId?: string; agentId?: string }) {
  return {
    jti: 'passport_fresh',
    stk: {
      operator_id: overrides?.operatorId ?? 'op_owner',
      agent_id: overrides?.agentId ?? 'agt_origin',
      intent_services: ['stripe'],
      authority_refs: [],
      services: [{
        service_id: 'svc_stripe',
        service_name: 'stripe',
        connection_id: 'scon_stripe',
        credential_ref: 'opaque',
        scopes: ['refunds:write'],
        constraints: [],
        policy: { mode: 'closed', operations: [] },
        allow_data_from: [],
      }],
    },
  };
}

const metadata = {
  id: 'pop_internal',
  requestHash: 'sha256:request',
  tombstoneHash: 'sha256:tombstone',
  agentId: 'agt_origin',
  passportJti: 'passport_original',
  authorityUseId: null,
  approvalId: null,
  connectionId: 'scon_stripe',
  credentialVersion: 1,
  destinationConfigHash: 'sha256:destination',
  provider: 'stripe',
  method: 'POST',
  adapterKind: 'stripe',
  deliveryState: 'response_received',
  replayState: 'available',
  accountingState: 'committed',
  reconciliationState: 'confirmed',
  reconciliationProviderStatus: 'succeeded',
  transportAttempts: 1,
  responseStatus: 200,
  responseHash: 'sha256:response',
  retryDeadline: new Date('2026-09-10T23:00:00.000Z'),
  responseReadableUntil: new Date('2026-09-11T00:00:00.000Z'),
  dispatchedAt: new Date('2026-09-10T00:00:01.000Z'),
  responseReceivedAt: new Date('2026-09-10T00:00:02.000Z'),
  unresolvedAt: null,
  createdAt: new Date('2026-09-10T00:00:00.000Z'),
  updatedAt: new Date('2026-09-10T00:00:02.000Z'),
};

async function makeApp(options?: {
  verifiedClaims?: ReturnType<typeof claims>;
  verifyError?: Error;
  authorize?: (input: Record<string, unknown>) => unknown;
}) {
  const verify = vi.fn(async () => {
    if (options?.verifyError) throw options.verifyError;
    return options?.verifiedClaims ?? claims();
  });
  const authorizeRead = vi.fn(async (input: Record<string, unknown>) =>
    options?.authorize
      ? options.authorize(input)
      : {
          metadata,
          ...(input['includeResponse']
            ? {
                replay: {
                  state: 'available',
                  status: 200,
                  headers: { 'content-type': 'application/json' },
                  body: { id: 're_1' },
                },
              }
            : {}),
        });
  const services = {
    passport: { verify },
    proxyOperation: { authorizeRead },
    redis: new RateStore(),
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerProxyOperationRoutes(app, services as never);
  await app.ready();
  return { app, verify, authorizeRead, services };
}

function request(options?: {
  includeResponse?: boolean;
  operationId?: string;
  headers?: Record<string, string>;
}) {
  return {
    method: 'POST' as const,
    url: '/v1/proxy/operations/get',
    headers: {
      authorization: 'Bearer synthetic-ordinary-auth',
      'x-passport-token': 'synthetic-fresh-passport',
      ...options?.headers,
    },
    payload: {
      operation_id: options?.operationId ?? OPERATION_ID,
      ...(options?.includeResponse ? { include_response: true } : {}),
    },
  };
}

describe('proxy operation status and replay authorization', () => {
  it('classifies the body-based read endpoint under proxy:read OAuth scope', () => {
    expect(ENGINE_ROUTE_SCOPES['POST /v1/proxy/operations/get']).toBe('proxy:read');
  });

  it('returns metadata without leaking internal authorization bindings', async () => {
    const { app, verify, authorizeRead } = await makeApp();
    const response = await app.inject(request());

    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['pragma']).toBe('no-cache');
    expect(response.json()).toEqual({
      operation_id: OPERATION_ID,
      delivery_state: 'response_received',
      replay_state: 'available',
      accounting_state: 'committed',
      provider: 'stripe',
      method: 'POST',
      created_at: '2026-09-10T00:00:00.000Z',
      dispatched_at: '2026-09-10T00:00:01.000Z',
      response_received_at: '2026-09-10T00:00:02.000Z',
      unresolved_at: null,
      provider_outcome: 'confirmed',
      provider_status: 'succeeded',
    });
    expect(response.json()).not.toHaveProperty('response');
    expect(JSON.stringify(response.json())).not.toContain('scon_stripe');
    expect(verify).toHaveBeenCalledWith('synthetic-fresh-passport', { check_freshness: true });
    expect(authorizeRead).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: 'op_owner',
      operationKey: OPERATION_ID,
      currentAgentId: 'agt_origin',
      includeResponse: false,
    }));
  });

  it('returns a stored response only through the separately limited replay branch', async () => {
    const { app } = await makeApp();
    const response = await app.inject(request({ includeResponse: true }));
    expect(response.statusCode).toBe(200);
    expect(response.json().response).toEqual({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: { id: 're_1' },
    });
  });

  it('makes unavailable and operation-level unauthorized results indistinguishable', async () => {
    const unavailable = await makeApp({ authorize: () => null });
    const foreign = await makeApp({ authorize: () => null });
    const [missingResponse, foreignResponse] = await Promise.all([
      unavailable.app.inject(request({ operationId: 'operation_bbbbbbbbbbbbb' })),
      foreign.app.inject(request()),
    ]);
    expect(missingResponse.statusCode).toBe(404);
    expect(foreignResponse.statusCode).toBe(404);
    expect(foreignResponse.body).toBe(missingResponse.body);
  });

  const deniedPrincipals: Array<[
    string,
    ReturnType<typeof claims>,
    Record<string, string>,
  ]> = [
    ['foreign tenant', claims({ operatorId: 'op_foreign' }), {}],
    ['foreign authenticated agent', claims(), { 'x-test-agent': 'agt_foreign' }],
  ];

  it.each(deniedPrincipals)(
    'hides existence from a %s before operation lookup',
    async (_name, verifiedClaims, headers) => {
      const { app, authorizeRead } = await makeApp({ verifiedClaims });
      const response = await app.inject(request({ headers }));
      expect(response.statusCode).toBe(404);
      expect(authorizeRead).not.toHaveBeenCalled();
    },
  );

  it('hides missing, expired, or revoked Passport authority', async () => {
    const missing = await makeApp();
    const expired = await makeApp({ verifyError: new PassportExpiredError() });
    const revoked = await makeApp({ verifyError: new PassportRevokedError() });
    const missingResponse = await missing.app.inject({
      ...request(),
      headers: { authorization: 'Bearer synthetic-ordinary-auth' },
    });
    const expiredResponse = await expired.app.inject(request());
    const revokedResponse = await revoked.app.inject(request());
    expect(missingResponse.statusCode).toBe(404);
    expect(expiredResponse.statusCode).toBe(404);
    expect(revokedResponse.statusCode).toBe(404);
    expect(expiredResponse.body).toBe(missingResponse.body);
    expect(revokedResponse.body).toBe(missingResponse.body);
  });

  it('passes the signed scope and current member connection ceiling to the service-side comparison', async () => {
    const { app, authorizeRead } = await makeApp();
    const response = await app.inject(request({
      headers: {
        'x-test-member': 'mem_current',
        'x-test-connections': 'scon_stripe',
      },
    }));
    expect(response.statusCode).toBe(200);
    expect(authorizeRead).toHaveBeenCalledWith(expect.objectContaining({
      allowedConnections: ['scon_stripe'],
      freshAuthority: expect.objectContaining({
        intentServices: ['stripe'],
        services: [expect.objectContaining({
          service_name: 'stripe',
          connection_id: 'scon_stripe',
          scopes: ['refunds:write'],
        })],
      }),
    }));
  });

  it('does not turn operation-ID possession into access past a member connection ceiling', async () => {
    const { app } = await makeApp({
      authorize: (input) => {
        const allowed = input['allowedConnections'] as string[] | undefined;
        return allowed?.includes('scon_stripe') ? { metadata } : null;
      },
    });
    const response = await app.inject(request({
      headers: {
        'x-test-member': 'mem_restricted',
        'x-test-connections': 'scon_other',
      },
    }));
    expect(response.statusCode).toBe(404);
  });

  it.each([
    [false, 60],
    [true, 10],
  ] as const)(
    'enforces the stable-principal %s response limit across token rotation',
    async (includeResponse, limit) => {
      const { app } = await makeApp();
      for (let index = 0; index < limit; index += 1) {
        const response = await app.inject(request({
          includeResponse,
          headers: { 'x-test-auth-nonce': `rotated-${index}`, 'x-test-agent': 'agt_origin' },
        }));
        expect(response.statusCode).toBe(200);
      }
      const limited = await app.inject(request({
        includeResponse,
        headers: { 'x-test-auth-nonce': 'rotated-again', 'x-test-agent': 'agt_origin' },
      }));
      expect(limited.statusCode).toBe(429);
      expect(limited.json()).toMatchObject({ error: { code: 'RATE_LIMITED' } });
    },
  );

  it('keeps the operation handle out of the URL', async () => {
    const { app } = await makeApp();
    expect((await app.inject(request())).statusCode).toBe(200);
    expect((await app.inject({
      method: 'POST',
      url: `/v1/proxy/operations/get/${OPERATION_ID}`,
      headers: { authorization: 'Bearer synthetic-ordinary-auth', 'x-passport-token': 'fresh' },
      payload: {},
    })).statusCode).toBe(404);
  });
});

describe.runIf(isDedicatedProxyFixtureDatabase())(
  'proxy operation service authorization in PostgreSQL',
  () => {
    let fixture: ProxyPostgresFixture;

    beforeAll(async () => { fixture = await createProxyPostgresFixture(); });
    afterAll(async () => { await fixture?.close(); });

    async function completedOperation(label: string, authorityBearing = false) {
      const operationKey = `operation_status_${label}_${'x'.repeat(24)}`;
      const scenario = await createProxyConcurrencyScenario(
        fixture,
        operationKey,
        'standard',
        authorityBearing,
      );
      await fixture.operationService.recordEvaluation({
        operatorId: fixture.ids.operatorId,
        operationKey,
        evaluationCommitmentHash: scenario.input.accounting.evaluationCommitmentHash,
        accountingPeriod: scenario.input.accounting.period,
        verdict: 'admitted',
        allowanceLimit: null,
        overageUnits10000thCent: 0,
      });
      await executeTransactionSafeProxy(scenario.input);
      return { operationKey, scenario };
    }

    function freshAuthority(authorityRefs: unknown[] = []) {
      return {
        services: [{
          service_id: fixture.ids.serviceId,
          service_name: fixture.ids.provider,
          connection_id: fixture.ids.connectionId,
          scopes: ['write'],
          constraints: [],
          policy: null,
          allow_data_from: [],
        }],
        intentServices: [fixture.ids.provider],
        discloseTo: [],
        authorityRefs,
      };
    }

    it('does not disclose an operation across tenant, agent, Passport scope, or member connection boundaries', async () => {
      const { operationKey } = await completedOperation('boundary');
      const service = fixture.operationService;
      await expect(service.authorizeRead({
        operatorId: 'op_foreign', operationKey, currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority(),
      })).resolves.toBeNull();
      await expect(service.authorizeRead({
        operatorId: fixture.ids.operatorId, operationKey, currentAgentId: 'agt_foreign',
        freshAuthority: freshAuthority(),
      })).resolves.toBeNull();
      await expect(service.authorizeRead({
        operatorId: fixture.ids.operatorId, operationKey, currentAgentId: fixture.ids.agentId,
        freshAuthority: { ...freshAuthority(), services: [] },
      })).resolves.toBeNull();
      await expect(service.authorizeRead({
        operatorId: fixture.ids.operatorId, operationKey, currentAgentId: fixture.ids.agentId,
        allowedConnections: ['scon_foreign'], freshAuthority: freshAuthority(),
      })).resolves.toBeNull();
      await expect(service.authorizeHumanMetadata({
        operatorId: 'op_foreign', operationKey,
      })).resolves.toBeNull();
      await expect(service.authorizeHumanMetadata({
        operatorId: fixture.ids.operatorId, operationKey, allowedConnections: ['scon_foreign'],
      })).resolves.toBeNull();
    });

    it('keeps metadata but denies replay after the original Passport expires or is revoked', async () => {
      const expired = await completedOperation('expired');
      await fixture.db.update(passports).set({ expires_at: new Date(Date.now() - 1_000) })
        .where(eq(passports.jti, expired.scenario.passportJti));
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey: expired.operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority(),
        includeResponse: true,
      })).resolves.toMatchObject({
        metadata: { passportJti: expired.scenario.passportJti },
        replay: { state: 'unavailable', reason: 'none' },
      });

      const revoked = await completedOperation('revoked');
      await fixture.db.update(passports).set({ revoked_at: new Date() })
        .where(eq(passports.jti, revoked.scenario.passportJti));
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey: revoked.operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority(),
        includeResponse: true,
      })).resolves.toMatchObject({
        metadata: { passportJti: revoked.scenario.passportJti },
        replay: { state: 'unavailable', reason: 'none' },
      });
    });

    it('accepts a verified replacement Passport for the stable agent but rejects narrowed original scope', async () => {
      const { operationKey } = await completedOperation('replacement');
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority(),
      })).resolves.toMatchObject({ metadata: { agentId: fixture.ids.agentId } });
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: {
          ...freshAuthority(),
          services: [{ ...freshAuthority().services[0]!, scopes: [] }],
        },
      })).resolves.toBeNull();
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: { ...freshAuthority(), intentServices: [] },
      })).resolves.toBeNull();
    });

    it('denies current human visibility after agent removal', async () => {
      const { operationKey } = await completedOperation('removed-agent');
      await fixture.db.update(agents).set({ status: 'revoked' })
        .where(eq(agents.id, fixture.ids.agentId));
      try {
        await expect(fixture.operationService.authorizeHumanMetadata({
          operatorId: fixture.ids.operatorId,
          operationKey,
        })).resolves.toBeNull();
      } finally {
        await fixture.db.update(agents).set({ status: 'active' })
          .where(eq(agents.id, fixture.ids.agentId));
      }
    });

    it('requires the original authority reference and withholds CMEK-erased payloads', async () => {
      const authority = await completedOperation('authority-erasure', true);
      const refs = authority.scenario.input.authorityRefs;
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey: authority.operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority(refs),
      })).resolves.toMatchObject({ metadata: { authorityUseId: authority.scenario.authorityUseId } });
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey: authority.operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority([]),
      })).resolves.toBeNull();

      const erased = await completedOperation('cmek-erasure');
      fixture.kms.revokeDecryptAccess();
      try {
        await expect(fixture.operationService.authorizeRead({
          operatorId: fixture.ids.operatorId,
          operationKey: erased.operationKey,
          currentAgentId: fixture.ids.agentId,
          freshAuthority: freshAuthority(),
          includeResponse: true,
        })).rejects.toThrow('CMEK decrypt access revoked');
      } finally {
        fixture.kms.restoreDecryptAccess();
      }
      const metadata = await fixture.operationService.readMetadata(
        fixture.ids.operatorId,
        erased.operationKey,
      );
      expect(await fixture.operationService.erasePayloads(
        fixture.ids.operatorId,
        metadata!.id,
      )).toBe(1);
      await expect(fixture.operationService.authorizeRead({
        operatorId: fixture.ids.operatorId,
        operationKey: erased.operationKey,
        currentAgentId: fixture.ids.agentId,
        freshAuthority: freshAuthority(),
        includeResponse: true,
      })).resolves.toMatchObject({
        metadata: { replayState: 'erased' },
        replay: { state: 'unavailable', reason: 'erased' },
      });
    });
  },
);
