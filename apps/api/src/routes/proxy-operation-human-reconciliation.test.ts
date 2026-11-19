import { fakeEntitlements } from '../test/entitlements.js';
import { fakeBrowserSessions } from '../test/browser-sessions.js';
import Fastify from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  proxyOperationEvidence,
  proxyOperations,
  SESSION_JWT_AUDIENCE,
  sha256,
} from '@stack/shared';
import type { ProxyOperationMetadata } from '@stack/vault';
import { EngineRegistries } from '../config/registries.js';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';
import { errorHandler } from '../middleware/error-handler.js';
import {
  createProxyConcurrencyScenario,
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';

const mocked = vi.hoisted(() => ({
  assertBrowserDecisionSession: vi.fn(async () => undefined),
}));

vi.mock('@stack/vault', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@stack/vault')>()),
  assertBrowserDecisionSession: mocked.assertBrowserDecisionSession,
}));

import { registerProxyOperationRoutes } from './proxy-operations.js';

const OPERATION_ID = 'operation_aaaaaaaaaaaaa';
const EVIDENCE_HASH = `sha256:${'e'.repeat(64)}` as `sha256:${string}`;
const OPERATION_RESULT_HASH = `sha256:${'f'.repeat(64)}` as const;
const apps: ReturnType<typeof Fastify>[] = [];
let previousDashboardUrl: string | undefined;

const baseMetadata: ProxyOperationMetadata = {
  id: 'pop_internal',
  requestHash: `sha256:${'a'.repeat(64)}`,
  tombstoneHash: `sha256:${'b'.repeat(64)}`,
  scopeCommitmentHash: `sha256:${'c'.repeat(64)}`,
  agentId: 'agt_origin',
  passportJti: 'passport_original',
  authorityUseId: 'ause_origin',
  approvalId: null,
  connectionId: 'scon_stripe',
  serviceId: 'svc_stripe',
  credentialVersion: 3,
  destinationConfigHash: `sha256:${'d'.repeat(64)}`,
  provider: 'stripe',
  method: 'POST',
  adapterKind: 'stripe',
  deliveryState: 'response_received',
  replayState: 'available',
  accountingState: 'committed',
  reconciliationState: 'pending',
  reconciliationEvidenceHash: null,
  reconciliationProviderStatus: null,
  transportAttempts: 1,
  responseStatus: 500,
  responseHash: 'f'.repeat(64),
  retryDeadline: new Date(Date.now() + 60_000),
  responseReadableUntil: new Date(Date.now() + 60_000),
  dispatchedAt: new Date(Date.now() - 1_000),
  responseReceivedAt: new Date(),
  unresolvedAt: null,
  createdAt: new Date(Date.now() - 2_000),
  updatedAt: new Date(),
};

beforeEach(() => {
  previousDashboardUrl = process.env['DASHBOARD_URL'];
  process.env['DASHBOARD_URL'] = 'https://getstack.run';
  mocked.assertBrowserDecisionSession.mockClear();
});

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
  if (previousDashboardUrl === undefined) delete process.env['DASHBOARD_URL'];
  else process.env['DASHBOARD_URL'] = previousDashboardUrl;
});

async function makeApp(options?: {
  metadata?: ProxyOperationMetadata;
  sessionPayload?: Record<string, unknown>;
  member?: Record<string, unknown> | null;
  reconciliation?: {
    state: 'confirmed' | 'not_found' | 'contradictory';
    evidenceHash: `sha256:${string}`;
    resourceHash?: `sha256:${string}`;
    providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
    observedCount: number;
  };
  metadataAfterRecord?: ProxyOperationMetadata;
}) {
  const sequence: string[] = [];
  let metadata = options?.metadata ?? baseMetadata;
  const reconcile = vi.fn(async () => options?.reconciliation ?? ({
    state: 'confirmed' as const,
    evidenceHash: EVIDENCE_HASH as `sha256:${string}`,
    resourceHash: `sha256:${'r'.repeat(64)}` as `sha256:${string}`,
    providerStatus: 'succeeded' as const,
    observedCount: 1,
  }));
  const authorizeHumanMetadata = vi.fn(async () => metadata);
  const readStripeReconciliationTarget = vi.fn(async () => ({
    metadata,
    operationKeyHash: 'a'.repeat(64),
    providerMarker: `stack_${'a'.repeat(64)}`,
    stripeAccount: null,
  }));
  const recordGovernedReconciliation = vi.fn(async (input: {
    state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
    evidenceHash: string;
    providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
  }) => {
    sequence.push('recorded');
    metadata = options?.metadataAfterRecord ?? {
      ...metadata,
      reconciliationState: input.state,
      reconciliationEvidenceHash: input.evidenceHash,
      reconciliationProviderStatus: input.providerStatus ?? null,
    };
    return true;
  });
  const completeRuntimeAuthorityUseByHash = vi.fn(async () => {
    sequence.push('authority-completed');
  });
  const retrieveCredentialPinnedByConnectionId = vi.fn(async () => ({
    provider: 'stripe', service_id: 'svc_stripe', connection_id: 'scon_stripe',
    credential_version: 3, allowed_hosts: ['api.stripe.com'], credential: 'sk_test_fixture',
  }));
  const session = {
    sub: 'op_owner',
    aud: SESSION_JWT_AUDIENCE,
    payload: {
      email: 'owner@test.invalid',
      owner_session_revision: '7',
      is_member: false,
      sid: 'dsf_owner',
      jti: 'dst_owner',
      auth_time: Math.floor(Date.now() / 1_000),
      exp: Math.floor(Date.now() / 1_000) + 600,
      ...options?.sessionPayload,
    },
  };
  const decisions: Array<Record<string, unknown>> = [];
  const registries = new EngineRegistries();
  registries.decisionReached.register(async (event) => { decisions.push({ ...event }); });
  const services = {
    registries,
    entitlements: fakeEntitlements(),
    signer: { verifyAccessOrSession: vi.fn(async () => session) },
    operator: { getById: vi.fn(async () => ({
      id: 'op_owner', email: 'owner@test.invalid', status: 'active', owner_session_revision: '7',
    })) },
    member: { findById: vi.fn(async () => options?.member ?? null) },
    get browserSessions() { return fakeBrowserSessions(this); },
    dashboardSessions: {
      assertActive: vi.fn(async () => undefined),
      assertActiveInTransaction: vi.fn(async () => undefined),
    },
    proxyOperation: {
      authorizeHumanMetadata,
      readStripeReconciliationTarget,
      recordGovernedReconciliation,
      transaction: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work({})),
    },
    serviceConnection: { retrieveCredentialPinnedByConnectionId },
    authority: { completeRuntimeAuthorityUseByHash },
  };
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerProxyOperationRoutes(app, services as never, { reconcileStripeRefund: reconcile });
  await app.ready();
  return {
    app, services, sequence, reconcile, authorizeHumanMetadata, readStripeReconciliationTarget,
    recordGovernedReconciliation, completeRuntimeAuthorityUseByHash,
    retrieveCredentialPinnedByConnectionId, decisions,
  };
}

function request(headers: Record<string, string> = {}) {
  return {
    method: 'POST' as const,
    url: '/v1/proxy/operations/reconcile',
    headers: {
      origin: 'https://getstack.run',
      cookie: 'stack_session=session-token',
      ...headers,
    },
    payload: { operation_id: OPERATION_ID },
  };
}

describe('human proxy reconciliation', () => {
  it('records provider evidence before completing the linked authority use', async () => {
    const fixture = await makeApp();
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.sequence).toEqual(['recorded', 'authority-completed']);
    expect(fixture.recordGovernedReconciliation).toHaveBeenCalledWith(expect.objectContaining({
      state: 'confirmed',
      evidenceHash: EVIDENCE_HASH,
    }));
    expect(fixture.completeRuntimeAuthorityUseByHash).toHaveBeenCalledWith({
      operatorId: 'op_owner',
      useId: 'ause_origin',
      outcome: 'succeeded',
      resultHash: OPERATION_RESULT_HASH,
    });
    expect(mocked.assertBrowserDecisionSession).toHaveBeenCalledWith(
      expect.anything(), 'op_owner', expect.anything(),
      { allowedMemberRoles: ['admin'], requiredConnectionId: 'scon_stripe' },
    );
  });

  it('tells the agent that sent the write how the reconciliation ended, once, named by the hash of its operation id', async () => {
    const fixture = await makeApp();
    expect((await fixture.app.inject(request())).statusCode).toBe(200);
    expect(fixture.decisions).toEqual([{
      operatorId: 'op_owner',
      agentId: 'agt_origin',
      kind: 'proxy_operation',
      itemId: `sha256:${sha256(OPERATION_ID)}`,
      result: 'succeeded',
    }]);
  });

  it('tells the agent nothing when the reconciliation did not reach an end, or the end was already recorded', async () => {
    const pending = await makeApp({ reconciliation: {
      state: 'confirmed', evidenceHash: EVIDENCE_HASH, providerStatus: 'pending', observedCount: 1,
    } });
    expect((await pending.app.inject(request())).statusCode).toBe(200);
    expect(pending.decisions).toEqual([]);
    const terminal = await makeApp({ metadata: {
      ...baseMetadata,
      reconciliationState: 'confirmed',
      reconciliationEvidenceHash: EVIDENCE_HASH,
      reconciliationProviderStatus: 'succeeded',
    } });
    expect((await terminal.app.inject(request())).statusCode).toBe(200);
    expect(terminal.decisions).toEqual([]);
  });

  it('retries authority completion from durable terminal evidence without another provider read', async () => {
    const terminal: ProxyOperationMetadata = {
      ...baseMetadata,
      reconciliationState: 'confirmed',
      reconciliationEvidenceHash: EVIDENCE_HASH,
      reconciliationProviderStatus: 'succeeded',
    };
    const fixture = await makeApp({ metadata: terminal });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.readStripeReconciliationTarget).not.toHaveBeenCalled();
    expect(fixture.retrieveCredentialPinnedByConnectionId).not.toHaveBeenCalled();
    expect(fixture.reconcile).not.toHaveBeenCalled();
    expect(fixture.recordGovernedReconciliation).not.toHaveBeenCalled();
    expect(fixture.completeRuntimeAuthorityUseByHash).toHaveBeenCalledTimes(1);
  });

  it('completes authority from the durable reconciliation winner, not a losing local provider read', async () => {
    const durableWinner: ProxyOperationMetadata = {
      ...baseMetadata,
      reconciliationState: 'confirmed',
      reconciliationEvidenceHash: `sha256:${'9'.repeat(64)}`,
      reconciliationProviderStatus: 'failed',
    };
    const fixture = await makeApp({ metadataAfterRecord: durableWinner });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.completeRuntimeAuthorityUseByHash).toHaveBeenCalledWith({
      operatorId: 'op_owner',
      useId: 'ause_origin',
      outcome: 'failed',
      resultHash: OPERATION_RESULT_HASH,
    });
  });

  it('treats contradictory evidence as terminal without reading the provider or completing authority', async () => {
    const terminal: ProxyOperationMetadata = {
      ...baseMetadata,
      reconciliationState: 'contradictory',
      reconciliationEvidenceHash: EVIDENCE_HASH,
      reconciliationProviderStatus: null,
    };
    const fixture = await makeApp({ metadata: terminal });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.readStripeReconciliationTarget).not.toHaveBeenCalled();
    expect(fixture.retrieveCredentialPinnedByConnectionId).not.toHaveBeenCalled();
    expect(fixture.reconcile).not.toHaveBeenCalled();
    expect(fixture.recordGovernedReconciliation).not.toHaveBeenCalled();
    expect(fixture.completeRuntimeAuthorityUseByHash).not.toHaveBeenCalled();
  });

  it('keeps an expired recovery window unresolved without emitting a false failed authority outcome', async () => {
    const terminal: ProxyOperationMetadata = {
      ...baseMetadata,
      reconciliationState: 'expired',
      reconciliationEvidenceHash: EVIDENCE_HASH,
      reconciliationProviderStatus: null,
      retryDeadline: new Date(Date.now() - 1_000),
    };
    const fixture = await makeApp({ metadata: terminal });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.readStripeReconciliationTarget).not.toHaveBeenCalled();
    expect(fixture.retrieveCredentialPinnedByConnectionId).not.toHaveBeenCalled();
    expect(fixture.reconcile).not.toHaveBeenCalled();
    expect(fixture.recordGovernedReconciliation).not.toHaveBeenCalled();
    expect(fixture.completeRuntimeAuthorityUseByHash).not.toHaveBeenCalled();
  });

  it('records deadline expiry without reading Stripe or completing authority as failed', async () => {
    const fixture = await makeApp({ metadata: {
      ...baseMetadata,
      retryDeadline: new Date(Date.now() - 1_000),
    } });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.retrieveCredentialPinnedByConnectionId).not.toHaveBeenCalled();
    expect(fixture.reconcile).not.toHaveBeenCalled();
    expect(fixture.recordGovernedReconciliation).toHaveBeenCalledWith(expect.objectContaining({
      state: 'expired',
    }));
    expect(fixture.completeRuntimeAuthorityUseByHash).not.toHaveBeenCalled();
    // Past the provider's window nothing can settle the write: its agent hears it is unresolved.
    expect(fixture.decisions).toEqual([expect.objectContaining({ kind: 'proxy_operation', result: 'unresolved' })]);
  });

  it('records a pending refund without emitting a false authority outcome', async () => {
    const fixture = await makeApp({ reconciliation: {
      state: 'confirmed',
      evidenceHash: EVIDENCE_HASH,
      resourceHash: `sha256:${'r'.repeat(64)}` as const,
      providerStatus: 'pending',
      observedCount: 1,
    } });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(200);
    expect(fixture.recordGovernedReconciliation).toHaveBeenCalledWith(expect.objectContaining({
      state: 'confirmed',
      providerStatus: 'pending',
    }));
    expect(fixture.completeRuntimeAuthorityUseByHash).not.toHaveBeenCalled();
  });

  it.each(['failed', 'canceled'] as const)(
    'maps Stripe %s to a failed authority outcome without calling it success',
    async (providerStatus) => {
      const fixture = await makeApp({ reconciliation: {
        state: 'confirmed',
        evidenceHash: EVIDENCE_HASH,
        resourceHash: `sha256:${'r'.repeat(64)}` as const,
        providerStatus,
        observedCount: 1,
      } });
      const response = await fixture.app.inject(request());
      expect(response.statusCode).toBe(200);
      expect(fixture.completeRuntimeAuthorityUseByHash).toHaveBeenCalledWith({
        operatorId: 'op_owner',
        useId: 'ause_origin',
        outcome: 'failed',
        resultHash: OPERATION_RESULT_HASH,
      });
    },
  );

  it('rejects agent-bearing Authorization even when a valid browser cookie is present', async () => {
    const fixture = await makeApp();
    const response = await fixture.app.inject(request({ authorization: 'Bearer agent-token' }));
    expect(response.statusCode).toBe(401);
    expect(fixture.authorizeHumanMetadata).not.toHaveBeenCalled();
    expect(fixture.reconcile).not.toHaveBeenCalled();
  });

  it('rejects a removed member before operation lookup or provider access', async () => {
    const fixture = await makeApp({
      sessionPayload: { member_id: 'mem_removed', is_member: true },
      member: null,
    });
    const response = await fixture.app.inject(request());
    expect(response.statusCode).toBe(401);
    expect(fixture.authorizeHumanMetadata).not.toHaveBeenCalled();
    expect(fixture.reconcile).not.toHaveBeenCalled();
  });
});

describe.runIf(isDedicatedProxyFixtureDatabase())(
  'human proxy reconciliation concurrency in PostgreSQL',
  () => {
    let fixture: ProxyPostgresFixture;

    beforeAll(async () => { fixture = await createProxyPostgresFixture(); });
    afterAll(async () => { await fixture?.close(); });

    it('serializes concurrent human evidence and preserves the contradictory loser', async () => {
      const operationKey = `operation_reconciliation_${'x'.repeat(24)}`;
      const scenario = await createProxyConcurrencyScenario(
        fixture,
        operationKey,
        'standard',
        false,
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
      const metadata = await fixture.operationService.readMetadata(fixture.ids.operatorId, operationKey);
      if (!metadata) throw new Error('proxy reconciliation fixture operation was not created');
      await fixture.db.update(proxyOperations).set({
        adapter_kind: 'stripe',
        provider: 'stripe',
        native_idempotency_key_hash: sha256(`native:${operationKey}`),
        provider_account_hash: sha256('credential-owner'),
        retry_deadline: new Date(Date.now() + 60_000),
        reconciliation_state: 'pending',
      }).where(eq(proxyOperations.id, metadata.id));

      const evidence = [
        {
          state: 'confirmed' as const,
          evidenceHash: `sha256:${'1'.repeat(64)}`,
          resourceHash: `sha256:${'a'.repeat(64)}`,
          providerStatus: 'succeeded' as const,
        },
        {
          state: 'confirmed' as const,
          evidenceHash: `sha256:${'2'.repeat(64)}`,
          resourceHash: `sha256:${'b'.repeat(64)}`,
          providerStatus: 'failed' as const,
        },
      ];
      const results = await Promise.all(evidence.map((item) => (
        fixture.operationService.transaction((transaction) => (
          fixture.operationService.recordGovernedReconciliation({
            operatorId: fixture.ids.operatorId,
            operationKey,
            ...item,
            transaction,
          })
        ))
      )));
      expect(results).toEqual([true, true]);

      const [operation] = await fixture.db.select().from(proxyOperations)
        .where(eq(proxyOperations.id, metadata.id));
      expect(operation).toMatchObject({
        reconciliation_state: 'confirmed',
      });
      expect(['succeeded', 'failed']).toContain(operation!.reconciliation_provider_status);
      const evidenceRows = await fixture.db.select().from(proxyOperationEvidence)
        .where(eq(proxyOperationEvidence.operation_id, metadata.id));
      expect(evidenceRows).toHaveLength(2);
      expect(new Set(evidenceRows.map((row) => row.evidence_hash))).toEqual(
        new Set(evidence.map((row) => row.evidenceHash)),
      );
      expect(evidenceRows.filter((row) => row.kind === 'contradictory')).toHaveLength(1);
    });
  },
);
