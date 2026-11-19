import { describe, expect, it, vi } from 'vitest';
import { executeTransactionSafeProxy, mergeProxyEntityCandidates } from './transaction-safe-proxy.js';

function fixture() {
  let prepared: unknown;
  const operation = {
    id: 'pop_fixture',
    admission_fence: 1,
    dispatch_fence: 0,
    delivery_state: 'admitted',
    replay_state: 'none',
    reconciliation_state: 'not_required',
    adapter_kind: 'generic',
    transport_attempts: 0,
    retry_deadline: null,
    response_hash: null,
  };
  const markOutcomeUnknown = vi.fn(async () => true);
  const services = {
    serviceConnection: {
      retrieveCredentialPinnedByConnectionId: vi.fn(async () => ({
        provider: 'custom_fixture',
        service_id: 'svc_fixture',
        connection_id: 'scon_fixture',
        credential_version: 1,
        credential: 'secret',
        allowed_hosts: ['api.example.invalid'],
      })),
    },
    proxy: {
      validatePrepared: vi.fn(async () => null),
      resolveAuthHeaders: vi.fn(() => ({ authorization: 'Bearer secret' })),
      forwardPrepared: vi.fn(async () => ({
        kind: 'response' as const,
        response: { status: 200, headers: {}, body: { ok: true } },
      })),
    },
    proxyOperation: {
      transaction: vi.fn(async (work: (transaction: unknown) => Promise<unknown>) => work({})),
      admit: vi.fn(async (input: { preparedRequest: unknown }) => {
        prepared = input.preparedRequest;
        return { state: 'created' as const, operation };
      }),
      readReplay: vi.fn(async () => ({ state: 'unavailable' as const, reason: 'none' as const })),
      promoteEvaluationToAdmitted: vi.fn(async () => ({ id: 'receipt' })),
      guardAndConsumeReplacement: vi.fn(async () => ({ state: 'not_required' as const })),
      claimDispatch: vi.fn(async () => ({
        state: 'acquired' as const,
        operation: { ...operation, delivery_state: 'dispatching', adapter_kind: 'generic' },
        dispatchFence: 1,
        dispatchToken: 'owner-token',
      })),
      decryptPreparedRequest: vi.fn(async () => prepared),
      markResponseScreening: vi.fn(async () => true),
      storePermittedResponse: vi.fn(async () => { throw new Error('KMS unavailable'); }),
      markOutcomeUnknown,
    },
    detector: { scanOutput: vi.fn(async () => ({ match: null, redactedBody: null })) },
    approvalGate: {},
    authority: {},
  };
  return { services, markOutcomeUnknown };
}

function postResponse() {
  return {
    accountability: 'standard' as const,
    missionIds: [],
    auditContext: {
      trace_id: 'trace_fixture',
      span_id: 'span_fixture',
      operator_id: 'op_fixture',
      agent_id: 'agt_fixture',
      passport_jti: 'pas_fixture',
    },
    startedAt: Date.now(),
  };
}

describe('transaction-safe proxy crash handling', () => {
  it('caps merged response and outbound entities without misaligning their types', () => {
    const responseEntities = Array.from({ length: 180 }, (_, index) => ({
      entity: `response-${index}@example.invalid`,
      entity_type: 'email' as const,
    }));
    const outboundEntities = Array.from({ length: 180 }, (_, index) => ({
      entity: `outbound-${index}@example.invalid`,
      entity_type: 'email' as const,
    }));
    const merged = mergeProxyEntityCandidates(responseEntities, outboundEntities);
    expect(merged).toHaveLength(256);
    expect(merged[255]).toEqual(outboundEntities[75]);
  });

  it('reports durable uncertainty and never returns an unstored provider response after finalization fails', async () => {
    const { services, markOutcomeUnknown } = fixture();
    const result = await executeTransactionSafeProxy({
      services: services as never,
      requestInput: {
        service: 'custom_fixture',
        url: 'https://api.example.invalid/v1/write',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { amount: 1 },
      },
      operationKey: `operation_${'x'.repeat(24)}`,
      operatorId: 'op_fixture',
      agentId: 'agt_fixture',
      passportJti: 'pas_fixture',
      gate: { skipped: true },
      connection: {
        provider: 'custom_fixture',
        service_id: 'svc_fixture',
        connection_id: 'scon_fixture',
        credential_version: 1,
        proxy_enabled: true,
        allowed_hosts: ['api.example.invalid'],
      },
      scope: { scopes: ['write'] },
      intentServices: ['custom_fixture'],
      discloseTo: [],
      authorityRefs: [],
      accounting: {
        operatorId: 'op_fixture',
        operationKey: `operation_${'x'.repeat(24)}`,
        evaluationCommitmentHash: `sha256:${'a'.repeat(64)}`,
        period: '2026-09',
        cents: 0,
        obligationId: 'obligation',
      },
      detectorContext: {} as never,
      postResponse: postResponse(),
    });

    expect(result).toMatchObject({
      result: { status: 202, body: { delivery_state: 'outcome_unknown' } },
      authorityOutcome: null,
    });
    expect(markOutcomeUnknown).toHaveBeenCalledWith(expect.objectContaining({
      operationId: 'pop_fixture',
      dispatchFence: 1,
    }));
  });

  it('repairs generic authority completion from a stored replay without another provider call', async () => {
    const { services } = fixture();
    const responseHash = 'b'.repeat(64);
    const replayOperation = {
      id: 'pop_fixture',
      admission_fence: 1,
      dispatch_fence: 1,
      delivery_state: 'response_received',
      replay_state: 'available',
      reconciliation_state: 'not_required',
      adapter_kind: 'generic',
      transport_attempts: 1,
      retry_deadline: null,
      response_hash: responseHash,
    };
    services.proxyOperation.admit.mockResolvedValueOnce({
      state: 'replay',
      operation: replayOperation,
    } as never);
    Object.assign(services.proxyOperation, {
      readReplay: vi.fn(async () => ({
        state: 'available' as const,
        status: 201,
        headers: { 'content-type': 'application/json' },
        body: { id: 'provider_result' },
      })),
    });

    const result = await executeTransactionSafeProxy({
      services: services as never,
      requestInput: {
        service: 'custom_fixture',
        url: 'https://api.example.invalid/v1/write',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { amount: 1 },
      },
      operationKey: `operation_${'x'.repeat(24)}`,
      operatorId: 'op_fixture',
      agentId: 'agt_fixture',
      passportJti: 'pas_fixture',
      authorityUseId: 'aus_fixture',
      authorityExecutionState: 'dispatched',
      gate: { skipped: true },
      connection: {
        provider: 'custom_fixture',
        service_id: 'svc_fixture',
        connection_id: 'scon_fixture',
        credential_version: 1,
        proxy_enabled: true,
        allowed_hosts: ['api.example.invalid'],
      },
      scope: { scopes: ['write'] },
      intentServices: ['custom_fixture'],
      discloseTo: [],
      authorityRefs: [],
      accounting: {
        operatorId: 'op_fixture',
        operationKey: `operation_${'x'.repeat(24)}`,
        evaluationCommitmentHash: `sha256:${'a'.repeat(64)}`,
        period: '2026-09',
        cents: 0,
        obligationId: 'obligation',
      },
      detectorContext: {} as never,
      postResponse: postResponse(),
    });

    expect(result).toMatchObject({
      replayed: true,
      responseHash: `sha256:${responseHash}`,
      authorityOutcome: 'succeeded',
      result: { status: 201, body: { id: 'provider_result' } },
    });
    expect(services.proxy.forwardPrepared).not.toHaveBeenCalled();
  });

  it('replays a stored Stripe 500 without claiming another provider attempt', async () => {
    const { services } = fixture();
    services.serviceConnection.retrieveCredentialPinnedByConnectionId.mockResolvedValueOnce({
      provider: 'stripe',
      service_id: 'svc_fixture',
      connection_id: 'scon_fixture',
      credential_version: 1,
      credential: 'sk_test_fixture',
      allowed_hosts: ['api.stripe.com'],
    });
    services.proxyOperation.admit.mockResolvedValueOnce({
      state: 'replay',
      operation: {
        id: 'pop_fixture',
        admission_fence: 1,
        dispatch_fence: 1,
        delivery_state: 'response_received',
        replay_state: 'available',
        reconciliation_state: 'pending',
        adapter_kind: 'stripe',
        transport_attempts: 1,
        retry_deadline: new Date(Date.now() + 60_000),
        response_hash: 'c'.repeat(64),
      },
    } as never);
    services.proxyOperation.readReplay.mockResolvedValueOnce({
      state: 'available', status: 500, headers: {}, body: { error: 'provider unresolved' },
    } as never);
    const claimStripeRetry = vi.fn();
    Object.assign(services.proxyOperation, { claimStripeRetry });

    const result = await executeTransactionSafeProxy({
      services: services as never,
      requestInput: {
        service: 'stripe',
        url: 'https://api.stripe.com/v1/refunds',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: { payment_intent: 'pi_fixture', amount: 100 },
      },
      operationKey: `operation_${'s'.repeat(24)}`,
      operatorId: 'op_fixture',
      agentId: 'agt_fixture',
      passportJti: 'pas_fixture',
      gate: { skipped: true },
      connection: {
        provider: 'stripe', service_id: 'svc_fixture', connection_id: 'scon_fixture',
        credential_version: 1, proxy_enabled: true, allowed_hosts: ['api.stripe.com'],
      },
      scope: { scopes: ['write'] },
      intentServices: ['stripe'],
      discloseTo: [],
      authorityRefs: [],
      accounting: {
        operatorId: 'op_fixture',
        operationKey: `operation_${'s'.repeat(24)}`,
        evaluationCommitmentHash: `sha256:${'a'.repeat(64)}`,
        period: '2026-09', cents: 0, obligationId: 'obligation',
      },
      detectorContext: {} as never,
      postResponse: postResponse(),
    });

    expect(result).toMatchObject({ replayed: true, result: { status: 500 } });
    expect(claimStripeRetry).not.toHaveBeenCalled();
    expect(services.proxy.forwardPrepared).not.toHaveBeenCalled();
  });

  it('fails before a Stripe retry dispatch when replay capacity cannot be reserved', async () => {
    const { services } = fixture();
    const retryDeadline = new Date(Date.now() + 60_000);
    services.proxyOperation.admit.mockResolvedValueOnce({
      state: 'replay',
      operation: {
        id: 'pop_fixture',
        admission_fence: 1,
        dispatch_fence: 1,
        delivery_state: 'outcome_unknown',
        replay_state: 'none',
        reconciliation_state: 'not_found',
        adapter_kind: 'stripe',
        transport_attempts: 1,
        retry_deadline: retryDeadline,
        response_hash: null,
      },
    } as never);
    const claimStripeRetry = vi.fn(async () => ({
      state: 'capacity_exceeded' as const,
      kind: 'replay_bytes' as const,
      limit: 256 * 1024 * 1024,
      used: 256 * 1024 * 1024,
    }));
    Object.assign(services.proxyOperation, {
      claimStripeRetry,
      originalPassportAllowsRetry: vi.fn(async () => true),
    });

    await expect(executeTransactionSafeProxy({
      services: services as never,
      requestInput: {
        service: 'custom_fixture',
        url: 'https://api.example.invalid/v1/write',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { amount: 1 },
      },
      operationKey: `operation_${'x'.repeat(24)}`,
      operatorId: 'op_fixture',
      agentId: 'agt_fixture',
      passportJti: 'pas_fixture',
      gate: { skipped: true },
      connection: {
        provider: 'custom_fixture',
        service_id: 'svc_fixture',
        connection_id: 'scon_fixture',
        credential_version: 1,
        proxy_enabled: true,
        allowed_hosts: ['api.example.invalid'],
      },
      scope: { scopes: ['write'] },
      intentServices: ['custom_fixture'],
      discloseTo: [],
      authorityRefs: [],
      accounting: {
        operatorId: 'op_fixture',
        operationKey: `operation_${'x'.repeat(24)}`,
        evaluationCommitmentHash: `sha256:${'a'.repeat(64)}`,
        period: '2026-09',
        cents: 0,
        obligationId: 'obligation',
      },
      detectorContext: {} as never,
      postResponse: postResponse(),
    })).rejects.toMatchObject({ code: 'CAPACITY_EXCEEDED', statusCode: 429 });

    expect(claimStripeRetry).toHaveBeenCalledWith(expect.objectContaining({
      capacityBytes: expect.any(Number),
    }));
    expect(services.proxy.forwardPrepared).not.toHaveBeenCalled();
  });
});

describe('a call to a connected service\'s MCP endpoint', () => {
  const run = (services: ReturnType<typeof fixture>['services'], url: string, body: unknown) => executeTransactionSafeProxy({
    services: services as never,
    requestInput: { service: 'custom_fixture', url, method: 'POST', headers: { 'content-type': 'application/json' }, body },
    operationKey: `operation_${'m'.repeat(24)}`,
    operatorId: 'op_fixture',
    agentId: 'agt_fixture',
    passportJti: 'pas_fixture',
    gate: { skipped: true },
    connection: {
      provider: 'custom_fixture', service_id: 'svc_fixture', connection_id: 'scon_fixture',
      credential_version: 1, proxy_enabled: true, allowed_hosts: ['api.example.invalid'],
    },
    scope: { scopes: ['write'] },
    intentServices: ['custom_fixture'],
    discloseTo: [],
    authorityRefs: [],
    accounting: {
      operatorId: 'op_fixture', operationKey: `operation_${'m'.repeat(24)}`, evaluationCommitmentHash: `sha256:${'a'.repeat(64)}`,
      period: '2026-11', cents: 0, obligationId: 'obligation',
    },
    detectorContext: {} as never,
    postResponse: postResponse(),
  });

  function mcpFixture(mcpUrl: string | null) {
    const { services } = fixture();
    services.serviceConnection.retrieveCredentialPinnedByConnectionId.mockResolvedValue({
      provider: 'custom_fixture', service_id: 'svc_fixture', connection_id: 'scon_fixture', credential_version: 1,
      credential: 'secret', allowed_hosts: ['api.example.invalid'], mcp_url: mcpUrl,
    } as never);
    const forwardMcpPrepared = vi.fn(async () => ({ kind: 'response' as const, response: { status: 200, headers: {}, body: { ok: true } } }));
    Object.assign(services.proxy, { forwardMcpPrepared });
    return { services, forwardMcpPrepared };
  }

  const rpc = { jsonrpc: '2.0', id: 1, method: 'tools/list' };

  it('is sent inside an MCP session, as the one admitted operation', async () => {
    const { services, forwardMcpPrepared } = mcpFixture('https://api.example.invalid/mcp');
    await run(services, 'https://api.example.invalid/mcp', rpc);
    expect(forwardMcpPrepared).toHaveBeenCalledTimes(1);
    expect(services.proxy.forwardPrepared).not.toHaveBeenCalled();
    expect(services.proxyOperation.admit).toHaveBeenCalledTimes(1);
    expect(services.proxyOperation.claimDispatch).toHaveBeenCalledTimes(1);
  });

  it('goes as it is to any other path of the service, and when the connection has no MCP endpoint', async () => {
    const other = mcpFixture('https://api.example.invalid/mcp');
    await run(other.services, 'https://api.example.invalid/v1/write', rpc);
    expect(other.forwardMcpPrepared).not.toHaveBeenCalled();
    expect(other.services.proxy.forwardPrepared).toHaveBeenCalledTimes(1);

    const none = mcpFixture(null);
    await run(none.services, 'https://api.example.invalid/mcp', rpc);
    expect(none.forwardMcpPrepared).not.toHaveBeenCalled();
    expect(none.services.proxy.forwardPrepared).toHaveBeenCalledTimes(1);
  });
});
