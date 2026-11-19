import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { and, eq } from 'drizzle-orm';
import { canonicalize, proxyAccountingReceipts, proxyOperations, sha256 } from '@stack/shared';
import {
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  proxyExecutionInput,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';

describe.runIf(isDedicatedProxyFixtureDatabase())('proxy pre-dispatch accounting in PostgreSQL', () => {
  let fixture: ProxyPostgresFixture;

  beforeAll(async () => { fixture = await createProxyPostgresFixture(); });
  afterEach(() => { vi.restoreAllMocks(); });
  afterAll(async () => { await fixture?.close(); });

  it('counts an evaluated denial once without creating a delivery reservation', async () => {
    const operationKey = `operation_denied_${'d'.repeat(24)}`;
    const evaluationCommitmentHash = `sha256:${sha256('bounded-denial')}`;
    const results = await Promise.all(Array.from({ length: 20 }, () =>
      fixture.operationService.recordEvaluation({
        operatorId: fixture.ids.operatorId,
        operationKey,
        evaluationCommitmentHash,
        accountingPeriod: '2099-12',
        verdict: 'denied',
        allowanceLimit: 100,
        overageUnits10000thCent: 100,
      })));

    expect(results.filter((result) => result.state === 'created')).toHaveLength(1);
    expect(results.filter((result) => result.state === 'existing')).toHaveLength(19);
    expect(await fixture.db.select().from(proxyAccountingReceipts).where(and(
      eq(proxyAccountingReceipts.operator_id, fixture.ids.operatorId),
      eq(proxyAccountingReceipts.operation_key_hash, sha256(operationKey)),
    ))).toHaveLength(1);
    expect(await fixture.db.select().from(proxyOperations).where(
      eq(proxyOperations.operator_id, fixture.ids.operatorId),
    )).toHaveLength(0);
  });

  it('rolls back admission before capacity rejection can consume dispatch authority', async () => {
    const operationKey = `operation_capacity_${'c'.repeat(24)}`;
    const input = proxyExecutionInput(fixture, operationKey) as Parameters<
      typeof executeTransactionSafeProxy
    >[0];
    await fixture.operationService.recordEvaluation({
      operatorId: fixture.ids.operatorId,
      operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      accountingPeriod: input.accounting.period,
      verdict: 'denied',
      allowanceLimit: 100,
      overageUnits10000thCent: 100,
    });

    input.gate = { skipped: false, approvalId: `ia_capacity_${'a'.repeat(24)}` };
    input.authorityUseId = `aus_capacity_${'a'.repeat(24)}`;
    input.authorityExecutionState = 'authorized';

    // The fixture does not build the full authority graph. Keep the admission
    // itself real while removing only those optional foreign-key links; the
    // transaction still receives the authority/approval inputs and would run
    // their side effects if capacity were checked too late.
    const admit = fixture.operationService.admit.bind(fixture.operationService);
    vi.spyOn(fixture.operationService, 'admit').mockImplementation((admitInput, transaction) => {
      const withoutOptionalLinks = { ...admitInput };
      delete withoutOptionalLinks.authorityUseId;
      delete withoutOptionalLinks.approvalId;
      const prepared = admitInput.preparedRequest;
      const parsedUrl = new URL(prepared.finalUrl);
      withoutOptionalLinks.preparedRequest = {
        ...prepared,
        requestHash: `sha256:${sha256(canonicalize({
          version: 1,
          operator_id: admitInput.operatorId,
          agent_id: admitInput.agentId,
          passport_jti: admitInput.passportJti,
          authority_use_id: null,
          approval_id: null,
          service_connection_id: admitInput.connectionId,
          credential_version: admitInput.credentialVersion,
          destination_config_hash: admitInput.destinationConfigHash,
          service: prepared.service,
          method: prepared.method,
          origin: prepared.persistence.origin,
          pathname: parsedUrl.pathname,
          query_pairs: [...parsedUrl.searchParams.entries()],
          headers: Object.entries(prepared.headers),
          body_kind: prepared.bodyKind,
          body_bytes: prepared.bodyBytes,
        }))}`,
      };
      return admit(withoutOptionalLinks, transaction);
    });
    vi.spyOn(fixture.operationService, 'claimDispatch').mockResolvedValue({
      state: 'capacity_exceeded',
      kind: 'replay_bytes',
      limit: 256 * 1024 * 1024,
      used: 256 * 1024 * 1024,
    });
    const replacement = vi.spyOn(fixture.operationService, 'guardAndConsumeReplacement');
    const reserveApproval = vi.spyOn(fixture.services.approvalGate, 'reserveForDispatch');
    const consumeApproval = vi.spyOn(fixture.services.approvalGate, 'markConsumed');
    const claimAuthority = vi.spyOn(fixture.services.authority, 'claimRuntimeAuthorityDispatch');

    await expect(executeTransactionSafeProxy(input)).rejects.toMatchObject({
      code: 'CAPACITY_EXCEEDED',
      statusCode: 429,
    });

    expect(fixture.upstreamAttempts.count).toBe(0);
    expect(replacement).toHaveBeenCalledOnce();
    expect(reserveApproval).not.toHaveBeenCalled();
    expect(consumeApproval).not.toHaveBeenCalled();
    expect(claimAuthority).not.toHaveBeenCalled();
    expect(await fixture.db.select().from(proxyOperations).where(and(
      eq(proxyOperations.operator_id, fixture.ids.operatorId),
      eq(proxyOperations.operation_key_hash, sha256(operationKey)),
    ))).toHaveLength(0);
    expect(await fixture.db.select().from(proxyAccountingReceipts).where(and(
      eq(proxyAccountingReceipts.operator_id, fixture.ids.operatorId),
      eq(proxyAccountingReceipts.operation_key_hash, sha256(operationKey)),
      eq(proxyAccountingReceipts.verdict, 'denied'),
    ))).toHaveLength(1);
  });

  it('keeps a replacement-required operation admitted without claiming dispatch', async () => {
    const operationKey = `operation_replacement_${'r'.repeat(24)}`;
    const input = proxyExecutionInput(fixture, operationKey) as Parameters<
      typeof executeTransactionSafeProxy
    >[0];
    await fixture.operationService.recordEvaluation({
      operatorId: fixture.ids.operatorId,
      operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      accountingPeriod: input.accounting.period,
      verdict: 'denied',
      allowanceLimit: 100,
      overageUnits10000thCent: 100,
    });
    vi.spyOn(fixture.operationService, 'guardAndConsumeReplacement').mockResolvedValue({
      state: 'authorization_required',
    });
    const claimDispatch = vi.spyOn(fixture.operationService, 'claimDispatch');

    const result = await executeTransactionSafeProxy(input);

    expect(result.result).toMatchObject({
      status: 202,
      body: { delivery_state: 'replacement_authorization_required' },
    });
    expect(claimDispatch).not.toHaveBeenCalled();
    expect(fixture.upstreamAttempts.count).toBe(0);
    expect(await fixture.db.select({
      deliveryState: proxyOperations.delivery_state,
      dispatchFence: proxyOperations.dispatch_fence,
    }).from(proxyOperations).where(and(
      eq(proxyOperations.operator_id, fixture.ids.operatorId),
      eq(proxyOperations.operation_key_hash, sha256(operationKey)),
    ))).toEqual([{ deliveryState: 'admitted', dispatchFence: 0 }]);
  });
});
