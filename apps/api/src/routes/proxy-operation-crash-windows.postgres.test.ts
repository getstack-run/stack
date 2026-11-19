import { proxyOperationAttempts, proxyOperationEvidence, proxyOperations, sha256 } from '@stack/shared';
import { eq } from 'drizzle-orm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';
import {
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  proxyExecutionInput,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';

describe.runIf(isDedicatedProxyFixtureDatabase())('transaction-safe proxy crash windows in PostgreSQL', () => {
  let fixture: ProxyPostgresFixture;

  beforeEach(async () => { fixture = await createProxyPostgresFixture(); });
  afterEach(async () => {
    vi.restoreAllMocks();
    await fixture?.close();
  });

  async function meter(input: ReturnType<typeof proxyExecutionInput>) {
    await fixture.operationService.recordEvaluation({
      operatorId: input.operatorId,
      operationKey: input.operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      accountingPeriod: input.accounting.period,
      verdict: 'admitted',
      allowanceLimit: null,
      overageUnits10000thCent: 0,
    });
  }

  function stripeRefundInput(operationKey: string) {
    const input = proxyExecutionInput(fixture, operationKey);
    fixture.services.serviceConnection.retrieveCredentialPinnedByConnectionId = async () => ({
      provider: 'stripe',
      service_id: fixture.ids.serviceId,
      connection_id: fixture.ids.connectionId,
      credential_version: 1,
      credential: 'test-secret',
      allowed_hosts: ['api.stripe.com'],
    }) as never;
    return {
      ...input,
      requestInput: {
        ...input.requestInput,
        service: 'stripe',
        url: 'https://api.stripe.com/v1/refunds',
        body: { payment_intent: 'pi_fixture', amount: 100 },
      },
      connection: {
        ...input.connection,
        provider: 'stripe',
        allowed_hosts: ['api.stripe.com'],
      },
      intentServices: ['stripe'],
    };
  }

  async function executeAgainWithoutRedispatch(
    input: ReturnType<typeof proxyExecutionInput>,
    forward: ReturnType<typeof vi.fn>,
  ) {
    await meter(input);
    const replay = await executeTransactionSafeProxy(input);
    expect(replay.result).toMatchObject({
      status: 202,
      body: { delivery_state: 'outcome_unknown' },
    });
    expect(replay.authorityOutcome).toBeNull();
    expect(forward).toHaveBeenCalledTimes(1);
  }

  it('keeps a generic socket-loss outcome unknown and never silently sends again', async () => {
    const input = proxyExecutionInput(fixture, `operation_unknown_${'u'.repeat(24)}`);
    const forward = vi.fn(async () => ({ kind: 'outcome_unknown' as const, reason: 'socket_closed_after_send' }));
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;
    await meter(input);
    const first = await executeTransactionSafeProxy(input);
    await meter(input);
    const second = await executeTransactionSafeProxy(input);

    expect(forward).toHaveBeenCalledTimes(1);
    expect(first.result).toMatchObject({ status: 202, body: { delivery_state: 'outcome_unknown' } });
    expect(second.result).toMatchObject({ status: 202, body: { delivery_state: 'outcome_unknown' } });
    expect(first.authorityOutcome).toBeNull();
    expect(second.authorityOutcome).toBeNull();
  });

  it('does not redispatch when mandatory response screening fails after receipt', async () => {
    const input = proxyExecutionInput(fixture, `operation_screening_${'s'.repeat(24)}`);
    const forward = vi.fn(async () => ({
      kind: 'response' as const,
      response: { status: 200, headers: {}, body: { accepted: true } },
    }));
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;
    fixture.services.detector.scanOutput = vi.fn(async () => { throw new Error('detector unavailable'); });
    await meter(input);
    const first = await executeTransactionSafeProxy(input);
    await meter(input);
    const second = await executeTransactionSafeProxy(input);

    expect(forward).toHaveBeenCalledTimes(1);
    expect(first.result).toMatchObject({ status: 202, body: { delivery_state: 'outcome_unknown' } });
    expect(second.result.status).toBe(202);
    expect(first.authorityOutcome).toBeNull();
    expect(second.authorityOutcome).toBeNull();
  });

  it.each([
    ['the upstream times out after send', 'timeout'],
    ['the upstream response exceeds the read limit after send', 'response_too_large'],
  ] as const)('keeps the outcome unknown and never redispatches when %s', async (_label, reason) => {
    const input = proxyExecutionInput(fixture, `operation_${reason}_${'t'.repeat(24)}`);
    const forward = vi.fn(async () => ({ kind: 'outcome_unknown' as const, reason }));
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;

    await meter(input);
    const first = await executeTransactionSafeProxy(input);
    expect(first.result).toMatchObject({
      status: 202,
      body: { delivery_state: 'outcome_unknown' },
    });
    await executeAgainWithoutRedispatch(input, forward);
  });

  it.each([
    ['response KMS encryption', 'kms'],
    ['PostgreSQL response persistence', 'database'],
  ] as const)('keeps the outcome unknown when %s fails after provider receipt', async (_label, failure) => {
    const input = proxyExecutionInput(fixture, `operation_${failure}_${'f'.repeat(24)}`);
    const forward = vi.fn(async () => ({
      kind: 'response' as const,
      response: { status: 201, headers: {}, body: { created: true } },
    }));
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;
    if (failure === 'kms') {
      fixture.kms.failNextResponseEncrypt();
    } else {
      vi.spyOn(fixture.repository, 'storeResponse')
        .mockRejectedValueOnce(new Error('simulated response write failure'));
    }

    await meter(input);
    const first = await executeTransactionSafeProxy(input);
    expect(first.result).toMatchObject({
      status: 202,
      body: { delivery_state: 'outcome_unknown' },
    });
    await executeAgainWithoutRedispatch(input, forward);
  });

  it('leaves an interrupted post-claim process fenced until lease recovery marks it unknown', async () => {
    const input = proxyExecutionInput(fixture, `operation_process_${'p'.repeat(24)}`);
    const forward = vi.fn(async () => {
      throw new Error('simulated process termination after durable dispatch');
    });
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;

    await meter(input);
    await expect(executeTransactionSafeProxy(input)).rejects.toThrow('simulated process termination');
    const dispatching = await fixture.repository.findByOperationKey(
      fixture.ids.operatorId,
      sha256(input.operationKey),
    );
    expect(dispatching).toMatchObject({ delivery_state: 'dispatching', transport_attempts: 1 });

    expect(await fixture.operationService.markExpiredDispatchesUnknown(
      new Date(Date.now() + 10 * 60 * 1_000),
    )).toBeGreaterThanOrEqual(1);
    await executeAgainWithoutRedispatch(input, forward);
  });

  it('marks a write unresolved once its outcome stayed unknown for seven days, once, and sends nothing again', async () => {
    const input = proxyExecutionInput(fixture, `operation_unresolved_${'u'.repeat(24)}`);
    const forward = vi.fn(async () => {
      throw new Error('simulated process termination after durable dispatch');
    });
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;
    await meter(input);
    await expect(executeTransactionSafeProxy(input)).rejects.toThrow('simulated process termination');
    await fixture.operationService.markExpiredDispatchesUnknown(new Date(Date.now() + 10 * 60 * 1_000));
    const keyHash = sha256(input.operationKey);
    const mine = (rows: Array<{ operator_id: string }>) => rows.filter((row) => row.operator_id === fixture.ids.operatorId);

    // Six days unknown: not yet.
    const sixDays = new Date(Date.now() - 6 * 86_400_000);
    await fixture.db.update(proxyOperations).set({ outcome_unknown_at: sixDays }).where(eq(proxyOperations.operation_key_hash, keyHash));
    expect(mine(await fixture.operationService.markUnresolvedDue())).toEqual([]);

    // Eight days unknown: unresolved, returned once with what the agent and the owner are told by.
    const eightDays = new Date(Date.now() - 8 * 86_400_000);
    await fixture.db.update(proxyOperations).set({ outcome_unknown_at: eightDays }).where(eq(proxyOperations.operation_key_hash, keyHash));
    const now = new Date();
    expect(mine(await fixture.operationService.markUnresolvedDue(now))).toEqual([expect.objectContaining({
      operator_id: fixture.ids.operatorId,
      agent_id: fixture.ids.agentId,
      operation_key_hash: keyHash,
      method: 'POST',
    })]);
    expect(mine(await fixture.operationService.markUnresolvedDue())).toEqual([]);
    const [row] = await fixture.db.select().from(proxyOperations).where(eq(proxyOperations.operation_key_hash, keyHash));
    expect(row).toMatchObject({ delivery_state: 'outcome_unknown', unresolved_at: now });
    expect(forward).toHaveBeenCalledTimes(1);

    // The status reads say so.
    const status = await fixture.operationService.authorizeHumanMetadata({
      operatorId: fixture.ids.operatorId, operationKey: input.operationKey,
    });
    expect(status?.unresolvedAt).toEqual(now);
  });

  it('never marks unresolved a Stripe write a reconciliation settled, and does mark one whose window ran out', async () => {
    const evidence = `sha256:${'e'.repeat(64)}`;
    const unknownStripeWrite = async (name: string) => {
      const base = stripeRefundInput(`operation_${name}_${'s'.repeat(24)}`);
      // Three separate refunds, so none is read as a replacement of another.
      const input = { ...base, requestInput: { ...base.requestInput, body: { payment_intent: `pi_${name}`, amount: 100 } } };
      fixture.services.proxy.forwardPrepared = vi.fn(async () => {
        throw new Error('simulated process termination after durable dispatch');
      }) as typeof fixture.services.proxy.forwardPrepared;
      await meter(input);
      await expect(executeTransactionSafeProxy(input)).rejects.toThrow('simulated process termination');
      await fixture.operationService.markExpiredDispatchesUnknown(new Date(Date.now() + 10 * 60 * 1_000));
      return sha256(input.operationKey);
    };
    const settled = await unknownStripeWrite('settled');
    const confirmed = await unknownStripeWrite('confirmed');
    const lapsed = await unknownStripeWrite('lapsed');
    const eightDays = new Date(Date.now() - 8 * 86_400_000);
    await fixture.db.update(proxyOperations).set({
      outcome_unknown_at: eightDays, reconciliation_state: 'contradictory', reconciliation_evidence_hash: evidence,
    }).where(eq(proxyOperations.operation_key_hash, settled));
    await fixture.db.update(proxyOperations).set({
      outcome_unknown_at: eightDays, reconciliation_state: 'confirmed', reconciliation_evidence_hash: evidence,
      reconciliation_provider_status: 'succeeded',
    }).where(eq(proxyOperations.operation_key_hash, confirmed));
    await fixture.db.update(proxyOperations).set({
      outcome_unknown_at: eightDays, reconciliation_state: 'expired', reconciliation_evidence_hash: evidence,
    }).where(eq(proxyOperations.operation_key_hash, lapsed));
    const marked = (await fixture.operationService.markUnresolvedDue()).map((row) => row.operation_key_hash);
    expect(marked).not.toContain(settled);
    expect(marked).not.toContain(confirmed);
    expect(marked).toContain(lapsed);
  });

  it('accepts the original owner late after lease expiry while rejecting a different owner', async () => {
    const input = proxyExecutionInput(fixture, `operation_late_owner_${'l'.repeat(24)}`);
    let releaseResponse!: () => void;
    let markSent!: () => void;
    const sent = new Promise<void>((resolve) => { markSent = resolve; });
    const responseReleased = new Promise<void>((resolve) => { releaseResponse = resolve; });
    const forward = vi.fn(async () => {
      markSent();
      await responseReleased;
      return {
        kind: 'response' as const,
        response: { status: 201, headers: {}, body: { accepted_late: true } },
      };
    });
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;

    await meter(input);
    const execution = executeTransactionSafeProxy(input);
    await sent;
    expect(await fixture.operationService.markExpiredDispatchesUnknown(
      new Date(Date.now() + 10 * 60 * 1_000),
    )).toBeGreaterThanOrEqual(1);
    const expired = await fixture.repository.findByOperationKey(
      fixture.ids.operatorId,
      sha256(input.operationKey),
    );
    expect(expired).toMatchObject({ delivery_state: 'outcome_unknown', dispatch_fence: 1 });
    await expect(fixture.operationService.storePermittedResponse({
      operatorId: fixture.ids.operatorId,
      operationId: expired!.id,
      dispatchToken: 'different-owner',
      dispatchFence: expired!.dispatch_fence,
      status: 200,
      rawHeaders: {},
      screenedBody: { forbidden: true },
      capacityBytes: 1_000_000,
      transportEvidenceHash: `sha256:${sha256('different-owner')}`,
    })).resolves.toBeNull();

    releaseResponse();
    const late = await execution;
    expect(late).toMatchObject({
      replayed: false,
      result: { status: 201, body: { accepted_late: true } },
    });
    await meter(input);
    const replay = await executeTransactionSafeProxy(input);
    expect(replay).toMatchObject({
      replayed: true,
      result: { status: 201, body: { accepted_late: true } },
    });
    expect(forward).toHaveBeenCalledTimes(1);
  });

  it('appends late response evidence without overwriting a contradictory provider resolution', async () => {
    const input = stripeRefundInput(`operation_late_contradiction_${'c'.repeat(24)}`);
    let releaseResponse!: () => void;
    let markSent!: () => void;
    const sent = new Promise<void>((resolve) => { markSent = resolve; });
    const responseReleased = new Promise<void>((resolve) => { releaseResponse = resolve; });
    fixture.services.proxy.forwardPrepared = vi.fn(async () => {
      markSent();
      await responseReleased;
      return {
        kind: 'response' as const,
        response: { status: 201, headers: {}, body: { arrived_late: true } },
      };
    }) as typeof fixture.services.proxy.forwardPrepared;

    await meter(input);
    const execution = executeTransactionSafeProxy(input);
    await sent;
    expect(await fixture.operationService.markExpiredDispatchesUnknown(
      new Date(Date.now() + 10 * 60 * 1_000),
    )).toBeGreaterThanOrEqual(1);
    const unknown = await fixture.repository.findByOperationKey(
      fixture.ids.operatorId,
      sha256(input.operationKey),
    );
    const providerEvidence = `sha256:${sha256('provider-contradiction')}` as const;
    expect(await fixture.repository.recordReconciliation({
      operatorId: fixture.ids.operatorId,
      operationId: unknown!.id,
      dispatchOwnerHash: unknown!.dispatch_owner_hash!,
      dispatchFence: unknown!.dispatch_fence,
      state: 'contradictory',
      resourceHash: `sha256:${sha256('provider-resource')}`,
      evidenceHash: providerEvidence,
      late: true,
    })).toBe(true);

    releaseResponse();
    const result = await execution;
    expect(result.result).toMatchObject({
      status: 202,
      body: { delivery_state: 'outcome_unknown' },
    });
    const [operation] = await fixture.db.select().from(proxyOperations).where(
      eq(proxyOperations.id, unknown!.id),
    );
    expect(operation).toMatchObject({
      reconciliation_state: 'contradictory',
      reconciliation_evidence_hash: providerEvidence,
      response_encrypted: null,
    });
    const evidence = await fixture.db.select().from(proxyOperationEvidence).where(
      eq(proxyOperationEvidence.operation_id, unknown!.id),
    );
    expect(evidence).toHaveLength(2);
    expect(evidence.map((row) => row.evidence_hash)).toContain(providerEvidence);
    const [attempt] = await fixture.db.select().from(proxyOperationAttempts).where(
      eq(proxyOperationAttempts.operation_id, unknown!.id),
    );
    expect(attempt).toMatchObject({ outcome: 'contradictory', response_status: 201 });
    expect(attempt!.late_evidence_at).toBeInstanceOf(Date);
  });

  it('fences a stale Stripe owner after a reconciled retry acquires the next dispatch fence', async () => {
    const input = stripeRefundInput(`operation_stale_owner_${'o'.repeat(24)}`);
    const markUnknown = vi.spyOn(fixture.operationService, 'markOutcomeUnknown');
    let releaseRetry!: () => void;
    let markRetryStarted!: () => void;
    const retryStarted = new Promise<void>((resolve) => { markRetryStarted = resolve; });
    const retryReleased = new Promise<void>((resolve) => { releaseRetry = resolve; });
    const forward = vi.fn()
      .mockResolvedValueOnce({ kind: 'outcome_unknown' as const, reason: 'timeout' })
      .mockImplementationOnce(async () => {
        markRetryStarted();
        await retryReleased;
        return {
          kind: 'response' as const,
          response: { status: 200, headers: {}, body: { id: 'recovered' } },
        };
      });
    fixture.services.proxy.forwardPrepared = forward as typeof fixture.services.proxy.forwardPrepared;

    await meter(input);
    await executeTransactionSafeProxy(input);
    const firstOwner = markUnknown.mock.calls[0]?.[0];
    expect(firstOwner).toBeDefined();
    expect(await fixture.operationService.recordReconciliation({
      operatorId: fixture.ids.operatorId,
      operationId: firstOwner!.operationId,
      dispatchToken: firstOwner!.dispatchToken,
      dispatchFence: firstOwner!.dispatchFence,
      state: 'not_found',
      evidenceHash: `sha256:${sha256('stripe-not-found-before-retry')}`,
    })).toBe(true);

    await meter(input);
    const retryExecution = executeTransactionSafeProxy(input);
    await retryStarted;
    const staleProviderEvidence = `sha256:${sha256('stale-first-owner-provider-read')}` as const;
    await expect(fixture.operationService.recordReconciliation({
      operatorId: fixture.ids.operatorId,
      operationId: firstOwner!.operationId,
      dispatchToken: firstOwner!.dispatchToken,
      dispatchFence: firstOwner!.dispatchFence,
      state: 'confirmed',
      resourceHash: `sha256:${sha256('stale-provider-resource')}`,
      evidenceHash: staleProviderEvidence,
      providerStatus: 'succeeded',
      late: true,
    })).resolves.toBe(true);
    const staleEvidenceHash = `sha256:${sha256('stale-first-owner-response')}` as const;
    await expect(fixture.operationService.storePermittedResponse({
      operatorId: fixture.ids.operatorId,
      operationId: firstOwner!.operationId,
      dispatchToken: firstOwner!.dispatchToken,
      dispatchFence: firstOwner!.dispatchFence,
      status: 200,
      rawHeaders: {},
      screenedBody: { stale: true },
      capacityBytes: 1_000_000,
      transportEvidenceHash: staleEvidenceHash,
    })).resolves.toBeNull();

    releaseRetry();
    const retried = await retryExecution;
    expect(retried.result).toMatchObject({ status: 200, body: { id: 'recovered' } });
    expect(forward).toHaveBeenCalledTimes(2);
    const row = await fixture.repository.findByOperationKey(
      fixture.ids.operatorId,
      sha256(input.operationKey),
    );
    expect(row).toMatchObject({
      delivery_state: 'response_received',
      dispatch_fence: firstOwner!.dispatchFence + 1,
      transport_attempts: 2,
    });
    const evidence = await fixture.db.select().from(proxyOperationEvidence).where(
      eq(proxyOperationEvidence.operation_id, firstOwner!.operationId),
    );
    expect(evidence.map((entry) => entry.evidence_hash)).toEqual(
      expect.arrayContaining([staleProviderEvidence, staleEvidenceHash]),
    );
  });

  it('keeps late response status and hash evidence after payload erasure', async () => {
    const input = proxyExecutionInput(fixture, `operation_erased_late_${'e'.repeat(24)}`);
    let releaseResponse!: () => void;
    let markSent!: () => void;
    const sent = new Promise<void>((resolve) => { markSent = resolve; });
    const responseReleased = new Promise<void>((resolve) => { releaseResponse = resolve; });
    fixture.services.proxy.forwardPrepared = vi.fn(async () => {
      markSent();
      await responseReleased;
      return { kind: 'response' as const, response: { status: 204, headers: {}, body: null } };
    }) as typeof fixture.services.proxy.forwardPrepared;
    await meter(input);
    const execution = executeTransactionSafeProxy(input);
    await sent;
    const dispatched = await fixture.repository.findByOperationKey(
      input.operatorId,
      sha256(input.operationKey),
    );
    expect(dispatched).not.toBeNull();
    expect(await fixture.repository.erasePayloads(input.operatorId, dispatched!.id)).toBe(1);
    releaseResponse();
    await expect(execution).resolves.toMatchObject({
      result: { status: 202, body: { delivery_state: 'outcome_unknown' } },
    });
    const [operation] = await fixture.db.select().from(proxyOperations).where(
      eq(proxyOperations.id, dispatched!.id),
    );
    expect(operation).toMatchObject({ replay_state: 'erased', response_encrypted: null });
    const evidence = await fixture.db.select().from(proxyOperationEvidence).where(
      eq(proxyOperationEvidence.operation_id, dispatched!.id),
    );
    expect(evidence).toHaveLength(1);
    expect(evidence[0]).toMatchObject({ kind: 'late' });
    expect(evidence[0]!.evidence_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    const [attempt] = await fixture.db.select().from(proxyOperationAttempts).where(
      eq(proxyOperationAttempts.operation_id, dispatched!.id),
    );
    expect(attempt?.response_status).toBe(204);
    expect(attempt?.late_evidence_at).toBeInstanceOf(Date);
  });

  it('preserves terminal reconciliation evidence while payload erasure races contradictory evidence', async () => {
    const input = stripeRefundInput(`operation_reconcile_erase_${'r'.repeat(24)}`);
    const markUnknown = vi.spyOn(fixture.operationService, 'markOutcomeUnknown');
    fixture.services.proxy.forwardPrepared = vi.fn(async () => ({
      kind: 'outcome_unknown' as const,
      reason: 'timeout',
    })) as typeof fixture.services.proxy.forwardPrepared;

    await meter(input);
    await executeTransactionSafeProxy(input);
    const owner = markUnknown.mock.calls[0]?.[0];
    expect(owner).toBeDefined();
    const confirmedEvidence = `sha256:${sha256('race-confirmed')}` as const;
    const contradictoryEvidence = `sha256:${sha256('race-contradictory')}` as const;
    const [confirmed, contradictory, erased] = await Promise.all([
      fixture.operationService.recordReconciliation({
        operatorId: fixture.ids.operatorId,
        operationId: owner!.operationId,
        dispatchToken: owner!.dispatchToken,
        dispatchFence: owner!.dispatchFence,
        state: 'confirmed',
        resourceHash: `sha256:${sha256('refund-confirmed')}`,
        evidenceHash: confirmedEvidence,
        providerStatus: 'succeeded',
      }),
      fixture.operationService.recordReconciliation({
        operatorId: fixture.ids.operatorId,
        operationId: owner!.operationId,
        dispatchToken: owner!.dispatchToken,
        dispatchFence: owner!.dispatchFence,
        state: 'contradictory',
        resourceHash: `sha256:${sha256('refund-contradictory')}`,
        evidenceHash: contradictoryEvidence,
        late: true,
      }),
      fixture.repository.erasePayloads(fixture.ids.operatorId, owner!.operationId),
    ]);
    expect([confirmed, contradictory, erased]).toEqual([true, true, 1]);

    const [row] = await fixture.db.select().from(proxyOperations).where(
      eq(proxyOperations.id, owner!.operationId),
    );
    expect(row).toMatchObject({
      replay_state: 'erased',
      prepared_request_encrypted: null,
      scope_descriptor_encrypted: null,
      response_encrypted: null,
      capacity_used_bytes: 0,
    });
    expect(['confirmed', 'contradictory']).toContain(row!.reconciliation_state);
    const evidence = await fixture.db.select().from(proxyOperationEvidence).where(
      eq(proxyOperationEvidence.operation_id, owner!.operationId),
    );
    expect(evidence.map((entry) => entry.evidence_hash)).toEqual(
      expect.arrayContaining([confirmedEvidence, contradictoryEvidence]),
    );
  });
});
