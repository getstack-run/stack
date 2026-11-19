import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { proxyOperations } from '@stack/shared';
import { ProxyPostResponseService } from '@stack/vault';
import { eq } from 'drizzle-orm';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';
import { finalizeProxyResponse } from '../lib/finalize-proxy-response.js';
import {
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  proxyExecutionInput,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';

describe.runIf(isDedicatedProxyFixtureDatabase())('transaction-safe proxy replay in PostgreSQL', () => {
  let fixture: ProxyPostgresFixture;

  beforeAll(async () => { fixture = await createProxyPostgresFixture(); });
  afterAll(async () => { await fixture?.close(); });

  it('replays the one stored permitted response across service instances without another dispatch', async () => {
    const operationKey = `operation_replay_${'r'.repeat(24)}`;
    const input = proxyExecutionInput(fixture, operationKey);
    fixture.upstreamResponse.body = { id: 'created_once', echoed_secret: 'test-secret' };
    fixture.upstreamResponse.headers.authorization = 'Bearer test-secret';

    const execute = async () => {
      await fixture.operationService.recordEvaluation({
        operatorId: input.operatorId,
        operationKey,
        evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
        accountingPeriod: input.accounting.period,
        verdict: 'admitted',
        allowanceLimit: null,
        overageUnits10000thCent: 0,
      });
      return executeTransactionSafeProxy(input);
    };

    const first = await execute();
    const second = await execute();
    expect(fixture.upstreamAttempts.count).toBe(1);
    expect(first.result).toEqual(second.result);
    expect(first.result.body).toEqual({ id: 'created_once', echoed_secret: '[REDACTED BY STACK]' });
    expect(first.result.headers).not.toHaveProperty('authorization');
    expect(second.replayed).toBe(true);
  });

  it('keeps post-response work durable after a producer failure and completes it without redispatch', async () => {
    const operationKey = `operation_post_response_${'p'.repeat(24)}`;
    const input = proxyExecutionInput(fixture, operationKey);
    const before = fixture.upstreamAttempts.count;
    await fixture.operationService.recordEvaluation({
      operatorId: input.operatorId,
      operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      accountingPeriod: input.accounting.period,
      verdict: 'admitted',
      allowanceLimit: null,
      overageUnits10000thCent: 0,
    });
    const first = await executeTransactionSafeProxy(input);
    expect(first.workOperationId).toMatch(/^pop_/);

    let auditFails = true;
    const processor = new ProxyPostResponseService({
      proxyOperation: fixture.operationService,
      redis: { sadd: async () => 1, expire: async () => 1 },
      audit: {
        write: async () => {
          if (auditFails) throw new Error('simulated audit outage');
          return 'audit_entry';
        },
      },
      claimRegistry: {
        registerClaim: async () => ({
          claimId: 'pc_post_response',
          envelopeCose: 'test',
          subject: 'stack://test',
        }),
      },
      authority: { completeRuntimeAuthorityUseByHash: async () => {} },
      securityEvent: { record: async () => null },
      passportClaimsRepo: { findObservedContentForFlow: async () => [] },
      analytics: { fireOnce: async () => {}, capture: () => {} },
    } as never);

    const failed = await processor.processOne(first.workOperationId);
    expect(failed.state).toBe('retry_pending');
    const pending = await fixture.repository.findById(input.operatorId, first.workOperationId!);
    expect(pending?.post_response_work_state).toBe('pending');
    expect(pending?.post_response_credential_at).toBeInstanceOf(Date);
    expect(pending?.post_response_audit_at).toBeNull();
    expect(pending?.post_response_attempts).toBe(1);
    expect(pending?.post_response_next_attempt_at?.getTime()).toBeGreaterThan(Date.now());

    const immediate = await processor.tick(100);
    expect(immediate.failed).toBeLessThan(100);
    const stillPending = await fixture.repository.findById(input.operatorId, first.workOperationId!);
    expect(stillPending?.post_response_attempts).toBe(1);

    auditFails = false;
    await fixture.db.update(proxyOperations).set({
      post_response_next_attempt_at: new Date(Date.now() - 1),
    }).where(eq(proxyOperations.id, first.workOperationId!));
    const completed = await processor.processOne(first.workOperationId);
    expect(completed.state).toBe('completed');
    const done = await fixture.repository.findById(input.operatorId, first.workOperationId!);
    expect(done?.post_response_work_state).toBe('completed');
    expect(done?.post_response_context_encrypted).toBeNull();

    await fixture.operationService.recordEvaluation({
      operatorId: input.operatorId,
      operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      accountingPeriod: input.accounting.period,
      verdict: 'admitted',
      allowanceLimit: null,
      overageUnits10000thCent: 0,
    });
    const replay = await executeTransactionSafeProxy(input);
    expect(replay.replayed).toBe(true);
    expect(fixture.upstreamAttempts.count - before).toBe(1);
  });
});

describe('permitted response credential scrubbing', () => {
  const detector = { scanOutput: async () => ({ match: null, redactedBody: null }) };

  it('scrubs an exact credential used as a JSON property name', async () => {
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: {} as never,
      response: { status: 200, headers: {}, body: { 'secret-value': 'present' } },
      rawCredential: 'secret-value',
      service: 'custom_test',
      method: 'POST',
    });
    expect(result.response.body).toEqual({ '[REDACTED BY STACK]': 'present' });
  });

  it('scrubs the exact injected Basic header and encoded credential', async () => {
    const encoded = Buffer.from('user:password').toString('base64');
    const header = `Basic ${encoded}`;
    const result = await finalizeProxyResponse({
      detector: detector as never,
      detectorContext: {} as never,
      response: { status: 200, headers: {}, body: { header, encoded } },
      rawCredential: JSON.stringify({ username: 'user', password: 'password' }),
      injectedAuthHeaders: { authorization: header },
      service: 'custom_test',
      method: 'POST',
    });
    expect(JSON.stringify(result.response.body)).not.toContain(header);
    expect(JSON.stringify(result.response.body)).not.toContain(encoded);
  });
});
