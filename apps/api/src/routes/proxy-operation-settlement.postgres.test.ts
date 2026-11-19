import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import { proxyAccountingReceipts, proxyOperations, sha256 } from '@stack/shared';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';
import {
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  proxyExecutionInput,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';

describe.runIf(isDedicatedProxyFixtureDatabase())('proxy dispatch settlement in PostgreSQL', () => {
  let fixture: ProxyPostgresFixture;

  beforeAll(async () => { fixture = await createProxyPostgresFixture(); });
  afterAll(async () => { await fixture?.close(); });

  it('promotes the one evaluation and commits its operation accounting with dispatch ownership', async () => {
    const operationKey = `operation_settlement_${'a'.repeat(24)}`;
    const input = proxyExecutionInput(fixture, operationKey);
    await fixture.operationService.recordEvaluation({
      operatorId: input.operatorId,
      operationKey,
      evaluationCommitmentHash: input.accounting.evaluationCommitmentHash,
      accountingPeriod: input.accounting.period,
      verdict: 'denied',
      allowanceLimit: null,
      overageUnits10000thCent: 0,
    });

    await expect(executeTransactionSafeProxy(input)).resolves.toMatchObject({ result: { status: 201 } });
    const [receipt] = await fixture.db.select().from(proxyAccountingReceipts).where(and(
      eq(proxyAccountingReceipts.operator_id, fixture.ids.operatorId),
      eq(proxyAccountingReceipts.operation_key_hash, sha256(operationKey)),
    ));
    expect(receipt).toMatchObject({ verdict: 'admitted', allowance_units: 1 });
    const [operation] = await fixture.db.select().from(proxyOperations).where(and(
      eq(proxyOperations.operator_id, fixture.ids.operatorId),
      eq(proxyOperations.operation_key_hash, sha256(operationKey)),
    ));
    expect(operation).toMatchObject({
      accounting_state: 'committed',
      delivery_state: 'response_received',
      transport_attempts: 1,
    });
    expect(operation?.accounting_committed_at).toBeInstanceOf(Date);
  });
});
