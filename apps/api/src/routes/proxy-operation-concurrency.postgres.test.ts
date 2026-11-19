import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import {
  authorityUses,
  intentApprovals,
  passportAuthorityBindings,
  proxyAccountingReceipts,
  proxyOperationAttempts,
  proxyOperations,
  sha256,
} from '@stack/shared';
import { executeTransactionSafeProxy } from '../lib/transaction-safe-proxy.js';
import {
  createProxyConcurrencyScenario,
  createProxyPostgresFixture,
  isDedicatedProxyFixtureDatabase,
  type ProxyPostgresFixture,
} from './proxy-operation-postgres-fixture.js';

const scenarios = (['standard', 'logged', 'enforced'] as const).flatMap((mode) => [
  { mode, authorityBearing: false, passportKind: 'legacy' as const },
  { mode, authorityBearing: true, passportKind: 'authority-bearing' as const },
]);

describe.runIf(isDedicatedProxyFixtureDatabase())('transaction-safe proxy concurrency in PostgreSQL', () => {
  let fixture: ProxyPostgresFixture;

  beforeAll(async () => { fixture = await createProxyPostgresFixture(); });
  afterAll(async () => { await fixture?.close(); });

  it.each(scenarios)(
    'elects one generic dispatch owner for 50 concurrent $mode-mode $passportKind Passport calls',
    async ({ mode, authorityBearing, passportKind }) => {
      const operationKey = `operation_${mode}_${passportKind}_${'x'.repeat(24)}`;
      const scenario = await createProxyConcurrencyScenario(
        fixture,
        operationKey,
        mode,
        authorityBearing,
      );
      const { input } = scenario;
      const attemptsBefore = fixture.upstreamAttempts.count;

      const results = await Promise.all(Array.from({ length: 50 }, async () => {
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
      }));

      expect(fixture.upstreamAttempts.count - attemptsBefore).toBe(1);
      expect(results.some((result) => result.result.status === 201)).toBe(true);
      const operationRows = await fixture.db.select().from(proxyOperations).where(and(
        eq(proxyOperations.operator_id, fixture.ids.operatorId),
        eq(proxyOperations.operation_key_hash, sha256(operationKey)),
      ));
      expect(operationRows).toHaveLength(1);
      expect(operationRows[0]).toMatchObject({
        delivery_state: 'response_received',
        replay_state: 'available',
        accounting_state: 'committed',
        transport_attempts: 1,
        passport_jti: scenario.passportJti,
        approval_id: scenario.approvalId ?? null,
        authority_use_id: scenario.authorityUseId ?? null,
      });
      expect(await fixture.db.select().from(proxyOperationAttempts).where(
        eq(proxyOperationAttempts.operation_id, operationRows[0]!.id),
      )).toHaveLength(1);
      expect(await fixture.db.select().from(proxyAccountingReceipts).where(and(
        eq(proxyAccountingReceipts.operator_id, fixture.ids.operatorId),
        eq(proxyAccountingReceipts.operation_key_hash, sha256(operationKey)),
      ))).toHaveLength(1);

      const approvalRows = await fixture.db.select().from(intentApprovals).where(
        eq(intentApprovals.passport_jti, scenario.passportJti),
      );
      if (scenario.approvalId) {
        expect(approvalRows).toHaveLength(1);
        expect(approvalRows[0]).toMatchObject({
          id: scenario.approvalId,
          status: 'consumed',
          consuming_owner_hash: sha256(operationKey),
        });
      } else {
        expect(approvalRows).toHaveLength(0);
      }

      const authorityBindingRows = await fixture.db.select().from(passportAuthorityBindings).where(
        eq(passportAuthorityBindings.passport_jti, scenario.passportJti),
      );
      const authorityUseRows = await fixture.db.select().from(authorityUses).where(
        eq(authorityUses.passport_jti, scenario.passportJti),
      );
      if (scenario.authorityUseId) {
        expect(authorityBindingRows).toHaveLength(1);
        expect(authorityUseRows).toHaveLength(1);
        expect(authorityUseRows[0]).toMatchObject({
          id: scenario.authorityUseId,
          status: 'dispatched',
        });
        expect(authorityUseRows[0]!.dispatched_at).toBeInstanceOf(Date);
      } else {
        expect(authorityBindingRows).toHaveLength(0);
        expect(authorityUseRows).toHaveLength(0);
      }
    },
    120_000,
  );
});
