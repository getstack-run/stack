import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { createDb, operators, proxyAccountingReceipts, type Database } from '@stack/shared';
import { ProxyOperationRepository } from './proxy-operation-repo.js';
import { ProxyOperationService } from '../services/proxy-operation-service.js';
import { isDedicatedVaultTestDatabase } from '../test/dedicated-test-database.js';

// These tests intentionally run only against the isolated local security DB or
// the CI database. They exercise PostgreSQL advisory locks, not an in-memory
// approximation of cross-node accounting.
const fixtureUrl = process.env['DATABASE_URL'];
const run = isDedicatedVaultTestDatabase(fixtureUrl) ? describe : describe.skip;

run('proxy operation accounting in PostgreSQL', () => {
  let db: Database;
  let repository: ProxyOperationRepository;
  let service: ProxyOperationService;
  const suffix = Math.random().toString(36).slice(2);
  const operatorId = `op_proxy_accounting_${suffix}`;
  const accountingPeriod = '2099-12';

  beforeAll(async () => {
    db = createDb(fixtureUrl!);
    repository = new ProxyOperationRepository(db);
    // No wallet: an engine install holds nothing (the default hold ledger). The hosted wallet's cases are in
    // the deployment's own tests.
    service = new ProxyOperationService(repository, {} as never);
    await db.insert(operators).values({
      id: operatorId,
      email: `${operatorId}@test.invalid`,
      api_key_hash: 'inert-fixture-hash',
    });
  });

  beforeEach(async () => {
    await db
      .delete(proxyAccountingReceipts)
      .where(eq(proxyAccountingReceipts.operator_id, operatorId));
  });

  afterAll(async () => {
    if (!db) return;
    await db
      .delete(proxyAccountingReceipts)
      .where(eq(proxyAccountingReceipts.operator_id, operatorId));
    await db.delete(operators).where(eq(operators.id, operatorId));
    await db.$client.end();
  });

  function record(
    operationKey: string,
    evaluationHash: string,
    verdict: 'admitted' | 'denied' = 'admitted',
  ) {
    return service.recordEvaluation({
      operatorId,
      operationKey,
      evaluationCommitmentHash: evaluationHash,
      accountingPeriod,
      verdict,
      allowanceLimit: 2,
      // 100 integer units = 0.01 cent. No floating-point cents are stored.
      overageUnits10000thCent: 100,
    });
  }

  it('counts one logical evaluation once under concurrent cross-node claims', async () => {
    const results = await Promise.all(
      Array.from({ length: 16 }, () =>
        record('abcdefghijklmnopqrstuv', `sha256:${'a'.repeat(64)}`),
      ),
    );
    expect(results.filter((result) => result.state === 'created')).toHaveLength(1);
    expect(results.filter((result) => result.state === 'existing')).toHaveLength(15);
    const rows = await db.query.proxyAccountingReceipts.findMany({
      where: eq(proxyAccountingReceipts.operator_id, operatorId),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      period_sequence: 1,
      allowance_units: 1,
      overage_units_10000th_cent: 0,
      wallet_state: 'none',
    });
  });

  it('serializes allowance crossing for admitted and denied evaluations and creates deterministic obligations', async () => {
    const keys = [
      'abcdefghijklmnopqrstuv',
      'abcdefghijklmnopqrstuw',
      'abcdefghijklmnopqrstux',
      'abcdefghijklmnopqrstuy',
    ];
    await Promise.all(
      keys.map((key, index) =>
        record(key, `sha256:${String(index).repeat(64)}`, index % 2 === 0 ? 'admitted' : 'denied'),
      ),
    );
    const rows = await db.query.proxyAccountingReceipts.findMany({
      where: eq(proxyAccountingReceipts.operator_id, operatorId),
      orderBy: (table, { asc }) => [asc(table.period_sequence)],
    });
    expect(rows.map((row) => row.period_sequence)).toEqual([1, 2, 3, 4]);
    expect(rows.map((row) => row.overage_units_10000th_cent)).toEqual([0, 0, 100, 100]);
    expect(rows.slice(2).every((row) => row.wallet_state === 'pending')).toBe(true);
    for (const row of rows) {
      expect(row.wallet_obligation_id).toMatch(/^whld_proxy_[0-9a-f]{40}$/);
    }
  });

  function boundaryRecord(index: number, period = accountingPeriod) {
    return service.recordEvaluation({
      operatorId,
      operationKey: `opkey_${String(index).padStart(16, '0')}`,
      evaluationCommitmentHash: `sha256:${index.toString(16).padStart(64, '0')}`,
      accountingPeriod: period,
      verdict: index % 2 === 0 ? 'admitted' : 'denied',
      allowanceLimit: 0,
      overageUnits10000thCent: 100,
    });
  }

  it('pins a replay to its original accounting month', async () => {
    const original = await boundaryRecord(1, '2099-11');
    const replay = await boundaryRecord(1, '2099-12');
    expect(replay.state).toBe('existing');
    expect(replay.receipt.id).toBe(original.receipt.id);
    expect(replay.receipt.accounting_period).toBe('2099-11');
    expect(
      await db.query.proxyAccountingReceipts.findMany({
        where: eq(proxyAccountingReceipts.operator_id, operatorId),
      }),
    ).toHaveLength(1);
  });

  it('promotes the original denial receipt once inside the dispatch transaction', async () => {
    const operationKey = 'abcdefghijklmnopqrstuv';
    const evaluationCommitmentHash = `sha256:${'a'.repeat(64)}`;
    const denied = await record(operationKey, evaluationCommitmentHash, 'denied');
    expect(denied.receipt.verdict).toBe('denied');
    await service.transaction(async (transaction) => {
      expect(
        await service.promoteEvaluationToAdmitted({
          operatorId,
          operationKey,
          evaluationCommitmentHash,
          transaction,
        }),
      ).toMatchObject({ id: denied.receipt.id, verdict: 'admitted' });
      expect(
        await service.promoteEvaluationToAdmitted({
          operatorId,
          operationKey,
          evaluationCommitmentHash,
          transaction,
        }),
      ).toMatchObject({ id: denied.receipt.id, verdict: 'admitted' });
    });
    expect(
      await db.query.proxyAccountingReceipts.findMany({
        where: eq(proxyAccountingReceipts.operator_id, operatorId),
      }),
    ).toHaveLength(1);
  });

  it('rejects changed content under the same meter key', async () => {
    const key = 'abcdefghijklmnopqrstuv';
    const first = await record(key, `sha256:${'a'.repeat(64)}`);
    expect(first.state).toBe('created');
    expect((await record(key, `sha256:${'b'.repeat(64)}`)).state).toBe('conflict');

    expect(
      await db.query.proxyAccountingReceipts.findMany({
        where: eq(proxyAccountingReceipts.operator_id, operatorId),
      }),
    ).toHaveLength(1);
  });
});
