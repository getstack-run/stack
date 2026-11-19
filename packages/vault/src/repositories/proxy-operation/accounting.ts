// Proxy accounting receipts: one receipt per evaluated logical action, counted exactly once under
// the operator lock, with the fractional overage carried until a whole cent is owed.

import { and, asc, eq, lte, sql } from 'drizzle-orm';
import { type Database, proxyAccountingReceipts } from '@stack/shared';
import { lockOperator } from './internals.js';
import {
  type ProxyOperationTransaction,
  type DbHandle,
  type ProxyAccountingReceipt,
  type ProxyAccountingProjection,
} from './types.js';

/** Count one evaluated logical action exactly once under an operator lock. */
export async function recordAccountingReceipt(database: Database, input: {
  id: string;
  operatorId: string;
  accountingPeriod: string;
  operationKeyHash: string;
  evaluationHash: string;
  verdict: 'admitted' | 'denied';
  allowanceLimit: number | null;
  overageUnits10000thCent: number;
  walletObligationId: string;
  evaluatedAt?: Date;
}, transaction?: ProxyOperationTransaction): Promise<{
  state: 'created' | 'existing' | 'conflict';
  receipt: ProxyAccountingReceipt;
  wholeCentsToReserve: number;
}> {
  const execute = async (db: DbHandle) => {
    await lockOperator(db, input.operatorId);
    // Operation handles are stable across month rollover. A retry in a new
    // month must return the original receipt rather than create usage in a
    // second accounting period.
    const existing = await db.query.proxyAccountingReceipts.findFirst({ where: and(
      eq(proxyAccountingReceipts.operator_id, input.operatorId),
      eq(proxyAccountingReceipts.operation_key_hash, input.operationKeyHash),
    ) });
    if (existing) return {
      state: existing.evaluation_hash === input.evaluationHash ? 'existing' as const : 'conflict' as const,
      receipt: existing,
      wholeCentsToReserve: 0,
    };
    const [prior] = await db.select({
      count: sql<number>`count(*)::int`,
      overage: sql<number>`coalesce(sum(${proxyAccountingReceipts.overage_units_10000th_cent}), 0)::bigint`,
    })
      .from(proxyAccountingReceipts).where(and(
        eq(proxyAccountingReceipts.operator_id, input.operatorId),
        eq(proxyAccountingReceipts.accounting_period, input.accountingPeriod),
      ));
    const periodSequence = (prior?.count ?? 0) + 1;
    const isOverage = input.allowanceLimit !== null && periodSequence > input.allowanceLimit;
    const overage = isOverage ? input.overageUnits10000thCent : 0;
    const priorOverage = Number(prior?.overage ?? 0);
    const wholeCentsToReserve = Math.floor((priorOverage + overage) / 10_000)
      - Math.floor(priorOverage / 10_000);
    const [receipt] = await db.insert(proxyAccountingReceipts).values({
      id: input.id,
      operator_id: input.operatorId,
      accounting_period: input.accountingPeriod,
      operation_key_hash: input.operationKeyHash,
      evaluation_hash: input.evaluationHash,
      verdict: input.verdict,
      period_sequence: periodSequence,
      allowance_units: 1,
      overage_units_10000th_cent: overage,
      wallet_obligation_id: input.walletObligationId,
      wallet_state: overage > 0 ? 'pending' : 'none',
      evaluated_at: input.evaluatedAt ?? new Date(),
    }).returning();
    if (!receipt) throw new Error('Proxy accounting receipt was not persisted');
    return { state: 'created' as const, receipt, wholeCentsToReserve };
  };
  return transaction ? execute(transaction) : database.transaction(execute);
}

/** Promote the once-only denial receipt when the same evaluation reaches dispatch. */
export async function promoteAccountingReceiptToAdmitted(input: {
  operatorId: string;
  operationKeyHash: string;
  evaluationHash: string;
}, transaction: ProxyOperationTransaction): Promise<ProxyAccountingReceipt | null> {
  await lockOperator(transaction, input.operatorId);
  const [promoted] = await transaction.update(proxyAccountingReceipts).set({ verdict: 'admitted' })
    .where(and(
      eq(proxyAccountingReceipts.operator_id, input.operatorId),
      eq(proxyAccountingReceipts.operation_key_hash, input.operationKeyHash),
      eq(proxyAccountingReceipts.evaluation_hash, input.evaluationHash),
      eq(proxyAccountingReceipts.verdict, 'denied'),
    )).returning();
  if (promoted) return promoted;
  const existing = await transaction.query.proxyAccountingReceipts.findFirst({ where: and(
    eq(proxyAccountingReceipts.operator_id, input.operatorId),
    eq(proxyAccountingReceipts.operation_key_hash, input.operationKeyHash),
  ) });
  return existing?.evaluation_hash === input.evaluationHash && existing.verdict === 'admitted'
    ? existing
    : null;
}

/** Commit every still-pending fractional receipt represented by one whole-cent debit. */
export async function commitAccountingThroughSequence(db: Database, input: {
  operatorId: string;
  accountingPeriod: string;
  throughSequence: number;
  walletTransactionId: string;
}, transaction?: ProxyOperationTransaction): Promise<number> {
  const rows = await (transaction ?? db).update(proxyAccountingReceipts).set({
    wallet_state: 'committed',
    wallet_transaction_id: input.walletTransactionId,
    wallet_committed_at: new Date(),
  }).where(and(
    eq(proxyAccountingReceipts.operator_id, input.operatorId),
    eq(proxyAccountingReceipts.accounting_period, input.accountingPeriod),
    eq(proxyAccountingReceipts.wallet_state, 'pending'),
    lte(proxyAccountingReceipts.period_sequence, input.throughSequence),
  )).returning({ id: proxyAccountingReceipts.id });
  return rows.length;
}

export async function listPendingAccountingReceipts(db: Database, limit = 100): Promise<ProxyAccountingReceipt[]> {
  return db.query.proxyAccountingReceipts.findMany({
    where: eq(proxyAccountingReceipts.wallet_state, 'pending'),
    orderBy: [asc(proxyAccountingReceipts.evaluated_at), asc(proxyAccountingReceipts.id)],
    limit: Math.max(1, Math.min(limit, 500)),
  });
}

export async function getAccountingProjection(
  db: Database,
  operatorId: string,
  accountingPeriod: string,
): Promise<ProxyAccountingProjection | null> {
  const [row] = await db.select({
    evaluatedUnits: sql<number>`coalesce(sum(${proxyAccountingReceipts.allowance_units}), 0)::bigint`,
    overageUnits: sql<number>`coalesce(sum(${proxyAccountingReceipts.overage_units_10000th_cent}), 0)::bigint`,
    committedCents: sql<number>`coalesce(sum(case when ${proxyAccountingReceipts.wallet_state} = 'committed' then ${proxyAccountingReceipts.overage_units_10000th_cent} else 0 end), 0)::bigint`,
    updatedAt: sql<Date>`max(coalesce(${proxyAccountingReceipts.wallet_committed_at}, ${proxyAccountingReceipts.evaluated_at}))`,
  }).from(proxyAccountingReceipts).where(and(
    eq(proxyAccountingReceipts.operator_id, operatorId),
    eq(proxyAccountingReceipts.accounting_period, accountingPeriod),
  ));
  if (!row || Number(row.evaluatedUnits) === 0 || !row.updatedAt) return null;
  return {
    operatorId,
    accountingPeriod,
    evaluatedUnits: Number(row.evaluatedUnits),
    overageUnits10000thCent: Number(row.overageUnits),
    committedCents: Math.floor(Number(row.committedCents) / 10_000),
    updatedAt: row.updatedAt,
  };
}

export async function listAccountingProjectionKeys(db: Database, limit = 500): Promise<Array<{
  operatorId: string;
  accountingPeriod: string;
}>> {
  const boundedLimit = Math.max(1, Math.min(limit, 2_000));
  return db.select({
    operatorId: proxyAccountingReceipts.operator_id,
    accountingPeriod: proxyAccountingReceipts.accounting_period,
  }).from(proxyAccountingReceipts)
    .groupBy(proxyAccountingReceipts.operator_id, proxyAccountingReceipts.accounting_period)
    .orderBy(sql`max(${proxyAccountingReceipts.evaluated_at}) desc`)
    .limit(boundedLimit);
}
