import { createHash } from 'node:crypto';
import type { ProxyOperationRepository } from '../repositories/proxy-operation-repo.js';
import { proxyAccountingWalletIdentity } from './proxy-operation-service.js';
import type { ProxyHoldLedger } from './spend/spend-ledger.js';

const PROJECTION_TTL_SECONDS = 70 * 24 * 60 * 60;

export interface ProxyAccountingProjectionStore {
  set(key: string, value: string, mode: 'EX', ttlSeconds: number): Promise<unknown>;
}

export interface ProxyAccountingReconcileResult {
  settlements: number;
  projectedPeriods: number;
  projectionFailures: number;
}

/**
 * Recovers whole-cent proxy charges and refreshes Redis from PostgreSQL.
 *
 * Redis never decides usage or money. Every value is an overwriteable cache
 * projection of a period fixed on the durable receipt at first evaluation.
 */
export class ProxyAccountingReconciler {
  constructor(
    private proxyRepository: ProxyOperationRepository,
    private holds: ProxyHoldLedger,
    private redis: ProxyAccountingProjectionStore,
  ) {}

  async tick(limit = 100): Promise<ProxyAccountingReconcileResult> {
    const affected = new Set<string>();
    let settlements = 0;
    const boundaries = await this.holds.listSettlementBoundaries(limit);
    for (const { receipt } of boundaries) {
      const identity = proxyAccountingWalletIdentity(
        receipt.operator_id,
        receipt.accounting_period,
        receipt.operation_key_hash,
      );
      if (identity.holdId !== receipt.wallet_obligation_id) {
        throw new Error('Proxy accounting receipt has a conflicting wallet obligation');
      }

      // settlePendingHold is idempotent for an already captured hold. A crash
      // after the Wallet transaction but before the receipt update therefore
      // converges on the same deterministic transaction ID.
      await this.holds.settlePendingHold(identity.holdId, receipt.operator_id);
      await this.proxyRepository.commitAccountingThroughSequence({
        operatorId: receipt.operator_id,
        accountingPeriod: receipt.accounting_period,
        throughSequence: receipt.period_sequence,
        walletTransactionId: identity.transactionId,
      });
      settlements += 1;
      affected.add(periodKey(receipt.operator_id, receipt.accounting_period));
    }

    const recentKeys = await this.proxyRepository.listAccountingProjectionKeys(500);
    for (const key of recentKeys) affected.add(periodKey(key.operatorId, key.accountingPeriod));
    let projectedPeriods = 0;
    let projectionFailures = 0;
    for (const key of affected) {
      const [operatorId, accountingPeriod] = parsePeriodKey(key);
      try {
        if (await this.projectPeriod(operatorId, accountingPeriod)) projectedPeriods += 1;
      } catch {
        // Redis is a projection. A cache outage must not roll back or stall
        // already-authoritative PostgreSQL receipts and Wallet settlement.
        projectionFailures += 1;
      }
    }
    return { settlements, projectedPeriods, projectionFailures };
  }

  async projectPeriod(operatorId: string, accountingPeriod: string): Promise<boolean> {
    const projection = await this.proxyRepository.getAccountingProjection(operatorId, accountingPeriod);
    if (!projection) return false;
    const redisKey = `stack:proxy-accounting:v1:${sha256(operatorId)}:${accountingPeriod}`;
    await this.redis.set(redisKey, JSON.stringify({
      version: 1,
      accounting_period: accountingPeriod,
      evaluated_units: projection.evaluatedUnits,
      overage_units_10000th_cent: projection.overageUnits10000thCent,
      committed_cents: projection.committedCents,
      updated_at: projectionTimestamp(projection.updatedAt),
    }), 'EX', PROJECTION_TTL_SECONDS);
    return true;
  }
}

function periodKey(operatorId: string, accountingPeriod: string): string {
  return `${operatorId}\u0000${accountingPeriod}`;
}

function parsePeriodKey(value: string): [string, string] {
  const separator = value.lastIndexOf('\u0000');
  if (separator < 1) throw new Error('Invalid proxy accounting projection key');
  return [value.slice(0, separator), value.slice(separator + 1)];
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function projectionTimestamp(value: Date | string): string {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(timestamp.getTime())) {
    throw new Error('Invalid proxy accounting projection timestamp');
  }
  return timestamp.toISOString();
}
