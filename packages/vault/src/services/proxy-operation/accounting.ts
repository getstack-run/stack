// Evaluation metering: one receipt per evaluated action, with any whole-cent overage reserved and
// frozen as a wallet obligation in the same transaction.

import { randomUUID } from 'node:crypto';
import { ProxyOperationId } from '@stack/shared';
import { type ProxyOperationTransaction } from '../../repositories/proxy-operation-repo.js';
import { type ProxyOperationDeps } from './types.js';
import { REPLAY_TTL_MS, proxyAccountingWalletIdentity, sha256 } from './envelope.js';

/** PostgreSQL-authoritative meter for admitted and denied evaluations. */
export async function recordEvaluation(deps: ProxyOperationDeps, input: {
  operatorId: string;
  operationKey: string;
  evaluationCommitmentHash: string;
  accountingPeriod: string;
  verdict: 'admitted' | 'denied';
  allowanceLimit: number | null;
  overageUnits10000thCent: number;
  transaction?: ProxyOperationTransaction;
  now?: Date;
}) {
  if (!ProxyOperationId.safeParse(input.operationKey).success) {
    throw new Error('Proxy operation key must be 22 to 256 base64url characters');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(input.evaluationCommitmentHash)) {
    throw new Error('Proxy evaluation commitment must be a canonical sha256 hash');
  }
  if (!/^[0-9]{4}-(0[1-9]|1[0-2])$/.test(input.accountingPeriod)) {
    throw new Error('Proxy accounting period must be a UTC calendar month');
  }
  if (input.allowanceLimit !== null
    && (!Number.isSafeInteger(input.allowanceLimit) || input.allowanceLimit < 0)) {
    throw new Error('Proxy allowance limit must be a non-negative integer or null');
  }
  if (!Number.isSafeInteger(input.overageUnits10000thCent)
    || input.overageUnits10000thCent < 0) {
    throw new Error('Proxy overage must use non-negative integer 0.0001-cent units');
  }
  const operationKeyHash = sha256(input.operationKey);
  const receiptId = `par_${randomUUID()}`;
  const walletIdentity = proxyAccountingWalletIdentity(
    input.operatorId,
    input.accountingPeriod,
    operationKeyHash,
  );
  const execute = async (transaction: ProxyOperationTransaction) => {
    const result = await deps.repository.recordAccountingReceipt({
      id: receiptId,
      operatorId: input.operatorId,
      accountingPeriod: input.accountingPeriod,
      operationKeyHash,
      evaluationHash: input.evaluationCommitmentHash,
      verdict: input.verdict,
      allowanceLimit: input.allowanceLimit,
      overageUnits10000thCent: input.overageUnits10000thCent,
      walletObligationId: walletIdentity.holdId,
      evaluatedAt: input.now,
    }, transaction);
    if (result.state === 'created' && result.wholeCentsToReserve > 0) {
      const now = input.now ?? new Date();
      await deps.holds.reserveInTransaction({
        id: walletIdentity.holdId,
        operator_id: input.operatorId,
        amount_cents: result.wholeCentsToReserve,
        purpose: `proxy_overage:${input.accountingPeriod}:${result.receipt.period_sequence}`,
        expires_at: new Date(now.getTime() + REPLAY_TTL_MS),
      }, transaction);
      await deps.holds.prepareHoldSettlementInTransaction({
        hold_id: walletIdentity.holdId,
        operator_id: input.operatorId,
        amount_cents: result.wholeCentsToReserve,
        transaction: {
          id: walletIdentity.transactionId,
          type: 'overage',
          meter: 'action',
          description: `Proxy action overage for ${input.accountingPeriod}`,
        },
      }, transaction);
    }
    return result;
  };
  return input.transaction ? execute(input.transaction) : deps.repository.transaction(execute);
}
