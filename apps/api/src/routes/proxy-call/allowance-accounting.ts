import {
  StackError,
  canonicalize,
  sha256,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { isSystemOperator } from '../../lib/action-meter.js';
import { pooledAccountingKey } from '../../lib/pooled-accounting.js';
import type {
  ParsedProxyRequest,
  ProxyAccounting,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  VerifiedProxyPassport,
} from './types.js';

/**
 * Record the evaluation receipt that fences this operation against the
 * billing account's allowance, and refuse a call past a blocking cap or a
 * reused operation handle.
 */
export async function recordProxyEvaluation(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
): Promise<ProxyAccounting> {
  const { isMutation, operationKey } = parsedRequest;
  const { operatorId, agentId, jti } = verified;
  const { normalizedRequest, conn } = target;
  const accountingNow = new Date();
  const accountingPeriod = `${accountingNow.getUTCFullYear()}-${String(accountingNow.getUTCMonth() + 1).padStart(2, '0')}`;
  const evaluationCommitmentHash = `sha256:${sha256(canonicalize({
    version: 1,
    operator_id: operatorId,
    agent_id: agentId,
    passport_jti: jti,
    connection_id: conn.connection_id,
    credential_version: conn.credential_version,
    approval_id: request.headers['x-intent-approval-id'] ?? null,
    request: normalizedRequest,
  }))}`;
  // The pool, the receipt sequence, its lock and the wallet obligation
  // belong to the billing account: the operator, or a white-label
  // tenant's partner. A tenant's receipts are keyed by a tenant-scoped
  // handle so each tenant's retries stay idempotent without colliding
  // with another tenant's handle under the shared partner account.
  const billing = await services.entitlements.resolve(operatorId);
  const accountingOperatorId = billing.planOperatorId;
  const accountingKey = isMutation
    ? (billing.pooled ? pooledAccountingKey(operatorId, operationKey!) : operationKey!)
    : null;
  const unbilled = isSystemOperator(operatorId) || isSystemOperator(accountingOperatorId);
  const tierLimit = billing.limits.actionsPerMonth;
  const blockAtCap = billing.limits.overage === 'block';
  // Every agent's action is priced on the account action meter
  // (meterProxyAction); the receipt still fences the operation but charges
  // nothing. A partner on a hard cap keeps the cap through the receipt.
  const accountPriced = !unbilled && !blockAtCap;
  // A hard-capped partner's pool is read from the meter that counted it.
  const sharedUsed = isMutation && !unbilled && !accountPriced && tierLimit !== Infinity
    ? (await services.actionMeter.pool(billing, accountingNow)).used
    : 0;
  if (!Number.isSafeInteger(sharedUsed) || sharedUsed < 0) {
    throw new StackError('Shared action usage is unavailable', 'SERVICE_UNAVAILABLE', 503);
  }
  const allowanceLimit = unbilled || accountPriced || tierLimit === Infinity
    ? null
    : Math.max(0, tierLimit - sharedUsed);
  const accountingReceipt = isMutation
    ? await services.proxyOperation.recordEvaluation({
        operatorId: accountingOperatorId,
        operationKey: accountingKey!,
        evaluationCommitmentHash,
        accountingPeriod,
        verdict: 'denied',
        allowanceLimit,
        // The receipt never charges: block mode refuses past the cap below, and
        // every other action is priced on the account meter.
        overageUnits10000thCent: 0,
      })
    : null;
  if (
    accountingReceipt
    && blockAtCap
    && allowanceLimit !== null
    && accountingReceipt.receipt.period_sequence > allowanceLimit
  ) {
    throw new StackError(
      `Monthly action allowance reached for this account. ${billing.isTenant ? 'Contact your platform provider.' : 'Contact STACK to raise the limit.'}`,
      'ALLOWANCE_EXHAUSTED',
      402,
    );
  }
  if (accountingReceipt?.state === 'conflict') {
    throw new StackError(
      'Operation handle was already used for a different request',
      'CONFLICT',
      409,
    );
  }
  return { accountingOperatorId, accountingKey, evaluationCommitmentHash, accountingReceipt, accountPriced };
}
