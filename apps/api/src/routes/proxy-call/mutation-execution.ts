import { StackError, safeErrorSummary } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import {
  executeTransactionSafeProxy,
  type TransactionSafeProxyResult,
} from '../../lib/transaction-safe-proxy.js';
import type {
  AuthorityDecision,
  ApprovalGateOutcome,
  FleetAdmission,
  ParsedProxyRequest,
  ProxyAccounting,
  ProxyHttpRequest,
  ResolvedProxyTarget,
  ServiceScope,
  ServiceScopeFacts,
  VerifiedProxyPassport,
} from './types.js';

/** The body of the 200 reply to a non-GET proxy request. */
export type ProxyMutationReply = { operation_id: string } & TransactionSafeProxyResult['result'];

/**
 * A non-GET request. Admit, fence, dispatch and retain it as one
 * transaction-safe operation, then wait for the durable record (not the
 * bookkeeping after it) before the caller replies.
 */
export async function executeProxyMutation(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  target: ResolvedProxyTarget,
  accounting: ProxyAccounting,
  authorityDecision: AuthorityDecision,
  fleetAdmission: FleetAdmission,
  approval: ApprovalGateOutcome,
  scopeFacts: ServiceScopeFacts,
  serviceScope: ServiceScope | undefined,
  start: number,
): Promise<ProxyMutationReply> {
  const { input, operationKey } = parsedRequest;
  const { claims, jti, agentId, operatorId, mode, missionIds } = verified;
  const { conn } = target;
  const { accountingOperatorId, accountingKey, evaluationCommitmentHash, accountingReceipt } = accounting;
  const { gate, approvalReplay } = approval;
  const { intentServices } = scopeFacts;
  if (!serviceScope || !accountingReceipt) {
    throw new StackError('Proxy operation authority is incomplete', 'CONFLICT', 409);
  }
  const authorityUseId = 'enforced' in authorityDecision
    ? undefined
    : authorityDecision.authorityUseId;
  const execution = await executeTransactionSafeProxy({
    services,
    ...(fleetAdmission ? { fleetAdmission } : {}),
    requestInput: input as typeof input & { method: 'POST' | 'PUT' | 'PATCH' | 'DELETE' },
    operationKey: operationKey!,
    operatorId,
    agentId,
    passportJti: jti,
    ...(authorityUseId ? { authorityUseId } : {}),
    ...(!('enforced' in authorityDecision) && authorityDecision.executionState
      ? { authorityExecutionState: authorityDecision.executionState }
      : {}),
    gate: {
      skipped: gate.skipped,
      ...(!gate.skipped ? { approvalId: gate.approvalId } : {}),
      ...(approvalReplay ? { replayOnly: true } : {}),
    },
    connection: conn,
    allowedConnections: request.allowedConnections,
    memberId: request.memberId,
    scope: serviceScope,
    intentServices,
    discloseTo: [],
    authorityRefs: [...(claims.stk.authority_refs ?? [])],
    accounting: {
      operatorId: accountingOperatorId,
      operationKey: accountingKey!,
      evaluationCommitmentHash,
      period: accountingReceipt.receipt.accounting_period,
      cents: Math.floor(accountingReceipt.receipt.overage_units_10000th_cent / 10_000),
      obligationId: accountingReceipt.receipt.wallet_obligation_id,
    },
    detectorContext: {
      operatorId,
      agentId,
      passportJti: jti,
      mode,
      tier: request.operatorTier,
    },
    postResponse: {
      accountability: mode === 'enforced' || mode === 'logged' ? mode : 'standard',
      missionIds: missionIds ?? [],
      ...(!gate.skipped ? { approvedIntentClaimId: gate.intentClaimId } : {}),
      auditContext: auditCtx(request, { agent_id: agentId, passport_jti: jti }),
      startedAt: start,
    },
  });

  if (execution.workOperationId) {
    // the response waits for the record (credential marker
    // audit row, undeclared-target check, signed claims including the
    // entity_observation the data-flow rule reads on the agent's next
    // call), not for the bookkeeping after it (analytics, authority-use
    // completion, closing the work item). Those finish on the same lease
    // after the reply; the work is durable, so if this process dies
    // first the worker resumes it from the last completed step.
    const workOperationId = execution.workOperationId;
    const logPending = (continuation: { state: string; error?: unknown }) => {
      if (continuation.state === 'retry_pending') {
        request.log.error(
          { operation_id: workOperationId, error: continuation.error },
          '[proxy operation] durable post-response work remains pending',
        );
      }
    };
    await new Promise<void>((resolve) => {
      void services.proxyPostResponse
        .processOne(workOperationId, { onRecorded: resolve })
        .then(logPending, (error: unknown) => logPending({ state: 'retry_pending', error: safeErrorSummary(error) }))
        .finally(resolve);
    });
  }
  return {
    operation_id: execution.operationId,
    ...execution.result,
  };
}
