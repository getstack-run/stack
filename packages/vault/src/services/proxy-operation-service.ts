import { randomBytes, randomUUID } from 'node:crypto';
import { PROXY_OPERATION_UNRESOLVED_AFTER_DAYS, ProxyOperationId } from '@stack/shared';
import type { KmsService } from '../crypto/kms.js';
import type {
  DispatchClaimResult,
  ProxyOperationRepository,
  ProxyOperationTransaction,
} from '../repositories/proxy-operation-repo.js';
import { NO_PROXY_HOLDS, type ProxyHoldLedger } from './spend/spend-ledger.js';
import * as accounting from './proxy-operation/accounting.js';
import * as dispatch from './proxy-operation/dispatch.js';
import {
  OWNER_LEASE_MS,
  PROXY_REPLACEMENT_WARNING,
  PROXY_REPLACEMENT_WARNING_HASH,
  PROXY_REPLACEMENT_WARNING_VERSION,
  admissionOwnerHashFor,
  sha256,
} from './proxy-operation/envelope.js';
import * as postResponse from './proxy-operation/post-response.js';
import * as reconciliation from './proxy-operation/reconciliation.js';
import * as replay from './proxy-operation/replay.js';
import type {
  AdmitProxyOperationInput,
  ProxyOperationDeps,
} from './proxy-operation/types.js';

export {
  PROXY_REPLACEMENT_WARNING_VERSION,
  PROXY_REPLACEMENT_WARNING,
  PROXY_REPLACEMENT_WARNING_HASH,
  SAFE_PROXY_REPLAY_HEADERS,
  postResponseRetryAt,
  proxyAccountingWalletIdentity,
  hashProxyOperationKey,
  admissionOwnerHashFor,
  preparedAad,
  responseAad,
  scopeAad,
  postResponseAad,
  proxyOwnerTokenMatches,
} from './proxy-operation/envelope.js';
export type {
  PreparedProxyRequest,
  ProxyScopeDescriptor,
  ProxyPostResponseContext,
  ClaimedProxyPostResponseWork,
  FreshProxyAuthority,
  AdmitProxyOperationInput,
  AdmitProxyOperationResult,
  ProxyReplayResult,
  ProxyOperationMetadata,
  StripeReconciliationTarget,
} from './proxy-operation/types.js';

export class ProxyOperationService {
  private readonly deps: ProxyOperationDeps;

  constructor(
    private repository: ProxyOperationRepository,
    kms: KmsService,
    holds: ProxyHoldLedger = NO_PROXY_HOLDS,
  ) {
    this.deps = { repository, kms, holds };
  }

  transaction<T>(work: (tx: ProxyOperationTransaction) => Promise<T>): Promise<T> {
    return this.repository.transaction(work);
  }

  /**
   * Writes whose outcome has been unknown for PROXY_OPERATION_UNRESOLVED_AFTER_DAYS with nothing settling them become
   * unresolved, returned so their agent and owner are told. Nothing is ever sent again: a replacement still needs a
   * person.
   */
  markUnresolvedDue(now: Date = new Date(), limit = 200) {
    const olderThan = new Date(now.getTime() - PROXY_OPERATION_UNRESOLVED_AFTER_DAYS * 86_400_000);
    return this.repository.markUnresolvedDue(olderThan, now, limit);
  }

  /** PostgreSQL-authoritative meter for admitted and denied evaluations. */
  recordEvaluation(input: Parameters<typeof accounting.recordEvaluation>[1]) {
    return accounting.recordEvaluation(this.deps, input);
  }

  /** Same receipt, same period, one verdict transition in the dispatch transaction. */
  promoteEvaluationToAdmitted(input: {
    operatorId: string;
    operationKey: string;
    evaluationCommitmentHash: string;
    transaction: ProxyOperationTransaction;
  }) {
    return this.repository.promoteAccountingReceiptToAdmitted({
      operatorId: input.operatorId,
      operationKeyHash: sha256(input.operationKey),
      evaluationHash: input.evaluationCommitmentHash,
    }, input.transaction);
  }

  listPendingAccountingReceipts(limit?: number) {
    return this.repository.listPendingAccountingReceipts(limit);
  }

  admit(input: AdmitProxyOperationInput, transaction?: ProxyOperationTransaction) {
    return dispatch.admit(this.deps, input, transaction);
  }

  async claimDispatch(input: {
    operatorId: string;
    operationId: string;
    operationKey: string;
    admissionFence: number;
    capacityBytes: number;
    requestEvidenceHash: string;
    transaction?: ProxyOperationTransaction;
    now?: Date;
  }): Promise<(DispatchClaimResult & { dispatchToken?: string })> {
    const dispatchToken = randomBytes(32).toString('base64url');
    const result = await this.repository.claimDispatch({
      operatorId: input.operatorId,
      operationId: input.operationId,
      admissionOwnerHash: admissionOwnerHashFor(input.operatorId, input.operationKey),
      admissionFence: input.admissionFence,
      dispatchOwnerHash: sha256(dispatchToken),
      leaseExpiresAt: new Date((input.now ?? new Date()).getTime() + OWNER_LEASE_MS),
      capacityBytes: input.capacityBytes,
      requestEvidenceHash: input.requestEvidenceHash,
    }, input.transaction);
    return result.state === 'acquired' ? { ...result, dispatchToken } : result;
  }

  async claimStripeRetry(input: {
    operatorId: string;
    operationId: string;
    capacityBytes: number;
    requestEvidenceHash: string;
    transaction?: ProxyOperationTransaction;
    now?: Date;
  }): Promise<(DispatchClaimResult & { dispatchToken?: string })> {
    const dispatchToken = randomBytes(32).toString('base64url');
    const result = await this.repository.claimStripeRetry({
      operatorId: input.operatorId,
      operationId: input.operationId,
      dispatchOwnerHash: sha256(dispatchToken),
      leaseExpiresAt: new Date((input.now ?? new Date()).getTime() + OWNER_LEASE_MS),
      capacityBytes: input.capacityBytes,
      requestEvidenceHash: input.requestEvidenceHash,
    }, input.transaction);
    return result.state === 'acquired' ? { ...result, dispatchToken } : result;
  }

  markResponseScreening(input: {
    operatorId: string; operationId: string; dispatchToken: string; dispatchFence: number;
  }) {
    return this.repository.markResponseScreening({
      ...input, dispatchOwnerHash: sha256(input.dispatchToken),
    });
  }

  markOutcomeUnknown(input: {
    operatorId: string; operationId: string; dispatchToken: string; dispatchFence: number;
    transportEvidenceHash?: string;
  }) {
    return this.repository.markOutcomeUnknown({
      ...input, dispatchOwnerHash: sha256(input.dispatchToken),
    });
  }

  recordLateResponseEvidence(input: {
    operatorId: string;
    operationId: string;
    dispatchToken: string;
    dispatchFence: number;
    status: number;
    evidenceHash: string;
  }) {
    return this.repository.recordLateResponseEvidence({
      operatorId: input.operatorId,
      operationId: input.operationId,
      dispatchOwnerHash: sha256(input.dispatchToken),
      dispatchFence: input.dispatchFence,
      status: input.status,
      evidenceHash: input.evidenceHash,
    });
  }

  markExpiredDispatchesUnknown(now?: Date) {
    return this.repository.markExpiredDispatchesUnknown(now);
  }

  originalPassportAllowsRetry(
    operatorId: string,
    passportJti: string,
    agentId: string,
    now?: Date,
  ) {
    return this.repository.originalPassportAllowsReplay(operatorId, passportJti, agentId, now);
  }

  recordReconciliation(input: {
    operatorId: string; operationId: string; dispatchToken: string; dispatchFence: number;
    state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
    resourceHash?: string; evidenceHash: string;
    providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
    late?: boolean;
  }) {
    return this.repository.recordReconciliation({
      ...input, dispatchOwnerHash: sha256(input.dispatchToken),
    });
  }

  /** Transaction-scoped human resolution; caller rechecks current governance first. */
  recordReconciliationByGovernance(input: {
    operatorId: string; operationKey: string;
    state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
    resourceHash?: string; evidenceHash: string;
    providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
    late?: boolean;
    transaction: ProxyOperationTransaction;
  }) {
    return this.repository.recordReconciliationByGovernance({
      operatorId: input.operatorId,
      operationKeyHash: sha256(input.operationKey),
      state: input.state,
      resourceHash: input.resourceHash,
      evidenceHash: input.evidenceHash,
      providerStatus: input.providerStatus,
      late: input.late,
    }, input.transaction);
  }

  releaseBeforeDispatch(input: {
    operatorId: string; operationId: string; operationKey: string; admissionFence: number;
  }) {
    return this.repository.releaseBeforeDispatch({
      operatorId: input.operatorId,
      operationId: input.operationId,
      admissionFence: input.admissionFence,
      admissionOwnerHash: admissionOwnerHashFor(input.operatorId, input.operationKey),
    });
  }

  expireReplay(now?: Date) {
    return this.repository.expireReplay(now);
  }

  erasePayloads(operatorId: string, operationId?: string) {
    return this.repository.erasePayloads(operatorId, operationId);
  }

  /** Store only the detector-screened body and a fixed safe-header projection. */
  storePermittedResponse(input: Parameters<typeof replay.storePermittedResponse>[1]) {
    return replay.storePermittedResponse(this.deps, input);
  }

  claimPostResponseWork(operationId?: string) {
    return postResponse.claimPostResponseWork(this.deps, operationId);
  }

  /** Rewrite the stored contexts of queued post-response work so none names a URL's query string. Idempotent. */
  redactQueuedPostResponseContexts(options?: { batch?: number }) {
    return postResponse.redactQueuedPostResponseContexts(this.deps, options);
  }

  markPostResponseStep(input: {
    operatorId: string;
    operationId: string;
    token: string;
    step: import('../repositories/proxy-operation-repo.js').ProxyPostResponseStep;
    intentClaimId?: string;
    outcomeClaimId?: string;
  }) {
    return this.repository.markPostResponseStep({
      operatorId: input.operatorId,
      operationId: input.operationId,
      ownerHash: sha256(input.token),
      step: input.step,
      intentClaimId: input.intentClaimId,
      outcomeClaimId: input.outcomeClaimId,
    });
  }

  releasePostResponseWork(input: {
    operatorId: string;
    operationId: string;
    token: string;
    waitingForProvider?: boolean;
    complete?: boolean;
    retryAt?: Date;
  }) {
    return this.repository.releasePostResponseWork({
      operatorId: input.operatorId,
      operationId: input.operationId,
      ownerHash: sha256(input.token),
      waitingForProvider: input.waitingForProvider,
      complete: input.complete,
      retryAt: input.retryAt,
    });
  }

  readReplay(operatorId: string, operationKey: string, now?: Date) {
    return replay.readReplay(this.deps, operatorId, operationKey, now);
  }

  readMetadata(operatorId: string, operationKey: string) {
    return replay.readMetadata(this.deps, operatorId, operationKey);
  }

  authorizeHumanMetadata(input: Parameters<typeof replay.authorizeHumanMetadata>[1]) {
    return replay.authorizeHumanMetadata(this.deps, input);
  }

  /**
   * Internal-only target for the fixed Stripe read adapter. This decrypts no
   * response body and returns no credential. Route authorization must already
   * have established a current owner/admin dashboard session.
   */
  readStripeReconciliationTarget(
    input: Parameters<typeof reconciliation.readStripeReconciliationTarget>[1],
  ) {
    return reconciliation.readStripeReconciliationTarget(this.deps, input);
  }

  /** Provider facts are already reduced to commitments before this call. */
  recordGovernedReconciliation(input: {
    operatorId: string;
    operationKey: string;
    state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
    resourceHash?: string;
    evidenceHash: string;
    providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
    late?: boolean;
    transaction: ProxyOperationTransaction;
  }) {
    return this.repository.recordReconciliationByGovernance({
      operatorId: input.operatorId,
      operationKeyHash: sha256(input.operationKey),
      state: input.state,
      resourceHash: input.resourceHash,
      evidenceHash: input.evidenceHash,
      providerStatus: input.providerStatus,
      late: input.late,
    }, input.transaction);
  }

  authorizeReplacement(input: {
    operatorId: string;
    originalOperationKey: string;
    replacementOperationKey: string;
    acknowledgedWarningHash: string;
    humanAuthor: { kind: 'operator_owner'; operatorId: string } | { kind: 'team_member'; memberId: string };
    dashboardSessionFamilyId: string;
    dashboardSessionTokenId: string;
    transaction: ProxyOperationTransaction;
    now?: Date;
  }) {
    if (!ProxyOperationId.safeParse(input.originalOperationKey).success
      || !ProxyOperationId.safeParse(input.replacementOperationKey).success
      || input.originalOperationKey === input.replacementOperationKey
      || input.acknowledgedWarningHash !== PROXY_REPLACEMENT_WARNING_HASH
      || !input.dashboardSessionFamilyId
      || !input.dashboardSessionTokenId) {
      return Promise.resolve({ state: 'unavailable' as const });
    }
    return this.repository.createReplacementAcknowledgement({
      id: `pra_${randomUUID()}`,
      operatorId: input.operatorId,
      originalOperationKeyHash: sha256(input.originalOperationKey),
      replacementOperationKeyHash: sha256(input.replacementOperationKey),
      warningVersion: PROXY_REPLACEMENT_WARNING_VERSION,
      warningText: PROXY_REPLACEMENT_WARNING,
      warningHash: PROXY_REPLACEMENT_WARNING_HASH,
      humanAuthorKind: input.humanAuthor.kind,
      humanAuthorId: input.humanAuthor.kind === 'operator_owner'
        ? input.humanAuthor.operatorId
        : input.humanAuthor.memberId,
      dashboardSessionFamilyId: input.dashboardSessionFamilyId,
      dashboardSessionTokenHash: sha256(input.dashboardSessionTokenId),
      acknowledgedAt: input.now,
    }, input.transaction);
  }

  guardAndConsumeReplacement(input: {
    operatorId: string;
    replacementOperationId: string;
    replacementOperationKey: string;
    replacementRequestHash: string;
    effectCorrelationHash: string;
    transaction: ProxyOperationTransaction;
  }) {
    return this.repository.guardAndConsumeReplacement({
      operatorId: input.operatorId,
      replacementOperationId: input.replacementOperationId,
      replacementOperationKeyHash: sha256(input.replacementOperationKey),
      replacementRequestHash: input.replacementRequestHash,
      effectCorrelationHash: input.effectCorrelationHash,
    }, input.transaction);
  }

  /** Called by dispatch only after the replacement operation exists in the same transaction. */
  consumeReplacementAcknowledgement(input: {
    operatorId: string;
    replacementOperationKey: string;
    replacementRequestHash: string;
    replacementOperationId: string;
    transaction: ProxyOperationTransaction;
  }) {
    return this.repository.consumeReplacementAcknowledgement({
      operatorId: input.operatorId,
      replacementOperationKeyHash: sha256(input.replacementOperationKey),
      replacementRequestHash: input.replacementRequestHash,
      replacementOperationId: input.replacementOperationId,
    }, input.transaction);
  }

  authorizeRead(input: Parameters<typeof replay.authorizeRead>[1]) {
    return replay.authorizeRead(this.deps, input);
  }

  decryptPreparedRequest(input: Parameters<typeof dispatch.decryptPreparedRequest>[1]) {
    return dispatch.decryptPreparedRequest(this.deps, input);
  }

}
