// ProxyOperationRepository.
//
// The delivery ledger for proxied write calls: one row per operator and operation key, a fenced
// dispatch owner, the stored (encrypted) response, provider reconciliation evidence, the post-
// response work queue and the accounting receipts. The class holds the database handle and
// delegates each method to the module that owns it under `./proxy-operation/`:
//
//   - lookups.ts         reads by operation key and id, and the human-visible lookup
//   - admission.ts       insert an admitted operation, claim dispatch and Stripe retry
//   - responses.ts       screening, stored response, unknown outcome
//   - post-response.ts   the post-response work queue
//   - reconciliation.ts  provider reconciliation and late-response evidence
//   - replacement.ts     one-shot replacement acknowledgements
//   - accounting.ts      accounting receipts and projections
//   - maintenance.ts     replay expiry and payload erasure
//   - internals.ts       operator and row locks, fencing predicate, attempt rows
//   - types.ts           row, result and input types and the capacity limits

import type { Database } from '@stack/shared';
import * as accounting from './proxy-operation/accounting.js';
import * as admission from './proxy-operation/admission.js';
import * as lookups from './proxy-operation/lookups.js';
import * as maintenance from './proxy-operation/maintenance.js';
import * as postResponse from './proxy-operation/post-response.js';
import * as reconciliation from './proxy-operation/reconciliation.js';
import * as replacement from './proxy-operation/replacement.js';
import * as responses from './proxy-operation/responses.js';
import type { ProxyOperationTransaction } from './proxy-operation/types.js';

export {
  PROXY_NONTERMINAL_LIMIT,
  PROXY_REPLAY_CAPACITY_BYTES,
  type DispatchClaimResult,
  type FencedDispatch,
  type InsertAdmittedResult,
  type ProxyAccountingProjection,
  type ProxyAccountingReceipt,
  type ProxyOperationInsert,
  type ProxyOperationReplacementAcknowledgement,
  type ProxyOperationRow,
  type ProxyOperationTransaction,
  type ProxyPostResponseStep,
} from './proxy-operation/types.js';

/** The arguments of a module function after its leading database handle. */
type AfterHandle<F> = F extends (handle: Database, ...args: infer A) => unknown ? A : never;

export class ProxyOperationRepository {
  constructor(private db: Database) {}

  transaction<T>(work: (tx: ProxyOperationTransaction) => Promise<T>): Promise<T> {
    return this.db.transaction(work);
  }

  findByOperationKey(...args: AfterHandle<typeof lookups.findByOperationKey>) {
    return lookups.findByOperationKey(this.db, ...args);
  }

  findById(...args: AfterHandle<typeof lookups.findById>) {
    return lookups.findById(this.db, ...args);
  }

  originalPassportAllowsReplay(...args: AfterHandle<typeof lookups.originalPassportAllowsReplay>) {
    return lookups.originalPassportAllowsReplay(this.db, ...args);
  }

  /** Current human visibility is an active originating agent plus the member's connection ceiling. */
  findVisibleByOperationKey(...args: AfterHandle<typeof lookups.findVisibleByOperationKey>) {
    return lookups.findVisibleByOperationKey(this.db, ...args);
  }

  insertAdmitted(...args: AfterHandle<typeof admission.insertAdmitted>) {
    return admission.insertAdmitted(this.db, ...args);
  }

  /** Count one evaluated logical action exactly once under an operator lock. */
  recordAccountingReceipt(...args: AfterHandle<typeof accounting.recordAccountingReceipt>) {
    return accounting.recordAccountingReceipt(this.db, ...args);
  }

  /** Promote the once-only denial receipt when the same evaluation reaches dispatch. */
  promoteAccountingReceiptToAdmitted(
    ...args: Parameters<typeof accounting.promoteAccountingReceiptToAdmitted>
  ) {
    return accounting.promoteAccountingReceiptToAdmitted(...args);
  }

  /** Commit every still-pending fractional receipt represented by one whole-cent debit. */
  commitAccountingThroughSequence(
    ...args: AfterHandle<typeof accounting.commitAccountingThroughSequence>
  ) {
    return accounting.commitAccountingThroughSequence(this.db, ...args);
  }

  listPendingAccountingReceipts(...args: AfterHandle<typeof accounting.listPendingAccountingReceipts>) {
    return accounting.listPendingAccountingReceipts(this.db, ...args);
  }

  getAccountingProjection(...args: AfterHandle<typeof accounting.getAccountingProjection>) {
    return accounting.getAccountingProjection(this.db, ...args);
  }

  listAccountingProjectionKeys(...args: AfterHandle<typeof accounting.listAccountingProjectionKeys>) {
    return accounting.listAccountingProjectionKeys(this.db, ...args);
  }

  claimDispatch(...args: AfterHandle<typeof admission.claimDispatch>) {
    return admission.claimDispatch(this.db, ...args);
  }

  /**
   * Stripe-only retry using the original native idempotency key when STACK has
   * no replay payload. Pending, not-found and confirmed provider evidence can
   * all be recovered safely; contradictory or expired evidence stays closed.
   */
  claimStripeRetry(...args: AfterHandle<typeof admission.claimStripeRetry>) {
    return admission.claimStripeRetry(this.db, ...args);
  }

  markResponseScreening(...args: AfterHandle<typeof responses.markResponseScreening>) {
    return responses.markResponseScreening(this.db, ...args);
  }

  storeResponse(...args: AfterHandle<typeof responses.storeResponse>) {
    return responses.storeResponse(this.db, ...args);
  }

  markUnresolvedDue(...args: AfterHandle<typeof responses.markUnresolvedDue>) {
    return responses.markUnresolvedDue(this.db, ...args);
  }

  recordLateResponseEvidence(...args: AfterHandle<typeof reconciliation.recordLateResponseEvidence>) {
    return reconciliation.recordLateResponseEvidence(this.db, ...args);
  }

  claimPostResponseWork(...args: AfterHandle<typeof postResponse.claimPostResponseWork>) {
    return postResponse.claimPostResponseWork(this.db, ...args);
  }

  listQueuedPostResponseContexts(...args: AfterHandle<typeof postResponse.listQueuedPostResponseContexts>) {
    return postResponse.listQueuedPostResponseContexts(this.db, ...args);
  }

  replacePostResponseContext(...args: AfterHandle<typeof postResponse.replacePostResponseContext>) {
    return postResponse.replacePostResponseContext(this.db, ...args);
  }

  markPostResponseStep(...args: AfterHandle<typeof postResponse.markPostResponseStep>) {
    return postResponse.markPostResponseStep(this.db, ...args);
  }

  releasePostResponseWork(...args: AfterHandle<typeof postResponse.releasePostResponseWork>) {
    return postResponse.releasePostResponseWork(this.db, ...args);
  }

  markOutcomeUnknown(...args: AfterHandle<typeof responses.markOutcomeUnknown>) {
    return responses.markOutcomeUnknown(this.db, ...args);
  }

  /**
   * A dead dispatch owner never hands a generic write to a new owner. Expiry
   * only makes the uncertainty visible; the original fenced owner may still
   * record a late response or contradictory provider evidence.
   */
  markExpiredDispatchesUnknown(...args: AfterHandle<typeof responses.markExpiredDispatchesUnknown>) {
    return responses.markExpiredDispatchesUnknown(this.db, ...args);
  }

  recordReconciliation(...args: AfterHandle<typeof reconciliation.recordReconciliation>) {
    return reconciliation.recordReconciliation(this.db, ...args);
  }

  /** The operation key selects and locks the row; the browser never supplies a fence or DB id. */
  recordReconciliationByGovernance(
    ...args: Parameters<typeof reconciliation.recordReconciliationByGovernance>
  ) {
    return reconciliation.recordReconciliationByGovernance(...args);
  }

  createReplacementAcknowledgement(
    ...args: Parameters<typeof replacement.createReplacementAcknowledgement>
  ) {
    return replacement.createReplacementAcknowledgement(...args);
  }

  /**
   * A fresh handle may not silently repeat an unresolved external effect. The
   * matching prior row and the one-shot human acknowledgement are locked and
   * checked in the same transaction that will claim the replacement dispatch.
   */
  guardAndConsumeReplacement(...args: Parameters<typeof replacement.guardAndConsumeReplacement>) {
    return replacement.guardAndConsumeReplacement(...args);
  }

  /** Consume only the exact request the human saw, in the replacement dispatch transaction. */
  consumeReplacementAcknowledgement(
    ...args: Parameters<typeof replacement.consumeReplacementAcknowledgement>
  ) {
    return replacement.consumeReplacementAcknowledgement(...args);
  }

  releaseBeforeDispatch(...args: AfterHandle<typeof admission.releaseBeforeDispatch>) {
    return admission.releaseBeforeDispatch(this.db, ...args);
  }

  expireReplay(...args: AfterHandle<typeof maintenance.expireReplay>) {
    return maintenance.expireReplay(this.db, ...args);
  }

  erasePayloads(...args: AfterHandle<typeof maintenance.erasePayloads>) {
    return maintenance.erasePayloads(this.db, ...args);
  }
}
