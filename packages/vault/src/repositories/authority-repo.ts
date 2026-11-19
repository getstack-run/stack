import type { AuthorityReference, Database, authorityProfileVersions } from '@stack/shared';
import type {
  AuthorityBindingProofRecord,
  AuthorityBindingRecord,
  AuthorityDbTransaction,
  AuthorityErasureTarget,
  AuthorityPresentationRecord,
  AuthorityProofRecord,
  AuthorityProofStatus,
  AuthorityReceiverKeyRecord,
  AuthorityReceiverRecord,
  AuthorityRuntimeBoundary,
  AuthorityUseInsert,
  AuthorityUseRecord,
  AuthorityPrincipalRecord,
  ReceiverTransactionReceiptRecord,
} from '../services/authority/records.js';
import type { AuthorityRepositoryPort } from '../services/authority/port.js';
import type { AuthorityProofCollectionWorkflowRecord } from '../services/authority/contracts.js';
import type { ResolvedAuthorityApprovalDecision } from '../services/authority/approval-verifier.js';
import { AuthorityApprovalRepository } from './authority/approvals.js';
import { AuthorityBindingRepository } from './authority/bindings.js';
import type { AuthorityRepoContext } from './authority/context.js';
import { AuthorityErasureRepository } from './authority/erasure.js';
import { AuthorityLedgerRepository } from './authority/ledger.js';
import { AuthorityPassportRefRepository } from './authority/passport-refs.js';
import { AuthorityPresentationRepository } from './authority/presentations.js';
import { AuthorityPrincipalRepository } from './authority/principals.js';
import { AuthorityProfileVersionRepository } from './authority/profile-versions.js';
import { AuthorityProofCollectionRepository } from './authority/proof-collection.js';
import { AuthorityProofRepository } from './authority/proofs.js';
import { AuthorityReceiptRepository } from './authority/receipts.js';
import { AuthorityReceiverRepository } from './authority/receivers.js';
import type { ReceiverDirectory } from './authority/context.js';
import { AuthorityRevocationRepository } from './authority/revocation.js';
import { AuthorityUseRepository } from './authority/uses.js';

/**
 * The authority repository: a thin composition of per-aggregate modules in
 * `./authority/`. Every module reads the same `AuthorityRepoContext`, so a
 * repository created inside a transaction (`atomic`, `idempotent`) uses that
 * transaction for every aggregate. All SQL lives in the modules.
 */
export class AuthorityRepository implements AuthorityRepositoryPort {
  private readonly principals: AuthorityPrincipalRepository;
  private readonly proofs: AuthorityProofRepository;
  private readonly proofCollection: AuthorityProofCollectionRepository;
  private readonly ledger: AuthorityLedgerRepository;
  private readonly receivers: AuthorityReceiverRepository;
  private readonly profileVersions: AuthorityProfileVersionRepository;
  private readonly bindings: AuthorityBindingRepository;
  private readonly revocation: AuthorityRevocationRepository;
  private readonly approvals: AuthorityApprovalRepository;
  private readonly uses: AuthorityUseRepository;
  private readonly presentations: AuthorityPresentationRepository;
  private readonly receipts: AuthorityReceiptRepository;
  private readonly passportRefs: AuthorityPassportRefRepository;
  private readonly erasure: AuthorityErasureRepository;

  constructor(
    private db: Database,
    private readonly transaction?: AuthorityDbTransaction,
    private readonly receiverDirectories: readonly ReceiverDirectory[] = [],
  ) {
    const ctx: AuthorityRepoContext = {
      db,
      transaction,
      receiverDirectories,
      repo: this,
      atomic: (mutation) => this.atomic(mutation),
      forTransaction: (tx) => new AuthorityRepository(tx as unknown as Database, tx, receiverDirectories),
    };
    this.principals = new AuthorityPrincipalRepository(ctx);
    this.proofs = new AuthorityProofRepository(ctx);
    this.proofCollection = new AuthorityProofCollectionRepository(ctx);
    this.ledger = new AuthorityLedgerRepository(ctx);
    this.receivers = new AuthorityReceiverRepository(ctx);
    this.profileVersions = new AuthorityProfileVersionRepository(ctx);
    this.bindings = new AuthorityBindingRepository(ctx);
    this.revocation = new AuthorityRevocationRepository(ctx);
    this.approvals = new AuthorityApprovalRepository(ctx);
    this.uses = new AuthorityUseRepository(ctx);
    this.presentations = new AuthorityPresentationRepository(ctx);
    this.receipts = new AuthorityReceiptRepository(ctx);
    this.passportRefs = new AuthorityPassportRefRepository(ctx);
    this.erasure = new AuthorityErasureRepository(ctx);
  }

  // Transactions

  currentTransaction(): AuthorityDbTransaction | undefined {
    return this.transaction;
  }

  async atomic<T>(mutation: (repo: AuthorityRepositoryPort) => Promise<T>): Promise<T> {
    if (this.transaction) return mutation(this);
    return this.db.transaction(async (tx) => mutation(new AuthorityRepository(tx as unknown as Database, tx, this.receiverDirectories)));
  }

  idempotent<T>(input: Parameters<AuthorityLedgerRepository['idempotent']>[0],
    mutation: (repo: AuthorityRepositoryPort) => Promise<T>): Promise<T> {
    return this.ledger.idempotent(input, mutation);
  }

  consumeReceiverJti(input: Parameters<AuthorityLedgerRepository['consumeReceiverJti']>[0]) {
    return this.ledger.consumeReceiverJti(input);
  }

  consumeAuthorityJti(input: Parameters<AuthorityLedgerRepository['consumeAuthorityJti']>[0]) {
    return this.ledger.consumeAuthorityJti(input);
  }

  // Principals and account listings

  insertPrincipal(row: AuthorityPrincipalRecord) {
    return this.principals.insertPrincipal(row);
  }

  listPrincipals(operatorId: string) {
    return this.principals.listPrincipals(operatorId);
  }

  listAccountRecords(operatorId: string, kind: 'principals' | 'proofs' | 'receivers', page: number, limit: number) {
    return this.principals.listAccountRecords(operatorId, kind, page, limit);
  }

  findPrincipal(operatorId: string, principalId: string) {
    return this.principals.findPrincipal(operatorId, principalId);
  }

  archivePrincipal(operatorId: string, principalId: string, reason: string, now: Date) {
    return this.principals.archivePrincipal(operatorId, principalId, reason, now);
  }

  // Erasure

  lockErasureGraph(input: Parameters<AuthorityErasureRepository['lockErasureGraph']>[0]): Promise<AuthorityErasureTarget[] | null> {
    return this.erasure.lockErasureGraph(input);
  }

  applyErasureGraph(input: Parameters<AuthorityErasureRepository['applyErasureGraph']>[0]): Promise<{ passportJtis: string[] }> {
    return this.erasure.applyErasureGraph(input);
  }

  // Proofs and the proof-collection workflow

  insertProof(row: AuthorityProofRecord) {
    return this.proofs.insertProof(row);
  }

  findLegacyIdentityClaim(operatorId: string, claimId: string) {
    return this.proofs.findLegacyIdentityClaim(operatorId, claimId);
  }

  findLegacyProofFacade(operatorId: string, legacyClaimId: string, subjectPrincipalId: string, profileVersionId: string) {
    return this.proofs.findLegacyProofFacade(operatorId, legacyClaimId, subjectPrincipalId, profileVersionId);
  }

  listLegacyProofFacades(operatorId: string, legacyClaimId: string) {
    return this.proofs.listLegacyProofFacades(operatorId, legacyClaimId);
  }

  listProofs(operatorId: string) {
    return this.proofs.listProofs(operatorId);
  }

  findProof(operatorId: string, proofId: string, version?: number) {
    return this.proofs.findProof(operatorId, proofId, version);
  }

  listProofSources(operatorId: string, proofId: string, version: number) {
    return this.proofs.listProofSources(operatorId, proofId, version);
  }

  transitionProof(input: {
    operatorId: string; proofId: string; from: AuthorityProofStatus[]; to: AuthorityProofStatus;
    now: Date; reason?: string; erase?: { tombstoneHash: string; tombstoneClaimId: string };
  }) {
    return this.proofs.transitionProof(input);
  }

  reserveProofCollectionWorkflow(input: Parameters<AuthorityProofCollectionRepository['reserveProofCollectionWorkflow']>[0]) {
    return this.proofCollection.reserveProofCollectionWorkflow(input);
  }

  findProofCollectionWorkflow(sessionId: string, operatorId?: string) {
    return this.proofCollection.findProofCollectionWorkflow(sessionId, operatorId);
  }

  acquireProofCollectionWorkflowLease(input: {
    operatorId: string; sessionId: string; from: Array<AuthorityProofCollectionWorkflowRecord['workflow_phase']>;
    to: 'initiating' | 'callback_verifying'; leaseTokenHash: string; leaseExpiresAt: Date; now: Date;
  }) {
    return this.proofCollection.acquireProofCollectionWorkflowLease(input);
  }

  transitionProofCollectionWorkflow(input: Parameters<AuthorityProofCollectionRepository['transitionProofCollectionWorkflow']>[0]) {
    return this.proofCollection.transitionProofCollectionWorkflow(input);
  }

  // Receivers, receiver keys and verification challenges

  findReceiver(operatorId: string, receiverId: string) {
    return this.receivers.findReceiver(operatorId, receiverId);
  }

  findReceiverById(receiverId: string) {
    return this.receivers.findReceiverById(receiverId);
  }

  findReceiverByCanonicalId(identifier: string) {
    return this.receivers.findReceiverByCanonicalId(identifier);
  }

  findNativeReceiversByCanonicalId(identifier: string) {
    return this.receivers.findNativeReceiversByCanonicalId(identifier);
  }

  findManagedReceiverByCanonicalId(operatorId: string, identifier: string) {
    return this.receivers.findManagedReceiverByCanonicalId(operatorId, identifier);
  }

  isOwnedActiveServiceConnection(operatorId: string, connectionId: string) {
    return this.receivers.isOwnedActiveServiceConnection(operatorId, connectionId);
  }

  findReceiverKey(receiverId: string, keyId: string, use: AuthorityReceiverKeyRecord['use']) {
    return this.receivers.findReceiverKey(receiverId, keyId, use);
  }

  resolveRuntimeReceivers(operatorId: string, boundary: AuthorityRuntimeBoundary) {
    return this.receivers.resolveRuntimeReceivers(operatorId, boundary);
  }

  isOwnedInternalReceiver(operatorId: string, identifier: string): Promise<boolean> {
    return this.receivers.isOwnedInternalReceiver(operatorId, identifier);
  }

  insertReceiver(row: AuthorityReceiverRecord & {
    canonical_identifier: string; display_name: string; proxy_service_connection_id: string | null; created_at: Date;
  }) {
    return this.receivers.insertReceiver(row);
  }

  listReceivers(operatorId: string) {
    return this.receivers.listReceivers(operatorId);
  }

  createReceiverVerificationChallenge(input: Parameters<AuthorityReceiverRepository['createReceiverVerificationChallenge']>[0]) {
    return this.receivers.createReceiverVerificationChallenge(input);
  }

  consumeReceiverVerificationChallenge(input: Parameters<AuthorityReceiverRepository['consumeReceiverVerificationChallenge']>[0]) {
    return this.receivers.consumeReceiverVerificationChallenge(input);
  }

  markReceiverVerified(operatorId: string, receiverId: string, now: Date) {
    return this.receivers.markReceiverVerified(operatorId, receiverId, now);
  }

  insertReceiverKey(row: AuthorityReceiverKeyRecord & { created_at: Date; revoked_at: Date | null }) {
    return this.receivers.insertReceiverKey(row);
  }

  listReceiverKeys(receiverId: string, use?: AuthorityReceiverKeyRecord['use']) {
    return this.receivers.listReceiverKeys(receiverId, use);
  }

  revokeReceiverKey(operatorId: string, receiverId: string, keyId: string, reason: string, now: Date) {
    return this.receivers.revokeReceiverKey(operatorId, receiverId, keyId, reason, now);
  }

  // Profile versions

  findProofProfileVersion(operatorId: string, id: string) {
    return this.profileVersions.findProofProfileVersion(operatorId, id);
  }

  findReceiverProfile(operatorId: string, profileId: string) {
    return this.profileVersions.findReceiverProfile(operatorId, profileId);
  }

  insertProfileVersion(row: typeof authorityProfileVersions.$inferInsert) {
    return this.profileVersions.insertProfileVersion(row);
  }

  findProfileVersion(operatorId: string, kind: 'proof' | 'domain' | 'receiver', id: string) {
    return this.profileVersions.findProfileVersion(operatorId, kind, id);
  }

  activateProfileVersion(operatorId: string, kind: 'proof' | 'domain' | 'receiver', id: string, now: Date) {
    return this.profileVersions.activateProfileVersion(operatorId, kind, id, now);
  }

  // Bindings and their agent, mission and Passport checks

  lockBindingGraphForDisclosure(operatorId: string, bindingId: string, bindingVersion: number): Promise<void> {
    return this.bindings.lockBindingGraphForDisclosure(operatorId, bindingId, bindingVersion);
  }

  listAccountRecordBindings(operatorId: string, kind: 'principals' | 'proofs' | 'receivers', recordId: string,
    version: number | undefined, page: number, limit: number) {
    return this.bindings.listAccountRecordBindings(operatorId, kind, recordId, version, page, limit);
  }

  resolveCurrentAgentKey(operatorId: string, agentId: string) {
    return this.bindings.resolveCurrentAgentKey(operatorId, agentId);
  }

  isMissionActive(operatorId: string, missionId: string) {
    return this.bindings.isMissionActive(operatorId, missionId);
  }

  insertBinding(row: AuthorityBindingRecord, proofs: AuthorityBindingProofRecord[]) {
    return this.bindings.insertBinding(row, proofs);
  }

  listBindings(operatorId: string) {
    return this.bindings.listBindings(operatorId);
  }

  listAgentBindings(operatorId: string, agentId: string, page: number, limit: number,
    binding?: { id: string; version: number }) {
    return this.bindings.listAgentBindings(operatorId, agentId, page, limit, binding);
  }

  findBinding(operatorId: string, bindingId: string, version?: number) {
    return this.bindings.findBinding(operatorId, bindingId, version);
  }

  listBindingProofs(operatorId: string, bindingId: string, version: number) {
    return this.bindings.listBindingProofs(operatorId, bindingId, version);
  }

  activateBinding(input: Parameters<AuthorityBindingRepository['activateBinding']>[0]) {
    return this.bindings.activateBinding(input);
  }

  isBindingInAgentChain(operatorId: string, bindingId: string, version: number, agentId: string) {
    return this.bindings.isBindingInAgentChain(operatorId, bindingId, version, agentId);
  }

  isPassportAuthorizedForBinding(input: Parameters<AuthorityBindingRepository['isPassportAuthorizedForBinding']>[0]) {
    return this.bindings.isPassportAuthorizedForBinding(input);
  }

  // Revocation cascades

  cascadeProofInvalidation(operatorId: string, proofId: string, now: Date, reason: string) {
    return this.revocation.cascadeProofInvalidation(operatorId, proofId, now, reason);
  }

  revokeBindingCascade(operatorId: string, bindingId: string, now: Date, reason: string) {
    return this.revocation.revokeBindingCascade(operatorId, bindingId, now, reason);
  }

  // Approvals

  hasUnsatisfiedApprovals(operatorId: string, bindingId: string, version: number, requestHash?: string) {
    return this.approvals.hasUnsatisfiedApprovals(operatorId, bindingId, version, requestHash);
  }

  consumeSatisfiedApprovals(input: Parameters<AuthorityApprovalRepository['consumeSatisfiedApprovals']>[0]) {
    return this.approvals.consumeSatisfiedApprovals(input);
  }

  ensureApprovalRequest(input: Parameters<AuthorityApprovalRepository['ensureApprovalRequest']>[0]) {
    return this.approvals.ensureApprovalRequest(input);
  }

  listApprovalRequests(operatorId: string, bindingId: string) {
    return this.approvals.listApprovalRequests(operatorId, bindingId);
  }

  listApprovalVerifierCandidates(operatorId: string, requestId: string, now: Date) {
    return this.approvals.listApprovalVerifierCandidates(operatorId, requestId, now);
  }

  validateApprovalDecision(input: {
    operatorId: string; requestId: string; authenticatedAuthor: unknown;
    decision: { request_id: string; decision: 'approve' | 'reject'; request_hash: string; signed_decision: string };
    resolved: ResolvedAuthorityApprovalDecision; now: Date;
  }) {
    return this.approvals.validateApprovalDecision(input);
  }

  listSatisfiedApprovalClaimRefs(input: Parameters<AuthorityApprovalRepository['listSatisfiedApprovalClaimRefs']>[0]) {
    return this.approvals.listSatisfiedApprovalClaimRefs(input);
  }

  decideApproval(input: {
    operatorId: string; requestId: string; authenticatedAuthor: unknown;
    decision: { request_id: string; decision: 'approve' | 'reject'; request_hash: string; signed_decision: string };
    resolved: ResolvedAuthorityApprovalDecision; decisionId: string; now: Date;
  }) {
    return this.approvals.decideApproval(input);
  }

  // Authority uses

  insertAuthorityUse(input: AuthorityUseInsert) {
    return this.uses.insertAuthorityUse(input);
  }

  findAuthorityUseByRuntimeRequest(operatorId: string, receiverId: string, receiverRequestId: string) {
    return this.uses.findAuthorityUseByRuntimeRequest(operatorId, receiverId, receiverRequestId);
  }

  authorizeWaitingAuthorityUse(operatorId: string, useId: string, now: Date) {
    return this.uses.authorizeWaitingAuthorityUse(operatorId, useId, now);
  }

  setAuthorityUseProofStrength(input: {
    operatorId: string;
    useId: string;
    from: AuthorityUseRecord['proof_strength'];
    to: AuthorityUseRecord['proof_strength'];
  }) {
    return this.uses.setAuthorityUseProofStrength(input);
  }

  markAuthorityUseDispatched(operatorId: string, useId: string, now: Date) {
    return this.uses.markAuthorityUseDispatched(operatorId, useId, now);
  }

  claimAuthorityUseDispatched(operatorId: string, useId: string, now: Date, transaction?: AuthorityDbTransaction) {
    return this.uses.claimAuthorityUseDispatched(operatorId, useId, now, transaction);
  }

  completeAuthorityUse(input: Parameters<AuthorityUseRepository['completeAuthorityUse']>[0]) {
    return this.uses.completeAuthorityUse(input);
  }

  findAuthorityUseById(receiverId: string, useId: string) {
    return this.uses.findAuthorityUseById(receiverId, useId);
  }

  findAuthorityUseForPresentation(receiverId: string, receiverRequestId: string, requestHash: string) {
    return this.uses.findAuthorityUseForPresentation(receiverId, receiverRequestId, requestHash);
  }

  listAuthorityUses(operatorId: string) {
    return this.uses.listAuthorityUses(operatorId);
  }

  listAgentAuthorityUses(operatorId: string, agentId: string, page: number, limit: number,
    binding?: { id: string; version: number }) {
    return this.uses.listAgentAuthorityUses(operatorId, agentId, page, limit, binding);
  }

  findAuthorityUseForOperator(operatorId: string, useId: string) {
    return this.uses.findAuthorityUseForOperator(operatorId, useId);
  }

  // Presentations and receipts

  insertPresentation(row: AuthorityPresentationRecord) {
    return this.presentations.insertPresentation(row);
  }

  findPresentation(receiverId: string, presentationId: string) {
    return this.presentations.findPresentation(receiverId, presentationId);
  }

  listPresentationsForOperator(operatorId: string) {
    return this.presentations.listPresentationsForOperator(operatorId);
  }

  findPresentationForOperator(operatorId: string, presentationId: string) {
    return this.presentations.findPresentationForOperator(operatorId, presentationId);
  }

  updatePresentation(input: Parameters<AuthorityPresentationRepository['updatePresentation']>[0]) {
    return this.presentations.updatePresentation(input);
  }

  lockReceiptAuthorityGraph(receiverId: string, presentationId: string, now: Date) {
    return this.receipts.lockReceiptAuthorityGraph(receiverId, presentationId, now);
  }

  lockPresentationAndUseForReceipt(receiverId: string, presentationId: string) {
    return this.receipts.lockPresentationAndUseForReceipt(receiverId, presentationId);
  }

  insertReceiverReceipt(row: ReceiverTransactionReceiptRecord) {
    return this.receipts.insertReceiverReceipt(row);
  }

  findReceiverReceiptByPresentation(receiverId: string, presentationId: string) {
    return this.receipts.findReceiverReceiptByPresentation(receiverId, presentationId);
  }

  // Passport references

  linkPassportRefs(input: { operatorId: string; passportJti: string; refs: AuthorityReference[] }, transaction?: AuthorityDbTransaction) {
    return this.passportRefs.linkPassportRefs(input, transaction);
  }

  listPassportRefs(operatorId: string, passportJti: string) {
    return this.passportRefs.listPassportRefs(operatorId, passportJti);
  }

  listPassportRefsForPassports(operatorId: string, passportJtis: string[]) {
    return this.passportRefs.listPassportRefsForPassports(operatorId, passportJtis);
  }
}
