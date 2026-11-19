import type {
  AddAuthorityReceiverKeyInput,
  AttachAuthorityProofInput,
  AuthorityApprovalDecisionInput,
  AuthorityProofCallbackInput,
  AuthorityStatusCheckInput,
  CreateAuthorityApprovalRequestsInput,
  CreateAuthorityBindingInput,
  CreateAuthorityPrincipalInput,
  CreateAuthorityProfileVersionInput,
  CreateAuthorityProofCollectionSessionInput,
  CreateAuthorityReceiverInput,
  DelegateAuthorityBindingInput,
  HumanOperatorAuthor,
  ReceiverChallengeInput,
  ReceiverReceiptInput,
} from '@stack/shared';
import type {
  AuthorityDbTransaction,
  AuthorityEvaluationInput,
  AuthorityMutationActor,
  AuthorityReceiverAuthContext,
} from './authority/records.js';
import type {
  AuthorityProofCallbackAuthContext,
  AuthorityServiceDeps,
  CreateLegacyIdentityProofFacadeInput,
} from './authority/contracts.js';
import type { BrowserDecisionSession } from './browser-decision-session.js';
import type { AuthorityModules } from './authority/modules.js';
import { createAuthorityModules } from './authority/modules.js';

export {
  AuthorityApprovalCeremonyRejectedError,
  PinnedAuthorityApprovalDecisionVerifier,
} from './authority/approval-verifier.js';
export type {
  ResolvedAuthorityApprovalDecision,
  AuthorityApprovalVerifierCandidate,
} from './authority/approval-verifier.js';
export type {
  VerifiedAuthorityProof,
  AuthorityProofAdapter,
  CreateLegacyIdentityProofFacadeInput,
  AuthorityProofCollectionWorkflowRecord,
  LegacyIdentityClaimReference,
  AuthorityProofCallbackAuthContext,
  AuthorityClaimIssuer,
  AuthorityServiceDeps,
} from './authority/contracts.js';
export { authorityAgentKeyThumbprint } from './authority/digest.js';
export { authorityMandateTermsDigest } from './authority/mandate-terms.js';
export type { AuthorityRepositoryPort } from './authority/port.js';
export type {
  AuthorityPresentationSigner,
  AuthorityPresentationTransport,
  AuthorityPresentationProtocol,
} from './authority/presentation-protocol.js';
export {
  STACK_DIRECT_POST_PROTOCOL_KEY,
  STACK_DIRECT_POST_PROTOCOL_VERSION,
  STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
  STACK_DIRECT_POST_DELIVERY_MODE,
  STACK_PROXY_BRIDGE_PROTOCOL_KEY,
  STACK_PROXY_BRIDGE_PROTOCOL_VERSION,
} from './authority/profile-validators.js';
export type {
  AuthorityProofStatus,
  AuthorityBindingStatus,
  AuthorityDbTransaction,
  AuthorityPrincipalRecord,
  AuthorityProofProfileVersionRecord,
  AuthorityReceiverRecord,
  AuthorityReceiverProfileRecord,
  AuthorityProofRecord,
  AuthorityBindingRecord,
  AuthorityErasureTargetKind,
  AuthorityErasureTarget,
  AuthorityErasureTombstone,
  AuthorityBindingProofRecord,
  AuthorityReceiverKeyRecord,
  AuthorityApprovalClaimContext,
  AuthorityApprovalRequestRecord,
  AuthorityEvaluationInput,
  AuthorityRuntimeBoundary,
  AuthorityMutationActor,
  AuthorityEvaluationResult,
  AuthorityUseInsert,
  AuthorityUseRecord,
  AuthorityReceiverAuthContext,
  ReceiverTransactionReceiptView,
  AuthorityPresentationRecord,
  AuthorityPresentationPatch,
  ReceiverTransactionReceiptRecord,
} from './authority/records.js';
export { StackDirectPostJwtV1Protocol } from './authority/stack-direct-post-protocol.js';
export {
  AUTHORITY_CLOCK_TOLERANCE_SECONDS,
  AUTHORITY_ASSERTION_MAX_SECONDS,
  AUTHORITY_PRESENTATION_MAX_SECONDS,
  AUTHORITY_RECEIPT_MAX_SECONDS,
  AUTHORITY_VERIFICATION_CHALLENGE_SECONDS,
} from './authority/receiver-validation.js';

/**
 * Authority service facade. Each concern lives in its own module under
 * ./authority/; this class composes them and keeps the public surface that
 * routes, workers and other services import.
 */
export class AuthorityService {
  private readonly modules: AuthorityModules;

  constructor(deps: AuthorityServiceDeps) {
    this.modules = createAuthorityModules(deps);
  }

  async createPrincipal(
    operatorId: string,
    input: CreateAuthorityPrincipalInput,
    idempotencyKey: string,
  ) {
    return this.modules.principals.createPrincipal(operatorId, input, idempotencyKey);
  }

  async resolveAgentKeyThumbprint(operatorId: string, agentId: string) {
    return this.modules.principals.resolveAgentKeyThumbprint(operatorId, agentId);
  }

  async listPrincipals(operatorId: string) {
    return this.modules.principals.listPrincipals(operatorId);
  }

  async listAccountRecords(
    operatorId: string,
    kind: 'principals' | 'proofs' | 'receivers',
    page: number,
    limit: number,
    related?: Parameters<AuthorityModules['principals']['listAccountRecords']>[4],
  ) {
    return this.modules.principals.listAccountRecords(operatorId, kind, page, limit, related);
  }

  async getPrincipal(operatorId: string, principalId: string) {
    return this.modules.principals.getPrincipal(operatorId, principalId);
  }

  async archivePrincipal(
    operatorId: string,
    principalId: string,
    reason: string,
    idempotencyKey: string,
  ) {
    return this.modules.principals.archivePrincipal(
      operatorId,
      principalId,
      reason,
      idempotencyKey,
    );
  }

  async attachProof(operatorId: string, input: AttachAuthorityProofInput, idempotencyKey: string) {
    return this.modules.proofs.attachProof(operatorId, input, idempotencyKey);
  }

  /** Direct evidence import. Caller supplies native bytes, never verification results. */
  async importProof(operatorId: string, input: AttachAuthorityProofInput, idempotencyKey: string) {
    return this.modules.proofs.importProof(operatorId, input, idempotencyKey);
  }

  async createLegacyIdentityProofFacade(
    operatorId: string,
    input: CreateLegacyIdentityProofFacadeInput,
    idempotencyKey: string,
  ) {
    return this.modules.proofs.createLegacyIdentityProofFacade(operatorId, input, idempotencyKey);
  }

  async invalidateLegacyIdentityClaim(operatorId: string, identityClaimId: string, reason: string) {
    return this.modules.proofs.invalidateLegacyIdentityClaim(operatorId, identityClaimId, reason);
  }

  async createProofCollectionSession(
    operatorId: string,
    input: CreateAuthorityProofCollectionSessionInput,
    idempotencyKey: string,
  ) {
    return this.modules.proofCollection.createProofCollectionSession(
      operatorId,
      input,
      idempotencyKey,
    );
  }

  async getProofCollectionSession(operatorId: string, sessionId: string) {
    return this.modules.proofCollection.getProofCollectionSession(operatorId, sessionId);
  }

  async authenticateProofCallbackRequest(
    adapterKey: string,
    sessionId: string,
    input: Parameters<AuthorityModules['proofCollection']['authenticateProofCallbackRequest']>[2],
  ) {
    return this.modules.proofCollection.authenticateProofCallbackRequest(
      adapterKey,
      sessionId,
      input,
    );
  }

  async completeProofCollectionSession(
    auth: AuthorityProofCallbackAuthContext,
    input: AuthorityProofCallbackInput,
  ) {
    return this.modules.proofCollection.completeProofCollectionSession(auth, input);
  }

  async listProofs(operatorId: string) {
    return this.modules.proofs.listProofs(operatorId);
  }

  async getProof(operatorId: string, proofId: string, version?: number) {
    return this.modules.proofs.getProof(operatorId, proofId, version);
  }

  async revokeProof(operatorId: string, proofId: string, reason: string, idempotencyKey: string) {
    return this.modules.proofs.revokeProof(operatorId, proofId, reason, idempotencyKey);
  }

  async eraseProof(operatorId: string, proofId: string, idempotencyKey: string) {
    return this.modules.erasure.eraseProof(operatorId, proofId, idempotencyKey);
  }

  async erasePrincipal(operatorId: string, principalId: string, idempotencyKey: string) {
    return this.modules.erasure.erasePrincipal(operatorId, principalId, idempotencyKey);
  }

  async eraseBinding(operatorId: string, bindingId: string, idempotencyKey: string) {
    return this.modules.erasure.eraseBinding(operatorId, bindingId, idempotencyKey);
  }

  async erasePresentation(operatorId: string, presentationId: string, idempotencyKey: string) {
    return this.modules.erasure.erasePresentation(operatorId, presentationId, idempotencyKey);
  }

  async createBinding(
    operatorId: string,
    input: CreateAuthorityBindingInput,
    idempotencyKey: string,
  ) {
    return this.modules.bindings.createBinding(operatorId, input, idempotencyKey);
  }

  async listBindings(operatorId: string) {
    return this.modules.bindings.listBindings(operatorId);
  }

  async listAgentBindings(
    operatorId: string,
    agentId: string,
    page: number,
    limit: number,
    binding?: Parameters<AuthorityModules['bindings']['listAgentBindings']>[4],
  ) {
    return this.modules.bindings.listAgentBindings(operatorId, agentId, page, limit, binding);
  }

  async getBinding(operatorId: string, bindingId: string, version?: number) {
    return this.modules.bindings.getBinding(operatorId, bindingId, version);
  }

  async createApprovalRequests(
    operatorId: string,
    bindingId: string,
    input: CreateAuthorityApprovalRequestsInput,
    idempotencyKey: string,
  ) {
    return this.modules.approvals.createApprovalRequests(
      operatorId,
      bindingId,
      input,
      idempotencyKey,
    );
  }

  async listApprovalRequests(operatorId: string, bindingId: string) {
    return this.modules.approvals.listApprovalRequests(operatorId, bindingId);
  }

  async activateBinding(
    operatorId: string,
    bindingId: string,
    version: number | undefined,
    idempotencyKey: string,
    browserSession?: BrowserDecisionSession,
  ) {
    return this.modules.bindings.activateBinding(
      operatorId,
      bindingId,
      version,
      idempotencyKey,
      browserSession,
    );
  }

  async delegateBinding(
    operatorId: string,
    parentBindingId: string,
    input: DelegateAuthorityBindingInput,
    actor: AuthorityMutationActor,
    idempotencyKey: string,
  ) {
    return this.modules.bindings.delegateBinding(
      operatorId,
      parentBindingId,
      input,
      actor,
      idempotencyKey,
    );
  }

  async revokeBinding(
    operatorId: string,
    bindingId: string,
    reason: string,
    actor: AuthorityMutationActor,
    idempotencyKey: string,
  ) {
    return this.modules.bindings.revokeBinding(
      operatorId,
      bindingId,
      reason,
      actor,
      idempotencyKey,
    );
  }

  async decideApproval(
    operatorId: string,
    requestId: string,
    authenticatedAuthor: HumanOperatorAuthor,
    input: AuthorityApprovalDecisionInput,
    idempotencyKey: string,
    browserSession?: BrowserDecisionSession,
  ) {
    return this.modules.approvals.decideApproval(
      operatorId,
      requestId,
      authenticatedAuthor,
      input,
      idempotencyKey,
      browserSession,
    );
  }

  async evaluateAuthority(operatorId: string, input: AuthorityEvaluationInput) {
    return this.modules.evaluation.evaluateAuthority(operatorId, input);
  }

  async markRuntimeAuthorityDispatched(operatorId: string, useId: string) {
    return this.modules.runtimeUse.markRuntimeAuthorityDispatched(operatorId, useId);
  }

  async claimRuntimeAuthorityDispatch(
    operatorId: string,
    useId: string,
    transaction: AuthorityDbTransaction,
  ) {
    return this.modules.runtimeUse.claimRuntimeAuthorityDispatch(operatorId, useId, transaction);
  }

  async completeRuntimeAuthorityUse(
    input: Parameters<AuthorityModules['runtimeUse']['completeRuntimeAuthorityUse']>[0],
  ) {
    return this.modules.runtimeUse.completeRuntimeAuthorityUse(input);
  }

  /**
   * Proxy operations retain the one encrypted response envelope. Authority
   * receives only its commitment so the old idempotency ledger cannot create a
   * second exact-result copy with a different retention lifecycle.
   */
  async completeRuntimeAuthorityUseByHash(
    input: Parameters<AuthorityModules['runtimeUse']['completeRuntimeAuthorityUseByHash']>[0],
  ) {
    return this.modules.runtimeUse.completeRuntimeAuthorityUseByHash(input);
  }

  /**
   * Single runtime chokepoint for proxy, Skills, LLM and A2A. It loads the
   * Passport's persisted refs, selects exactly one active matching binding,
   * and refuses both zero matches and ambiguity before creating authority_use.
   */
  async evaluateRuntimeAuthority(
    input: Parameters<AuthorityModules['evaluation']['evaluateRuntimeAuthority']>[0],
  ) {
    return this.modules.evaluation.evaluateRuntimeAuthority(input);
  }

  async resolvePassportRefs(
    input: Parameters<AuthorityModules['passportRefs']['resolvePassportRefs']>[0],
  ) {
    return this.modules.passportRefs.resolvePassportRefs(input);
  }

  async delegatePassportRefs(
    input: Parameters<AuthorityModules['passportRefs']['delegatePassportRefs']>[0],
  ) {
    return this.modules.passportRefs.delegatePassportRefs(input);
  }

  async verifyPassportRefs(
    input: Parameters<AuthorityModules['passportRefs']['verifyPassportRefs']>[0],
  ) {
    return this.modules.passportRefs.verifyPassportRefs(input);
  }

  async linkPassportRefs(
    input: Parameters<AuthorityModules['passportRefs']['linkPassportRefs']>[0],
    transaction?: AuthorityDbTransaction,
  ) {
    return this.modules.passportRefs.linkPassportRefs(input, transaction);
  }

  async createReceiver(
    operatorId: string,
    input: CreateAuthorityReceiverInput,
    idempotencyKey: string,
  ) {
    return this.modules.receivers.createReceiver(operatorId, input, idempotencyKey);
  }

  async listReceivers(operatorId: string) {
    return this.modules.receivers.listReceivers(operatorId);
  }

  async getReceiver(operatorId: string, receiverId: string) {
    return this.modules.receivers.getReceiver(operatorId, receiverId);
  }

  async createReceiverVerificationChallenge(
    operatorId: string,
    receiverId: string,
    idempotencyKey: string,
  ) {
    return this.modules.receivers.createReceiverVerificationChallenge(
      operatorId,
      receiverId,
      idempotencyKey,
    );
  }

  async verifyReceiver(operatorId: string, receiverId: string, idempotencyKey: string) {
    return this.modules.receivers.verifyReceiver(operatorId, receiverId, idempotencyKey);
  }

  async addReceiverKey(
    operatorId: string,
    receiverId: string,
    input: AddAuthorityReceiverKeyInput,
    idempotencyKey: string,
  ) {
    return this.modules.receivers.addReceiverKey(operatorId, receiverId, input, idempotencyKey);
  }

  async revokeReceiverKey(
    operatorId: string,
    receiverId: string,
    keyId: string,
    reason: string,
    idempotencyKey: string,
  ) {
    return this.modules.receivers.revokeReceiverKey(
      operatorId,
      receiverId,
      keyId,
      reason,
      idempotencyKey,
    );
  }

  async createProfileVersion(
    operatorId: string,
    input: CreateAuthorityProfileVersionInput,
    idempotencyKey: string,
  ) {
    return this.modules.profileVersions.createProfileVersion(operatorId, input, idempotencyKey);
  }

  async activateProfileVersion(
    operatorId: string,
    kind: 'proof' | 'domain' | 'receiver',
    profileId: string,
    idempotencyKey: string,
  ) {
    return this.modules.profileVersions.activateProfileVersion(
      operatorId,
      kind,
      profileId,
      idempotencyKey,
    );
  }

  async authenticateReceiverRequest(
    input: Parameters<AuthorityModules['receivers']['authenticateReceiverRequest']>[0],
  ) {
    return this.modules.receivers.authenticateReceiverRequest(input);
  }

  async createPresentationRequest(
    auth: AuthorityReceiverAuthContext,
    input: ReceiverChallengeInput,
  ) {
    return this.modules.presentations.createPresentationRequest(auth, input);
  }

  async getPresentationRequest(auth: AuthorityReceiverAuthContext, presentationId: string) {
    return this.modules.presentations.getPresentationRequest(auth, presentationId);
  }

  async listAuthorityUses(operatorId: string) {
    return this.modules.uses.listAuthorityUses(operatorId);
  }

  async listAgentAuthorityUses(
    operatorId: string,
    agentId: string,
    page: number,
    limit: number,
    binding?: Parameters<AuthorityModules['uses']['listAgentAuthorityUses']>[4],
  ) {
    return this.modules.uses.listAgentAuthorityUses(operatorId, agentId, page, limit, binding);
  }

  /** Safe opaque projection for operator-facing Passport inventory. */
  async listPassportAuthorityRefs(operatorId: string, passportJti: string) {
    return this.modules.passportRefs.listPassportAuthorityRefs(operatorId, passportJti);
  }

  async listPassportAuthorityRefsForPassports(operatorId: string, passportJtis: string[]) {
    return this.modules.passportRefs.listPassportAuthorityRefsForPassports(
      operatorId,
      passportJtis,
    );
  }

  async getAuthorityUse(operatorId: string, useId: string) {
    return this.modules.uses.getAuthorityUse(operatorId, useId);
  }

  async listAuthorityPresentations(operatorId: string) {
    return this.modules.uses.listAuthorityPresentations(operatorId);
  }

  async getAuthorityPresentation(operatorId: string, presentationId: string) {
    return this.modules.uses.getAuthorityPresentation(operatorId, presentationId);
  }

  async statusCheck(auth: AuthorityReceiverAuthContext, input: AuthorityStatusCheckInput) {
    return this.modules.receipts.statusCheck(auth, input);
  }

  async acceptReceipt(
    auth: AuthorityReceiverAuthContext,
    presentationId: string,
    input: ReceiverReceiptInput,
  ) {
    return this.modules.receipts.acceptReceipt(auth, presentationId, input);
  }
}
