/** The persistence port the authority service depends on. */
import type {
  AuthorityApprovalDecisionInput,
  AuthorityReference,
  HumanOperatorAuthor,
} from '@stack/shared';
import type { JWK } from 'jose';
import type {
  AuthorityApprovalClaimContext,
  AuthorityApprovalRequestRecord,
  AuthorityBindingProofRecord,
  AuthorityBindingRecord,
  AuthorityDbTransaction,
  AuthorityErasureTarget,
  AuthorityErasureTombstone,
  AuthorityPresentationPatch,
  AuthorityPresentationRecord,
  AuthorityPrincipalRecord,
  AuthorityProofProfileVersionRecord,
  AuthorityProofRecord,
  AuthorityProofStatus,
  AuthorityReceiverKeyRecord,
  AuthorityReceiverProfileRecord,
  AuthorityReceiverRecord,
  AuthorityRuntimeBoundary,
  AuthorityUseInsert,
  AuthorityUseRecord,
  ReceiverTransactionReceiptRecord,
} from './records.js';
import type {
  AuthorityApprovalVerifierCandidate,
  ResolvedAuthorityApprovalDecision,
} from './approval-verifier.js';
import type {
  AuthorityProofCollectionWorkflowRecord,
  LegacyIdentityClaimReference,
} from './contracts.js';

export interface AuthorityRepositoryPort {
  /** Runs every repository write in one caller-owned database transaction. */
  atomic<T>(mutation: (repo: AuthorityRepositoryPort) => Promise<T>): Promise<T>;
  /** Opaque transaction handle used only by ClaimRegistry's persistence override. */
  currentTransaction(): AuthorityDbTransaction | undefined;
  idempotent<T>(
    input: {
      ledgerId: string;
      operatorId: string;
      operation: string;
      idempotencyKey: string;
      payloadHash: string;
      workflowPayloadEncrypted: string;
      matchesExistingRequest(encrypted: string, existingLedgerId: string): Promise<boolean>;
      responseStatus: number;
    },
    mutation: (repo: AuthorityRepositoryPort) => Promise<T>,
  ): Promise<T>;

  insertPrincipal(row: AuthorityPrincipalRecord): Promise<AuthorityPrincipalRecord>;
  listPrincipals(operatorId: string): Promise<AuthorityPrincipalRecord[]>;
  listAccountRecords(
    operatorId: string,
    kind: 'principals' | 'proofs' | 'receivers',
    page: number,
    limit: number,
  ): Promise<
    | { principals: AuthorityPrincipalRecord[]; proofs?: never; receivers?: never }
    | { proofs: AuthorityProofRecord[]; principals?: never; receivers?: never }
    | { receivers: AuthorityReceiverRecord[]; principals?: never; proofs?: never }
  >;
  listAccountRecordBindings(
    operatorId: string,
    kind: 'principals' | 'proofs' | 'receivers',
    recordId: string,
    version: number | undefined,
    page: number,
    limit: number,
  ): Promise<AuthorityBindingRecord[]>;
  findPrincipal(operatorId: string, principalId: string): Promise<AuthorityPrincipalRecord | null>;
  archivePrincipal(
    operatorId: string,
    principalId: string,
    reason: string,
    now: Date,
  ): Promise<AuthorityPrincipalRecord | null>;
  lockErasureGraph(input: {
    operatorId: string;
    targetKind: 'principal' | 'binding' | 'proof' | 'presentation';
    targetId: string;
  }): Promise<AuthorityErasureTarget[] | null>;
  applyErasureGraph(input: {
    operatorId: string;
    targetKind: 'principal' | 'binding' | 'proof' | 'presentation';
    targetId: string;
    erasedAt: Date;
    tombstones: AuthorityErasureTombstone[];
  }): Promise<{ passportJtis: string[] }>;

  findProofProfileVersion(
    operatorId: string,
    id: string,
  ): Promise<AuthorityProofProfileVersionRecord | null>;
  insertProof(row: AuthorityProofRecord): Promise<AuthorityProofRecord>;
  findLegacyIdentityClaim(
    operatorId: string,
    claimId: string,
  ): Promise<LegacyIdentityClaimReference | null>;
  findLegacyProofFacade(
    operatorId: string,
    legacyClaimId: string,
    subjectPrincipalId: string,
    profileVersionId: string,
  ): Promise<AuthorityProofRecord | null>;
  listLegacyProofFacades(
    operatorId: string,
    legacyClaimId: string,
  ): Promise<AuthorityProofRecord[]>;
  reserveProofCollectionWorkflow(input: {
    ledgerId: string;
    operatorId: string;
    sessionId: string;
    idempotencyKey: string;
    requestHash: string;
    workflowPayloadEncrypted: string;
    expiresAt: Date;
    now: Date;
  }): Promise<{ workflow: AuthorityProofCollectionWorkflowRecord; created: boolean }>;
  findProofCollectionWorkflow(
    sessionId: string,
    operatorId?: string,
  ): Promise<AuthorityProofCollectionWorkflowRecord | null>;
  acquireProofCollectionWorkflowLease(input: {
    operatorId: string;
    sessionId: string;
    from: Array<AuthorityProofCollectionWorkflowRecord['workflow_phase']>;
    to: 'initiating' | 'callback_verifying';
    leaseTokenHash: string;
    leaseExpiresAt: Date;
    now: Date;
  }): Promise<{ workflow: AuthorityProofCollectionWorkflowRecord; acquired: boolean } | null>;
  transitionProofCollectionWorkflow(input: {
    operatorId: string;
    sessionId: string;
    from: AuthorityProofCollectionWorkflowRecord['workflow_phase'];
    leaseTokenHash: string;
    to: AuthorityProofCollectionWorkflowRecord['workflow_phase'];
    workflowPayloadEncrypted: string;
    now: Date;
    safeResponse?: Record<string, unknown>;
    responseStatus?: number;
  }): Promise<AuthorityProofCollectionWorkflowRecord | null>;
  listProofs(operatorId: string): Promise<AuthorityProofRecord[]>;
  findProof(
    operatorId: string,
    proofId: string,
    version?: number,
  ): Promise<AuthorityProofRecord | null>;
  listProofSources(
    operatorId: string,
    proofId: string,
    version: number,
  ): Promise<AuthorityProofRecord[]>;
  transitionProof(input: {
    operatorId: string;
    proofId: string;
    from: AuthorityProofStatus[];
    to: AuthorityProofStatus;
    now: Date;
    reason?: string;
    erase?: { tombstoneHash: string; tombstoneClaimId: string };
  }): Promise<AuthorityProofRecord | null>;
  cascadeProofInvalidation(
    operatorId: string,
    proofId: string,
    now: Date,
    reason: string,
  ): Promise<{ passportJtis: string[] }>;

  resolveCurrentAgentKey(
    operatorId: string,
    agentId: string,
  ): Promise<{
    thumbprint: string;
    active: boolean;
    publicJwk: JWK;
  } | null>;
  isMissionActive(operatorId: string, missionId: string): Promise<boolean>;
  findReceiver(operatorId: string, receiverId: string): Promise<AuthorityReceiverRecord | null>;
  findReceiverProfile(
    operatorId: string,
    profileId: string,
  ): Promise<AuthorityReceiverProfileRecord | null>;
  insertBinding(
    row: AuthorityBindingRecord,
    proofs: AuthorityBindingProofRecord[],
  ): Promise<AuthorityBindingRecord>;
  listBindings(operatorId: string): Promise<AuthorityBindingRecord[]>;
  listAgentBindings(
    operatorId: string,
    agentId: string,
    page: number,
    limit: number,
    binding?: { id: string; version: number },
  ): Promise<{
    bindings: AuthorityBindingRecord[];
    links: AuthorityBindingProofRecord[];
    principals: AuthorityPrincipalRecord[];
    receivers: AuthorityReceiverRecord[];
    proofs: AuthorityProofRecord[];
    has_more: boolean;
  }>;
  findBinding(
    operatorId: string,
    bindingId: string,
    version?: number,
  ): Promise<AuthorityBindingRecord | null>;
  listBindingProofs(
    operatorId: string,
    bindingId: string,
    version: number,
  ): Promise<AuthorityBindingProofRecord[]>;
  activateBinding(input: {
    operatorId: string;
    bindingId: string;
    version: number;
    claimId: string;
    claimHash: string;
    now: Date;
  }): Promise<AuthorityBindingRecord | null>;
  revokeBindingCascade(
    operatorId: string,
    bindingId: string,
    now: Date,
    reason: string,
  ): Promise<{
    binding: AuthorityBindingRecord;
    passportJtis: string[];
  } | null>;
  isBindingInAgentChain(
    operatorId: string,
    bindingId: string,
    version: number,
    agentId: string,
  ): Promise<boolean>;
  isPassportAuthorizedForBinding(input: {
    operatorId: string;
    passportJti: string;
    agentId: string;
    bindingId: string;
    bindingVersion: number;
    now: Date;
  }): Promise<boolean>;
  hasUnsatisfiedApprovals(
    operatorId: string,
    bindingId: string,
    version: number,
    requestHash?: string,
  ): Promise<boolean>;
  consumeSatisfiedApprovals(input: {
    operatorId: string;
    bindingId: string;
    bindingVersion: number;
    phase: 'activation' | 'action' | 'presentation';
    requestHash: string;
    now: Date;
  }): Promise<void>;
  ensureApprovalRequest(input: {
    operatorId: string;
    bindingId: string;
    bindingVersion: number;
    authorityUseId?: string;
    phase: 'activation' | 'action' | 'presentation';
    groupKey: string;
    requestHash: string;
    challengeHash: string;
    requiredWeight: number;
    rejectMode: 'any_reject' | 'threshold_reject';
    expiresAt: Date;
  }): Promise<void>;
  listApprovalRequests(
    operatorId: string,
    bindingId: string,
  ): Promise<AuthorityApprovalRequestRecord[]>;
  listSatisfiedApprovalClaimRefs(input: {
    operatorId: string;
    bindingId: string;
    bindingVersion: number;
    authorityUseId: string;
  }): Promise<{
    claimRefs: Array<{
      claim_id: string;
      claim_hash: string;
      phase: AuthorityApprovalRequestRecord['phase'];
    }>;
    requirements: Array<{
      phase: AuthorityApprovalRequestRecord['phase'];
      group_key_hash: string;
      required_weight: number;
      collected_weight: number;
      reject_mode: AuthorityApprovalRequestRecord['reject_mode'];
      request_hash: string;
      approval_requirement_hash: string;
      status: AuthorityApprovalRequestRecord['status'];
      decision_claim_refs: Array<{ claim_id: string; claim_hash: string }>;
    }>;
  }>;
  listApprovalVerifierCandidates(
    operatorId: string,
    requestId: string,
    now: Date,
  ): Promise<AuthorityApprovalVerifierCandidate[]>;
  decideApproval(input: {
    operatorId: string;
    requestId: string;
    authenticatedAuthor: HumanOperatorAuthor;
    decision: AuthorityApprovalDecisionInput;
    resolved: ResolvedAuthorityApprovalDecision;
    decisionId: string;
    now: Date;
  }): Promise<Record<string, unknown> | null>;
  validateApprovalDecision(input: {
    operatorId: string;
    requestId: string;
    authenticatedAuthor: HumanOperatorAuthor;
    decision: AuthorityApprovalDecisionInput;
    resolved: ResolvedAuthorityApprovalDecision;
    now: Date;
  }): Promise<Omit<
    AuthorityApprovalClaimContext,
    'decision_id' | 'decided_at' | 'revoked_at'
  > | null>;
  insertAuthorityUse(input: AuthorityUseInsert): Promise<AuthorityUseRecord>;
  findAuthorityUseByRuntimeRequest(
    operatorId: string,
    receiverId: string,
    receiverRequestId: string,
  ): Promise<AuthorityUseRecord | null>;
  authorizeWaitingAuthorityUse(
    operatorId: string,
    useId: string,
    now: Date,
  ): Promise<AuthorityUseRecord | null>;
  setAuthorityUseProofStrength(input: {
    operatorId: string;
    useId: string;
    from: AuthorityUseRecord['proof_strength'];
    to: AuthorityUseRecord['proof_strength'];
  }): Promise<AuthorityUseRecord | null>;
  markAuthorityUseDispatched(
    operatorId: string,
    useId: string,
    now: Date,
  ): Promise<AuthorityUseRecord | null>;
  claimAuthorityUseDispatched(
    operatorId: string,
    useId: string,
    now: Date,
    transaction?: AuthorityDbTransaction,
  ): Promise<AuthorityUseRecord | null>;
  completeAuthorityUse(input: {
    operatorId: string;
    useId: string;
    outcome: 'succeeded' | 'failed';
    resultHash: string;
    intentClaimId?: string;
    outcomeClaimId?: string;
    now: Date;
  }): Promise<AuthorityUseRecord | null>;
  consumeReceiverJti(input: {
    receiverId: string;
    jtiHash: string;
    expiresAt: Date;
  }): Promise<boolean>;
  consumeAuthorityJti(input: {
    operatorId: string;
    namespace: string;
    jtiHash: string;
    expiresAt: Date;
  }): Promise<boolean>;
  findReceiverKey(
    receiverId: string,
    keyId: string,
    use: AuthorityReceiverKeyRecord['use'],
  ): Promise<AuthorityReceiverKeyRecord | null>;
  findReceiverById(receiverId: string): Promise<AuthorityReceiverRecord | null>;
  findReceiverByCanonicalId(receiverId: string): Promise<AuthorityReceiverRecord | null>;
  findNativeReceiversByCanonicalId(identifier: string): Promise<AuthorityReceiverRecord[]>;
  findManagedReceiverByCanonicalId(
    operatorId: string,
    identifier: string,
  ): Promise<AuthorityReceiverRecord | null>;
  isOwnedActiveServiceConnection(operatorId: string, connectionId: string): Promise<boolean>;
  isOwnedInternalReceiver(operatorId: string, identifier: string): Promise<boolean>;
  resolveRuntimeReceivers(
    operatorId: string,
    boundary: AuthorityRuntimeBoundary,
  ): Promise<AuthorityReceiverRecord[]>;
  insertReceiver(
    row: AuthorityReceiverRecord & {
      canonical_identifier: string;
      display_name: string;
      proxy_service_connection_id: string | null;
      created_at: Date;
    },
  ): Promise<AuthorityReceiverRecord>;
  listReceivers(operatorId: string): Promise<AuthorityReceiverRecord[]>;
  createReceiverVerificationChallenge(input: {
    operatorId: string;
    receiverId: string;
    challengeId: string;
    challengeHash: string;
    expiresAt: Date;
  }): Promise<boolean>;
  consumeReceiverVerificationChallenge(input: {
    operatorId: string;
    receiverId: string;
    challengeId: string;
    challengeHash: string;
    now: Date;
  }): Promise<boolean>;
  markReceiverVerified(
    operatorId: string,
    receiverId: string,
    now: Date,
  ): Promise<AuthorityReceiverRecord | null>;
  insertReceiverKey(
    row: AuthorityReceiverKeyRecord & { created_at: Date; revoked_at: Date | null },
  ): Promise<AuthorityReceiverKeyRecord>;
  listReceiverKeys(
    receiverId: string,
    use?: AuthorityReceiverKeyRecord['use'],
  ): Promise<AuthorityReceiverKeyRecord[]>;
  revokeReceiverKey(
    operatorId: string,
    receiverId: string,
    keyId: string,
    reason: string,
    now: Date,
  ): Promise<AuthorityReceiverKeyRecord | null>;
  insertProfileVersion(row: {
    id: string;
    owner_operator_id: string | null;
    profile_kind: 'proof' | 'domain' | 'receiver';
    profile_key: string;
    version: number;
    receiver_id: string | null;
    schema_uri: string;
    schema_version: string;
    adapter_key: string;
    adapter_version: number;
    config_json: Record<string, unknown>;
    content_hash: string;
    status: 'draft';
    created_at: Date;
  }): Promise<Record<string, unknown>>;
  activateProfileVersion(
    operatorId: string,
    kind: 'proof' | 'domain' | 'receiver',
    id: string,
    now: Date,
  ): Promise<Record<string, unknown> | null>;
  findProfileVersion(
    operatorId: string,
    kind: 'proof' | 'domain' | 'receiver',
    id: string,
  ): Promise<Record<string, unknown> | null>;
  findAuthorityUseById(receiverId: string, useId: string): Promise<AuthorityUseRecord | null>;
  findAuthorityUseForPresentation(
    receiverId: string,
    receiverRequestId: string,
    requestHash: string,
  ): Promise<AuthorityUseRecord | null>;
  insertPresentation(row: AuthorityPresentationRecord): Promise<AuthorityPresentationRecord>;
  findPresentation(
    receiverId: string,
    presentationId: string,
  ): Promise<AuthorityPresentationRecord | null>;
  lockPresentationAndUseForReceipt(
    receiverId: string,
    presentationId: string,
  ): Promise<{
    presentation: AuthorityPresentationRecord;
    use: AuthorityUseRecord;
  } | null>;
  lockReceiptAuthorityGraph(
    receiverId: string,
    presentationId: string,
    now: Date,
  ): Promise<{
    presentation: AuthorityPresentationRecord;
    use: AuthorityUseRecord;
    binding: AuthorityBindingRecord;
  } | null>;
  lockBindingGraphForDisclosure(
    operatorId: string,
    bindingId: string,
    bindingVersion: number,
  ): Promise<void>;
  updatePresentation(input: {
    receiverId: string;
    presentationId: string;
    from: AuthorityPresentationRecord['status'][];
    patch: AuthorityPresentationPatch;
  }): Promise<AuthorityPresentationRecord | null>;
  insertReceiverReceipt(
    row: ReceiverTransactionReceiptRecord,
  ): Promise<ReceiverTransactionReceiptRecord>;
  findReceiverReceiptByPresentation(
    receiverId: string,
    presentationId: string,
  ): Promise<ReceiverTransactionReceiptRecord | null>;
  listAuthorityUses(operatorId: string): Promise<AuthorityUseRecord[]>;
  listAgentAuthorityUses(
    operatorId: string,
    agentId: string,
    page: number,
    limit: number,
    binding?: { id: string; version: number },
  ): Promise<{
    uses: AuthorityUseRecord[];
    presentations: AuthorityPresentationRecord[];
    has_more: boolean;
  }>;
  findAuthorityUseForOperator(
    operatorId: string,
    useId: string,
  ): Promise<AuthorityUseRecord | null>;
  listPresentationsForOperator(operatorId: string): Promise<AuthorityPresentationRecord[]>;
  findPresentationForOperator(
    operatorId: string,
    presentationId: string,
  ): Promise<AuthorityPresentationRecord | null>;
  linkPassportRefs(
    input: {
      operatorId: string;
      passportJti: string;
      refs: AuthorityReference[];
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<void>;
  listPassportRefs(operatorId: string, passportJti: string): Promise<AuthorityReference[]>;
  listPassportRefsForPassports(
    operatorId: string,
    passportJtis: string[],
  ): Promise<Map<string, AuthorityReference[]>>;
}
