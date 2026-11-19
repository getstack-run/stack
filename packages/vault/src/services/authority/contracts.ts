/** Collaborator contracts and dependency bundle of the authority service. */
import type {
  AuthorityReference,
  CreateAuthorityProofCollectionSessionInput,
  HumanOperatorAuthor,
} from '@stack/shared';
import type {
  AuthorityApprovalClaimContext,
  AuthorityBindingProofRecord,
  AuthorityBindingRecord,
  AuthorityDbTransaction,
  AuthorityErasureTombstone,
  AuthorityProofProfileVersionRecord,
  AuthorityProofRecord,
  AuthorityUseInsert,
  AuthorityUseRecord,
  ReceiverTransactionReceiptRecord,
} from './records.js';
import type { AuthorityPresentationProtocol } from './presentation-protocol.js';
import type { AuthorityRepositoryPort } from './port.js';
import type { KmsService } from '../../crypto/kms.js';
import type { ResolvedAuthorityApprovalDecision } from './approval-verifier.js';

export interface VerifiedAuthorityProof {
  normalizedFacts: Record<string, unknown>;
  issuerIdentifier: string;
  issuerKeyThumbprint?: string;
  verificationMethod: string;
  verifierIdentifier: string;
  verifierVersion: string;
  assuranceUri?: string;
  verifiedAt: Date;
  validFrom: Date;
  expiresAt?: Date;
  statusFreshUntil?: Date;
  signatureVerified: boolean;
  signatureAlgorithm?: string;
  subjectPrincipalId: string;
  representedPrincipalId?: string;
  /** Required for mandate/consent/signature proofs bound to exact terms. */
  mandateTermsDigest?: string;
}

export interface AuthorityProofAdapter {
  key: string;
  version: number;
  /** Immutable adapter-owned allowlist for browser authorization redirects. */
  authorizationOrigins?: readonly string[];
  verify(input: {
    nativeEvidence: string;
    nativeFormat: string;
    expectedIssuer: string;
    expectedSubjectPrincipalId: string;
    expectedRepresentedPrincipalId?: string;
    profile: AuthorityProofProfileVersionRecord;
  }): Promise<VerifiedAuthorityProof>;
  meetsAssurance?(actual: string | null, minimum: string): boolean;
  initiateCollection?(input: {
    operationId: string;
    sessionId: string;
    stateToken: string;
    subjectPrincipalId: string;
    representedPrincipalId?: string;
    issuerIdentifier: string;
    profile: AuthorityProofProfileVersionRecord;
    nativeFormat: string;
  }): Promise<{ authorizationUrl?: string; providerSessionReference?: string; expiresAt: Date }>;
  authenticateCallback?(input: {
    method: 'POST';
    path: string;
    headers: Readonly<Record<string, string | undefined>>;
    bodyHash: string;
  }): Promise<{ jti: string; issuerIdentifier: string; expiresAt: Date }>;
  completeCollection?(input: {
    operationId: string;
    sessionId: string;
    signedCallback: string;
    expectedIssuerIdentifier: string;
    providerSessionReference?: string;
  }): Promise<{ nativeEvidence: string; nativeFormat: string; validFrom: Date; expiresAt?: Date }>;
  verifyApprovalDecision?(input: {
    requestId: string;
    requestHash: string;
    decision: 'approve' | 'reject';
    signedDecision: string;
    authenticatedAuthor: HumanOperatorAuthor;
    authoriserPrincipalId: string;
    identityProof: AuthorityProofRecord;
    capacityProof?: AuthorityProofRecord;
    profile: AuthorityProofProfileVersionRecord;
  }): Promise<{ decisionProofId: string; decisionProofVersion: number }>;
  bindLegacyIdentitySubject?(input: {
    operatorId: string;
    identityClaimId: string;
    signedClaimId: string;
    subjectPrincipalId: string;
    profile: AuthorityProofProfileVersionRecord;
  }): Promise<boolean>;
  disclose?(input: {
    mode: 'predicate' | 'pairwise' | 'issuer_evidence';
    factId: string;
    nativePath: string;
    receiverId: string;
    requestHash: string;
    proof: AuthorityProofRecord;
    profile: AuthorityProofProfileVersionRecord;
    normalizedFacts?: Record<string, unknown>;
    nativeEvidence?: string;
  }): Promise<{
    mode: 'predicate' | 'pairwise' | 'issuer_evidence';
    value: unknown;
    evidenceDigest: string;
    provenance: { adapter_key: string; adapter_version: number; method: string };
  }>;
}

export interface CreateLegacyIdentityProofFacadeInput {
  identity_claim_id: string;
  subject_principal_id: string;
  profile_version_id: string;
}

export interface AuthorityProofCollectionWorkflowRecord {
  ledger_id: string;
  operator_id: string;
  session_id: string;
  request_hash: string;
  state: 'started' | 'completed';
  response_status: number | null;
  response_body: Record<string, unknown> | null;
  workflow_phase:
    | 'reserved'
    | 'initiating'
    | 'ready'
    | 'callback_verifying'
    | 'callback_verified'
    | 'completed'
    | 'failed';
  workflow_payload_encrypted: string;
  lease_token_hash: string | null;
  lease_expires_at: Date | null;
  expires_at: Date;
}

export interface AuthorityProofCollectionWorkflowPayload {
  request: CreateAuthorityProofCollectionSessionInput;
  adapter_key: string;
  adapter_version: number;
  state_hash: string;
  state_token: string;
  ceremony_expires_at: string;
  initiation_operation_id: string;
  authorization_url?: string;
  provider_session_reference?: string;
  provider_expires_at?: string;
  callback_jti_hash?: string;
  callback_hash?: string;
  callback_operation_id?: string;
  callback_result?: {
    native_evidence: string;
    native_format: string;
    verified: {
      normalized_facts: Record<string, unknown>;
      issuer_identifier: string;
      issuer_key_thumbprint?: string;
      subject_principal_id: string;
      represented_principal_id?: string;
      verification_method: string;
      verifier_identifier: string;
      verifier_version: string;
      assurance_uri?: string;
      verified_at: string;
      valid_from: string;
      expires_at?: string;
      status_fresh_until?: string;
      signature_verified: boolean;
      signature_algorithm?: string;
      mandate_terms_digest?: string;
    };
  };
  proof_view?: Record<string, unknown>;
}

export interface LegacyIdentityClaimReference {
  id: string;
  operator_id: string;
  provider_key: string;
  layer: string;
  claim_type: string;
  assurance_level: string;
  verified_at: Date;
  expires_at: Date;
  signed_claim_id: string;
  signed_claim_hash: string;
}

export interface AuthorityProofCallbackAuthContext {
  adapterKey: string;
  callbackJti: string;
  issuerIdentifier: string;
  expiresAt: Date;
}

export interface AuthorityClaimIssuer {
  registerExternalProofVerificationClaim(
    input: {
      operatorId: string;
      proof: AuthorityProofRecord;
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<{ claimId: string; claimHash: string }>;
  registerBindingClaim(
    input: {
      operatorId: string;
      binding: AuthorityBindingRecord;
      proofRefs: AuthorityBindingProofRecord[];
      bindingDigest: string;
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<{ claimId: string; claimHash: string }>;
  registerApprovalClaim(
    input: {
      operatorId: string;
      claim: AuthorityApprovalClaimContext;
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<{ claimId: string; claimHash: string }>;
  registerAuthorityUseClaim(
    input: {
      operatorId: string;
      use: AuthorityUseInsert | AuthorityUseRecord;
      bindingDigest: string;
      domainProfileVersionId: string | null;
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<{ claimId: string; claimHash: string }>;
  registerReceiverReceiptClaim(
    input: {
      operatorId: string;
      receipt: ReceiverTransactionReceiptRecord;
      presentationPayloadHash: string;
      actionUri: string;
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<{ claimId: string; claimHash: string }>;
  registerAuthorityErasureTombstone(
    input: {
      operatorId: string;
      tombstone: Omit<AuthorityErasureTombstone, 'tombstone_claim_id'>;
      erasedAt: Date;
    },
    transaction?: AuthorityDbTransaction,
  ): Promise<{ claimId: string; claimHash: string }>;
}

export interface AuthorityServiceDeps {
  repo: AuthorityRepositoryPort;
  kms: Pick<KmsService, 'encrypt' | 'decrypt'>;
  adapters?: AuthorityProofAdapter[];
  claimIssuer: AuthorityClaimIssuer;
  /** Versioned receiver-wire adapters. Core selects only from the immutable receiver profile. */
  presentationProtocols?: AuthorityPresentationProtocol[];
  /** Exact audience accepted on every receiver-signed request JWT. */
  receiverRequestAudience: string;
  passportVerifier: {
    verifyPresentationPassport(input: {
      token: string;
      operatorId: string;
      receiverId: string;
      authorityRef: AuthorityReference;
      missionId: string | null;
    }): Promise<{ jti: string; agentId: string }>;
  };
  approvalDecisionVerifier: {
    verify(input: {
      operatorId: string;
      requestId: string;
      requestHash: string;
      decision: 'approve' | 'reject';
      signedDecision: string;
      authenticatedAuthor: HumanOperatorAuthor;
    }): Promise<ResolvedAuthorityApprovalDecision>;
  };
  receiverOriginVerifier: {
    fetchWellKnown(input: {
      url: string;
      resolvedAddresses: string[];
      redirect: 'manual';
    }): Promise<{ status: number; body: string; location?: string }>;
  };
  passportRevocationPublisher: {
    publishAuthorityRevocations(jtis: string[], reason: string): Promise<void>;
  };
  legacyIdentityResolver: {
    resolveFacts(input: {
      operatorId: string;
      identityClaimId: string;
      subjectPrincipalId: string;
    }): Promise<Record<string, unknown>>;
  };
  now?: () => Date;
}
