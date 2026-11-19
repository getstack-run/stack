import { canonicalize, sha256 } from '@stack/shared';
import type { JWTPayload } from 'jose';
import {
  AuthorityApprovalCeremonyRejectedError,
  type AuthorityProofAdapter,
  type VerifiedAuthorityProof,
} from '../../services/authority-service.js';

const ADAPTER_KEY = 'enterprise_oidc_authority';
const ADAPTER_VERSION = 1;
const STACK_CEREMONY_ISSUER = 'stack:authority-ceremony';

export interface EnterpriseOidcAuthoritySigner {
  verifyAuthorityCeremony(token: string): Promise<JWTPayload>;
}

export interface EnterpriseOidcAuthorityVerifier {
  verifyAuthorityEvidence(input: {
    operatorId: string;
    configId: string;
    idToken: string;
    expectedNonce: string;
  }): Promise<{
    payload: JWTPayload;
    signature_algorithm: string;
    issuer_key_thumbprint: string;
    expires_at: Date;
  }>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} is unavailable`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isInteger(value) || Number(value) <= 0) throw new Error(`${label} is unavailable`);
  return Number(value);
}

function atPath(value: unknown, path: string): unknown {
  let current = value;
  for (const segment of path.split('.')) {
    if (['__proto__', 'prototype', 'constructor'].includes(segment)
      || !current || typeof current !== 'object' || Array.isArray(current)
      || !Object.prototype.hasOwnProperty.call(current, segment)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function claimMatches(actual: unknown, expectedHash: string): boolean {
  if (Array.isArray(actual)) {
    return actual.some((value) => typeof value === 'string' && sha256(value) === expectedHash);
  }
  return typeof actual === 'string' && sha256(actual) === expectedHash;
}

function envelopeExpiry(payload: JWTPayload): Date {
  if (typeof payload.exp !== 'number') throw new Error('Authority evidence has no expiry');
  return new Date(payload.exp * 1000);
}

/**
 * Verifies customer-IdP identity and organisational-capacity evidence. STACK's
 * signed envelope binds provider-native evidence to the Authority principal;
 * the embedded ID token is independently re-verified against the configured
 * issuer and JWKS before any proof is accepted.
 */
export class EnterpriseOidcAuthorityAdapter implements AuthorityProofAdapter {
  readonly key = ADAPTER_KEY;
  readonly version = ADAPTER_VERSION;

  constructor(
    private readonly oidc: EnterpriseOidcAuthorityVerifier,
    private readonly signer: EnterpriseOidcAuthoritySigner,
  ) {}

  async verify(input: Parameters<AuthorityProofAdapter['verify']>[0]): Promise<VerifiedAuthorityProof> {
    if (![
      'application/stack-authority-oidc+jwt',
      'application/stack-authority-decision+jwt',
      'application/stack-authority-principal+jwt',
    ]
      .includes(input.nativeFormat)) {
      throw new Error('Authority evidence format is unsupported');
    }
    const envelope = await this.signer.verifyAuthorityCeremony(input.nativeEvidence);
    const operatorId = text(input.profile.operator_id, 'Authority proof operator');
    if (envelope['operator_id'] !== operatorId || envelope.sub !== input.expectedSubjectPrincipalId) {
      throw new Error('Authority evidence subject does not match its tenant or principal');
    }
    const represented = typeof envelope['represented_principal_id'] === 'string'
      ? envelope['represented_principal_id'] : undefined;
    if (represented !== input.expectedRepresentedPrincipalId) {
      throw new Error('Authority evidence represented principal mismatch');
    }

    if (input.nativeFormat === 'application/stack-authority-principal+jwt') {
      if (envelope['ceremony_type'] !== 'stack_principal_identity') {
        throw new Error('Authority principal evidence type is invalid');
      }
      const expiry = envelopeExpiry(envelope);
      return {
        normalizedFacts: {
          identity: {
            principal_registered: true,
            registration_hash: text(envelope['registration_hash'], 'Principal registration hash'),
          },
        },
        issuerIdentifier: STACK_CEREMONY_ISSUER,
        verificationMethod: 'stack:authority-principal-registration/1',
        verifierIdentifier: `${this.key}@${this.version}`,
        verifierVersion: String(this.version),
        assuranceUri: 'urn:stack:assurance:customer-asserted-organisation',
        verifiedAt: new Date(Number(envelope.iat) * 1000),
        validFrom: new Date(Number(envelope.nbf ?? envelope.iat) * 1000),
        expiresAt: expiry,
        statusFreshUntil: expiry,
        signatureVerified: true,
        signatureAlgorithm: 'EdDSA',
        subjectPrincipalId: input.expectedSubjectPrincipalId,
      };
    }

    if (input.nativeFormat === 'application/stack-authority-decision+jwt') {
      if (envelope['ceremony_type'] !== 'authority_decision_evidence') {
        throw new Error('Authority decision evidence type is invalid');
      }
      const mandateTermsDigest = text(envelope['mandate_terms_digest'], 'Mandate terms digest');
      const expiry = envelopeExpiry(envelope);
      return {
        normalizedFacts: {
          mandate_terms_digest: mandateTermsDigest,
          decision_purpose: text(envelope['decision_purpose'], 'Decision purpose'),
        },
        issuerIdentifier: STACK_CEREMONY_ISSUER,
        verificationMethod: 'stack:authority-ceremony/1',
        verifierIdentifier: `${this.key}@${this.version}`,
        verifierVersion: String(this.version),
        assuranceUri: 'urn:stack:assurance:oidc-reauthenticated',
        verifiedAt: new Date(Number(envelope.iat) * 1000),
        validFrom: new Date(Number(envelope.nbf ?? envelope.iat) * 1000),
        expiresAt: expiry,
        statusFreshUntil: expiry,
        signatureVerified: true,
        signatureAlgorithm: 'EdDSA',
        subjectPrincipalId: input.expectedSubjectPrincipalId,
        ...(represented ? { representedPrincipalId: represented } : {}),
        mandateTermsDigest,
      };
    }

    if (envelope['ceremony_type'] !== 'oidc_authority_evidence') {
      throw new Error('OIDC Authority evidence type is invalid');
    }
    const config = input.profile.config_json;
    const validation = config.validation as Record<string, unknown>;
    const subjectBinding = validation.subject_binding as Record<string, unknown>;
    const configId = text(subjectBinding['oidc_config_id'], 'OIDC profile configuration');
    if (envelope['oidc_config_id'] !== configId) throw new Error('OIDC configuration mismatch');
    const oidc = await this.oidc.verifyAuthorityEvidence({
      operatorId,
      configId,
      idToken: text(envelope['oidc_id_token'], 'OIDC ID token'),
      expectedNonce: text(envelope['oidc_nonce'], 'OIDC nonce'),
    });
    const issuer = text(oidc.payload.iss, 'OIDC issuer');
    if (issuer !== input.expectedIssuer) throw new Error('OIDC issuer mismatch');
    const subjectHash = sha256(`${issuer}\u0000${text(oidc.payload.sub, 'OIDC subject')}`);
    if (envelope['oidc_subject_hash'] !== subjectHash) throw new Error('OIDC subject binding mismatch');

    const proofKind = String(config.proof_kind ?? '');
    const facts: Record<string, unknown> = {
      identity: { subject_hash: subjectHash, issuer },
    };
    if (proofKind === 'capacity') {
      const claimPath = text(subjectBinding['claim_path'], 'OIDC capacity claim path');
      const claimValueHash = text(subjectBinding['claim_value_hash'], 'OIDC capacity claim value');
      const roleName = text(envelope['role_name'], 'OIDC capacity role name');
      if (sha256(roleName) !== text(subjectBinding['role_name_hash'], 'OIDC capacity role name binding')) {
        throw new Error('OIDC capacity role name mismatch');
      }
      if (!claimMatches(atPath(oidc.payload, claimPath), claimValueHash)) {
        throw new Error('OIDC token does not carry the configured organisational role');
      }
      facts.capacity = {
        role_verified: true,
        role_name: roleName,
        claim_path: claimPath,
        represented_principal_id: represented,
      };
    } else if (proofKind !== 'identity') {
      throw new Error('OIDC Authority profile proof kind is unsupported');
    }

    const issuedAt = typeof oidc.payload.iat === 'number' ? new Date(oidc.payload.iat * 1000) : new Date();
    const expiry = new Date(Math.min(oidc.expires_at.getTime(), envelopeExpiry(envelope).getTime()));
    return {
      normalizedFacts: facts,
      issuerIdentifier: issuer,
      issuerKeyThumbprint: oidc.issuer_key_thumbprint,
      verificationMethod: `${issuer}#oidc-id-token`,
      verifierIdentifier: `${this.key}@${this.version}`,
      verifierVersion: String(this.version),
      assuranceUri: 'urn:stack:assurance:enterprise-oidc',
      verifiedAt: issuedAt,
      validFrom: issuedAt,
      expiresAt: expiry,
      statusFreshUntil: expiry,
      signatureVerified: true,
      signatureAlgorithm: oidc.signature_algorithm,
      subjectPrincipalId: input.expectedSubjectPrincipalId,
      ...(represented ? { representedPrincipalId: represented } : {}),
    };
  }

  async verifyApprovalDecision(input: NonNullable<Parameters<NonNullable<AuthorityProofAdapter['verifyApprovalDecision']>>[0]>) {
    try {
      const payload = await this.signer.verifyAuthorityCeremony(input.signedDecision);
      if (payload['ceremony_type'] !== 'authority_approval_decision'
        || payload.sub !== input.authoriserPrincipalId
        || payload['request_id'] !== input.requestId
        || payload['request_hash'] !== input.requestHash
        || payload['decision'] !== input.decision
        || payload['authenticated_author_hash'] !== sha256(canonicalize(input.authenticatedAuthor))
        || payload['identity_proof_id'] !== input.identityProof.id
        || payload['identity_proof_version'] !== input.identityProof.version
        || payload['capacity_proof_id'] !== (input.capacityProof?.id ?? null)
        || payload['capacity_proof_version'] !== (input.capacityProof?.version ?? null)) {
        throw new AuthorityApprovalCeremonyRejectedError();
      }
      return {
        decisionProofId: text(payload['decision_proof_id'], 'Decision proof id'),
        decisionProofVersion: integer(payload['decision_proof_version'], 'Decision proof version'),
      };
    } catch (error) {
      if (error instanceof AuthorityApprovalCeremonyRejectedError) throw error;
      throw new AuthorityApprovalCeremonyRejectedError();
    }
  }
}

export const ENTERPRISE_OIDC_AUTHORITY_ADAPTER_KEY = ADAPTER_KEY;
export const ENTERPRISE_OIDC_AUTHORITY_ADAPTER_VERSION = ADAPTER_VERSION;
