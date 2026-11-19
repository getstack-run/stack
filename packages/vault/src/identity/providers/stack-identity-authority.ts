import { canonicalize, sha256 } from '@stack/shared';
import type { JWTPayload } from 'jose';
import {
  AuthorityApprovalCeremonyRejectedError,
  type AuthorityProofAdapter,
  type VerifiedAuthorityProof,
} from '../../services/authority-service.js';

const ADAPTER_KEY = 'stack_identity_authority';
const ADAPTER_VERSION = 1;
const STACK_CEREMONY_ISSUER = 'stack:authority-ceremony';

export interface StackIdentityAuthoritySigner {
  verifyAuthorityCeremony(token: string): Promise<JWTPayload>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} is unavailable`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isInteger(value) || Number(value) <= 0) throw new Error(`${label} is unavailable`);
  return Number(value);
}

function envelopeExpiry(payload: JWTPayload): Date {
  if (typeof payload.exp !== 'number') throw new Error('Authority evidence has no expiry');
  return new Date(payload.exp * 1000);
}

/**
 * Bridges a fresh, provider-verified STACK identity claim into Authority.
 * The legacy claim remains the revocation source; the signed ceremony binds
 * that exact claim to the exact human principal and approval request.
 */
export class StackIdentityAuthorityAdapter implements AuthorityProofAdapter {
  readonly key = ADAPTER_KEY;
  readonly version = ADAPTER_VERSION;

  constructor(private readonly signer: StackIdentityAuthoritySigner) {}

  async bindLegacyIdentitySubject(input: Parameters<NonNullable<AuthorityProofAdapter['bindLegacyIdentitySubject']>>[0]) {
    try {
      const validation = input.profile.config_json.validation as Record<string, unknown>;
      const subjectBinding = validation.subject_binding as Record<string, unknown>;
      if (subjectBinding['method'] !== 'stack_identity_claim_ceremony') return false;
      const payload = await this.signer.verifyAuthorityCeremony(
        text(subjectBinding['binding_jws'], 'Identity binding ceremony'),
      );
      return payload['ceremony_type'] === 'identity_claim_authority_binding'
        && payload['operator_id'] === input.operatorId
        && payload.sub === input.subjectPrincipalId
        && payload['identity_claim_id'] === input.identityClaimId
        && payload['signed_claim_id'] === input.signedClaimId;
    } catch {
      return false;
    }
  }

  async verify(input: Parameters<AuthorityProofAdapter['verify']>[0]): Promise<VerifiedAuthorityProof> {
    if (![
      'application/stack-authority-capacity+jwt',
      'application/stack-authority-decision+jwt',
      'application/stack-authority-principal+jwt',
    ].includes(input.nativeFormat)) {
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
    const expiry = envelopeExpiry(envelope);
    const issuedAt = new Date(Number(envelope.iat) * 1000);
    const base = {
      issuerIdentifier: STACK_CEREMONY_ISSUER,
      verifierIdentifier: `${this.key}@${this.version}`,
      verifierVersion: String(this.version),
      verifiedAt: issuedAt,
      validFrom: new Date(Number(envelope.nbf ?? envelope.iat) * 1000),
      expiresAt: expiry,
      statusFreshUntil: expiry,
      signatureVerified: true,
      signatureAlgorithm: 'EdDSA',
      subjectPrincipalId: input.expectedSubjectPrincipalId,
      ...(represented ? { representedPrincipalId: represented } : {}),
    };

    if (input.nativeFormat === 'application/stack-authority-principal+jwt') {
      if (envelope['ceremony_type'] !== 'stack_principal_identity') {
        throw new Error('Authority principal evidence type is invalid');
      }
      return {
        ...base,
        normalizedFacts: {
          identity: {
            principal_registered: true,
            registration_hash: text(envelope['registration_hash'], 'Principal registration hash'),
          },
        },
        verificationMethod: 'stack:authority-principal-registration/1',
        assuranceUri: 'urn:stack:assurance:customer-asserted-organisation',
      };
    }

    if (input.nativeFormat === 'application/stack-authority-capacity+jwt') {
      if (envelope['ceremony_type'] !== 'customer_asserted_capacity') {
        throw new Error('Authority capacity evidence type is invalid');
      }
      return {
        ...base,
        normalizedFacts: {
          capacity: {
            role_asserted: true,
            role_name: text(envelope['role_name'], 'Asserted company role'),
            assertion_source: 'customer_account_admin',
            assertion_hash: text(envelope['assertion_hash'], 'Capacity assertion hash'),
          },
        },
        verificationMethod: 'stack:customer-capacity-assertion/1',
        assuranceUri: 'urn:stack:assurance:customer-asserted-capacity',
      };
    }

    if (envelope['ceremony_type'] !== 'authority_decision_evidence') {
      throw new Error('Authority decision evidence type is invalid');
    }
    const mandateTermsDigest = text(envelope['mandate_terms_digest'], 'Mandate terms digest');
    return {
      ...base,
      normalizedFacts: {
        mandate_terms_digest: mandateTermsDigest,
        decision_purpose: text(envelope['decision_purpose'], 'Decision purpose'),
      },
      verificationMethod: 'stack:authority-ceremony/1',
      assuranceUri: 'urn:stack:assurance:provider-verified-human-decision',
      mandateTermsDigest,
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

export const STACK_IDENTITY_AUTHORITY_ADAPTER_KEY = ADAPTER_KEY;
export const STACK_IDENTITY_AUTHORITY_ADAPTER_VERSION = ADAPTER_VERSION;
