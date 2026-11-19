import type { WorkloadAttestationClaim } from '@stack/shared';
import { WimseWitValidator, type WimseIssuerConfig } from '../wimse-wit-validator.js';

/**
 * WIMSE workload-identity provider — accepts WIMSE Workload Identity
 * Token (WIT) bearers at the workload route boundary and produces a
 * verified workload_attestation claim ready to attach to a passport.
 *
 * Standalone in v1, intentionally NOT implementing the SPIFFE-shaped
 * WorkloadIdentityProvider interface. Both providers share the same
 * category (token-in, attestation-out) but the SPIFFE interface's
 * spiffe_id-shaped result and acceptSvid method name don't fit WIMSE
 * cleanly. A common interface is a cleanup item once OIDC
 * lands and we have three workload-attestation
 * shapes to unify against.
 *
 * The provider does NOT hold any operator/agent mapping logic — that
 * belongs in the route layer (/v1/workload/wit) which fetches the
 * issuer config from the DB and consults the
 * workload_id_mapping_policy_json field.
 */
export class WimseWorkloadProvider {
  readonly providerKey = 'wimse';
  readonly displayName = 'WIMSE (Workload Identity)';
  readonly claimTypes = ['verified_workload'] as const;

  constructor(private validator: WimseWitValidator) {}

  /**
   * Validate a WIT bearer and build the workload_attestation claim.
   * Throws WimseValidationError on validation failure (caller maps to
   * HTTP error in the route layer).
   */
  async acceptWit(token: string, config: WimseIssuerConfig): Promise<WimseAcceptResult> {
    const result = await this.validator.validateWit(token, config);

    const attestation_claim: WorkloadAttestationClaim = {
      type: 'workload_attestation',
      workload_id: result.workload_id,
      issuer: result.issuer,
      ...(result.audience !== undefined ? { audience: result.audience } : {}),
      not_after_token: result.not_after,
      attested_at: Math.floor(Date.now() / 1000),
      token_format: 'wimse-wit',
      ...(result.confirmation_jwk !== undefined
        ? { confirmation_jwk: result.confirmation_jwk as Record<string, unknown> }
        : {}),
    };

    return {
      workload_id: result.workload_id,
      issuer: result.issuer,
      audience: result.audience,
      not_after: result.not_after,
      attestation_claim,
    };
  }
}

export interface WimseAcceptResult {
  workload_id: string;
  issuer: string;
  audience?: string;
  not_after: number;
  attestation_claim: WorkloadAttestationClaim;
}
