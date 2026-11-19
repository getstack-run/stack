import type { JWK } from 'jose';
import type { TrustLayer, AssuranceLevel, SvidAttestationClaim } from '@stack/shared';
import type {
  WorkloadIdentityProvider,
  WorkloadProviderConfig,
  WorkloadAcceptResult,
} from '../types.js';
import { SpiffeSvidValidator, type TrustDomainConfig } from '../spiffe-svid-validator.js';

/**
 * SPIFFE/SPIRE workload-identity provider — accepts JWT-SVID Bearer
 * tokens at the workload route boundary and produces a verified
 * svid_attestation claim ready to attach to a passport.
 *
 * The provider holds the validator (cryptographic gate) but does NOT
 * hold any operator/agent mapping logic — that belongs in the route
 * layer (P1.7) where the trust-domain config is fetched from the DB
 * and the SPIFFE-ID-to-agent map is consulted.
 *
 * JWT-SVID Bearer only (svid_format = 'jwt-svid'). X.509-SVID
 * mTLS is not supported.
 */
export class SpiffeWorkloadProvider implements WorkloadIdentityProvider {
  readonly providerKey = 'spiffe';
  readonly displayName = 'SPIFFE / SPIRE';
  readonly claimTypes = ['verified_workload'] as const;
  readonly supportedLayers: readonly TrustLayer[] = ['workload'];
  readonly assuranceLevel: AssuranceLevel = 'high';

  constructor(private validator: SpiffeSvidValidator) {}

  async acceptSvid(token: string, config: WorkloadProviderConfig): Promise<WorkloadAcceptResult> {
    if (config.kind !== 'spiffe') {
      throw new Error(`SpiffeWorkloadProvider received non-spiffe config kind="${config.kind}"`);
    }

    const validatorConfig: TrustDomainConfig = {
      id: config.id,
      trust_domain: config.trust_domain,
      jwks_uri: config.jwks_uri,
      audience: config.audience,
      jwks_cache_ttl_seconds: config.jwks_cache_ttl_seconds,
      // The repo row's last-known-good is stored as parsed JSON of a
      // JWKS shape. Cast through unknown is safe — the validator
      // re-checks `keys` is an array before use.
      jwks_cached_jwks_json: config.jwks_cached_jwks_json
        ? (config.jwks_cached_jwks_json as { keys: JWK[] })
        : null,
    };

    const result = await this.validator.validateJwtSvid(token, validatorConfig);

    const attestation_claim: SvidAttestationClaim = {
      type: 'svid_attestation',
      spiffe_id: result.spiffe_id,
      trust_domain: result.trust_domain,
      not_after_svid: result.not_after,
      issuer: result.issuer,
      attested_at: Math.floor(Date.now() / 1000),
      svid_format: 'jwt-svid',
    };

    return {
      spiffe_id: result.spiffe_id,
      trust_domain: result.trust_domain,
      not_after: result.not_after,
      issuer: result.issuer,
      audience: result.audience,
      attestation_claim,
    };
  }
}
