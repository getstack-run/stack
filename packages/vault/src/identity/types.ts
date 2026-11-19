import type { AssuranceLevel, TrustLayer, SvidAttestationClaim } from '@stack/shared';

// ─── Provider Contract ──────────────────────────────────────────────

/**
 * Every identity provider implements this interface.
 * Stripe Identity and Cloudflare Turnstile plug in identically.
 */
export interface IdentityVerificationProvider {
  /** Unique key matching identity_providers.provider_key in DB */
  readonly providerKey: string;

  /** Human-readable name */
  readonly displayName: string;

  /** What claim types this provider can assert */
  readonly claimTypes: readonly string[];

  /** Which trust layers this provider supports */
  readonly supportedLayers: readonly TrustLayer[];

  /** Provider's assurance level */
  readonly assuranceLevel: AssuranceLevel;

  /**
   * Opt-in capability for the human-operated Connect verification surface.
   * Absence is fail-closed: workload providers, enterprise federation, and
   * development mocks never become startable only because a catalog row is
   * active.
   */
  readonly connect?: {
    readonly flow: 'inline' | 'redirect';
    readonly requestedClaim: 'verified_human' | 'verified_identity';
  };

  /** Start a verification flow. Returns a session the operator completes externally. */
  initiate(operatorId: string, context: VerificationContext): Promise<InitiateResult>;

  /**
   * Complete verification — called after provider callback or polling.
   * Returns signed assertions for each claim type the provider verified.
   */
  complete(operatorId: string, sessionRef: string): Promise<VerificationResult>;

  /** Validate an existing assertion is still valid (re-verification). */
  validateAssertion?(assertion: string): Promise<boolean>;
}

// ─── Flow Types ─────────────────────────────────────────────────────

export interface VerificationContext {
  /** Where to redirect after verification (for browser-based flows) */
  return_url?: string;
  /** Which claim types the operator wants verified */
  requested_claims: string[];
  /**
   * Server-authored purpose for a verification that belongs to a larger
   * ceremony. Providers may echo this as opaque metadata; callers cannot use
   * it to claim a verification result or assurance level.
   */
  purpose?: {
    kind: 'authority';
    request_id: string;
  };
}

export interface InitiateResult {
  /** Opaque reference to the verification session (provider-specific) */
  session_ref: string;
  /** URL the operator visits to perform verification */
  verification_url?: string;
  /** QR code data for mobile app flows (e.g. a national e-ID app's autostart) */
  qr_code?: string;
  /** When this verification session expires */
  expires_at: Date;
}

export interface VerificationResult {
  success: boolean;
  /** One entry per claim type the provider verified */
  claims: VerifiedClaim[];
  /** Provider-specific raw response — stored encrypted for audit/debug */
  raw_response?: unknown;
}

export interface VerifiedClaim {
  /** e.g. "verified_human", "verified_identity" */
  claim_type: string;
  /** Which trust layer: humanity (L1), identity (L2), delegation (L3) */
  layer: TrustLayer;
  /** Provider-signed proof (JWS compact, opaque token, or structured assertion) */
  assertion: string;
  /** Assurance level of this specific claim */
  assurance_level: AssuranceLevel;
  /** When the provider verified this claim */
  verified_at: Date;
  /** When the assertion expires */
  expires_at: Date;
  /** Provider-specific metadata. For Layer 2, includes `pii` sub-object. */
  metadata?: Record<string, unknown>;
}

// ─── Workload Identity Provider (sibling shape, P1.4+) ─────────────
//
// SPIFFE/SPIRE and similar attestation systems (AWS IAM Roles Anywhere,
// GCP Workload Identity Federation, ...) do not fit the human-in-the-
// loop initiate/complete shape: the workload presents a token directly
// at the API boundary, with no prior session. This sibling interface
// captures that flow.
//
// A single method — `acceptSvid` — takes the presented token plus the
// resolved trust-domain config (the route layer is the lookup owner)
// and returns the verified workload identity facts plus a pre-built
// svid_attestation claim ready to attach to a passport via the claim
// registry.
//
// Pluggable so future workload-attestation providers can register here
// without inheriting the human-flow interface.

export interface WorkloadIdentityProvider {
  readonly providerKey: string;          // matches identity_providers.provider_key
  readonly displayName: string;
  readonly claimTypes: readonly string[]; // ['verified_workload']
  readonly supportedLayers: readonly TrustLayer[]; // ['workload']
  readonly assuranceLevel: AssuranceLevel;

  /**
   * Validate a presented workload token (e.g. JWT-SVID Bearer) and
   * return the verified identity facts. Throws on validation failure
   * (caller catches and maps to HTTP error in the route layer).
   *
   * The `config` argument is provider-specific; for SPIFFE it is the
   * resolved spiffe_trust_domains row. The caller (route) owns lookup.
   */
  acceptSvid(
    token: string,
    config: WorkloadProviderConfig,
  ): Promise<WorkloadAcceptResult>;
}

/**
 * Provider-specific trust-anchor config. Discriminated by `kind` so
 * future workload providers (aws-iam-roles-anywhere, gcp-workload-
 * identity-federation, ...) carry their own shape without polluting
 * the SPIFFE one.
 */
export type WorkloadProviderConfig = {
  kind: 'spiffe';
  // Subset of spiffe_trust_domains row the SPIFFE provider needs.
  // Structurally compatible with the trust-domain repo's row shape.
  id: string;
  trust_domain: string;
  jwks_uri: string;
  audience: string | null;
  jwks_cache_ttl_seconds: number;
  jwks_cached_jwks_json: { keys: unknown[] } | null;
};

export interface WorkloadAcceptResult {
  spiffe_id: string;            // for SPIFFE; future providers may rename
  trust_domain: string;
  not_after: number;            // unix seconds; passport TTL ≤ this
  issuer: string;
  audience?: string;
  /** Pre-built typed claim ready to attach via passport-service.attachClaim. */
  attestation_claim: SvidAttestationClaim;
}

// ─── Claim Matching ─────────────────────────────────────────────────

export interface ServiceRequirementRecord {
  id: string;
  service_id: string;
  layer: TrustLayer;
  requires_claim: string;
  minimum_assurance: AssuranceLevel;
  accepted_providers: string[];
  required_scopes?: string[];    // Layer 3 — which delegated scopes are needed
  requires_pii: boolean;          // Must be true for Layer 2
  lawful_basis?: string | null;   // GDPR lawful basis when requires_pii = true
}

export interface ClaimMatchResult {
  /** Whether all service requirements are satisfied */
  satisfied: boolean;
  /** Which claim satisfied which requirement */
  matches: ClaimMatch[];
  /** Requirements that had no matching claim */
  unmet: ServiceRequirementRecord[];
}

export interface ClaimMatch {
  requirement: ServiceRequirementRecord;
  claim: { provider: string; claim_type: string; assurance_level: AssuranceLevel };
}
