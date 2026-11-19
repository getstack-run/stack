import { z } from 'zod';
import {
  SSO_DOMAIN_CHECK_RESULTS,
  SSO_DOMAIN_STATUSES,
  SSO_JWKS_CACHE_MAX_SECONDS,
  SSO_JWKS_CACHE_MIN_SECONDS,
} from '../constants/sso-login.js';

// ─── Assurance Level ────────────────────────────────────────────────

export const AssuranceLevel = z.enum(['low', 'substantial', 'high']);
export type AssuranceLevel = z.infer<typeof AssuranceLevel>;

// ─── Trust Layers ───────────────────────────────────────────────────
//
// Layer 1 — Proof of Humanity:    "a verified human backs this agent"
// Layer 2 — Proof of Identity:    "this specific person backs this agent" (PII)
// Layer 3 — Proof of Delegation:  "this person authorized these specific actions"
// Workload — Proof of Workload Attestation:
//                                  "this agent is running inside an attested
//                                  workload (SPIFFE/SPIRE)". Complementary to
//                                  the human-trust ladder above, NOT on it.
//                                  Anchors identity to runtime properties
//                                  (k8s SA, mTLS-bound process, image hash).

export const TrustLayer = z.enum(['humanity', 'identity', 'delegation', 'workload']);
export type TrustLayer = z.infer<typeof TrustLayer>;

// `workload` is rank 0 because it answers a different question from the
// human-identity ladder (humanity/identity/delegation). It must not be
// compared on that scale — a workload claim does not "satisfy" an L1
// humanity requirement. Rank exists for the human-ladder ordering only;
// any future workload-vs-workload comparison should use a separate axis.
export const TRUST_LAYER_RANK: Record<TrustLayer, number> = {
  workload: 0,
  humanity: 1,
  identity: 2,
  delegation: 3,
};

// ─── Claim Payloads (per layer) ─────────────────────────────────────

/** Layer 1 — boolean proof of humanity, no PII */
export const HumanityClaimPayload = z.object({
  layer: z.literal('humanity'),
  verified: z.literal(true),
  assurance_level: AssuranceLevel,
});
export type HumanityClaimPayload = z.infer<typeof HumanityClaimPayload>;

/** Layer 2 — specific identity, contains PII. Never embedded in JWT. */
export const IdentityClaimPayload = z.object({
  layer: z.literal('identity'),
  verified: z.literal(true),
  assurance_level: AssuranceLevel,
  full_name: z.string(),
  national_id_hash: z.string(),       // SHA-256 hash — never store raw national ID
  date_of_birth: z.string(),           // YYYY-MM-DD
  issuing_country: z.string(),         // ISO 3166-1 alpha-2
  id_document_type: z.string(),        // "national_id" | "passport"
});
export type IdentityClaimPayload = z.infer<typeof IdentityClaimPayload>;

/** Layer 3 — delegated authority scopes. Separate consent step from identity. */
export const DelegationClaimPayload = z.object({
  layer: z.literal('delegation'),
  verified: z.literal(true),
  delegated_scopes: z.array(z.string()),    // e.g. ["tax:file", "tax:read"]
  delegated_by: z.string(),                  // national_id_hash of authorising human
  delegated_at: z.number(),                  // unix timestamp
  expires_at: z.number(),
});
export type DelegationClaimPayload = z.infer<typeof DelegationClaimPayload>;

/** Union of all claim payloads */
export const ClaimPayload = z.discriminatedUnion('layer', [
  HumanityClaimPayload,
  IdentityClaimPayload,
  DelegationClaimPayload,
]);
export type ClaimPayload = z.infer<typeof ClaimPayload>;

// ─── Stored Claims (DB record) ─────────────────────────────────────

export const StoredIdentityClaim = z.object({
  id: z.string(),
  operator_id: z.string(),
  provider_id: z.string(),
  provider_key: z.string(),
  layer: TrustLayer,
  claim_type: z.string(),
  assurance_level: AssuranceLevel,
  verified_at: z.date(),
  expires_at: z.date(),
  assertion_encrypted: z.string(),  // KMS-encrypted provider assertion
  payload_encrypted: z.string(),    // KMS-encrypted claim payload (PII for Layer 2)
  revoked_at: z.date().nullable(),
});
export type StoredIdentityClaim = z.infer<typeof StoredIdentityClaim>;

// ─── Passport Claim References ──────────────────────────────────────
//
// The passport JWT carries claim REFERENCES, not claim payloads.
// Layer 1: carries the full claim (no PII, safe to embed)
// Layer 2: carries claim_id only — PII resolved server-side during verify
// Layer 3: carries delegated_scopes (no PII) + claim_id for audit
//

export const PassportClaimRef = z.object({
  claim_id: z.string(),             // reference to identity_claims.id
  provider: z.string(),             // provider_key for quick matching
  layer: TrustLayer,
  claim_type: z.string(),           // e.g. "verified_human", "verified_identity", "delegated_authority", "verified_workload"
  assurance_level: AssuranceLevel,
  verified_at: z.number(),
  expires_at: z.number(),
  // Layer 1 only — safe to embed
  humanity_verified: z.boolean().optional(),
  // Layer 3 only — no PII, safe to embed
  delegated_scopes: z.array(z.string()).optional(),
  // Workload only — workload identity is not personal data, safe to embed.
  // The full attestation lives as a typed claim attached via the passport
  // claim registry (see passport-claims/svid-attestation).
  spiffe_id: z.string().optional(),
  trust_domain: z.string().optional(),
  not_after_svid: z.number().optional(),  // unix ts; passport TTL ≤ this
  // Layer 2 PII is NEVER here — resolved server-side
});
export type PassportClaimRef = z.infer<typeof PassportClaimRef>;

// ─── Service Identity Requirements ─────────────────────────────────

export const ServiceIdentityRequirement = z.object({
  id: z.string(),
  service_id: z.string(),
  layer: TrustLayer,
  requires_claim: z.string(),                      // e.g. "verified_human", "verified_identity"
  minimum_assurance: AssuranceLevel,
  accepted_providers: z.array(z.string()),          // empty = any provider
  required_scopes: z.array(z.string()).optional(),   // for Layer 3 delegation matching
  requires_pii: z.boolean().default(false),          // must be true for Layer 2
  lawful_basis: z.string().optional(),               // GDPR lawful basis when requires_pii = true
});
export type ServiceIdentityRequirement = z.infer<typeof ServiceIdentityRequirement>;

// ─── Identity Provider Registry ─────────────────────────────────────

export const IdentityProvider = z.object({
  id: z.string(),
  name: z.string(),                                 // e.g. "Stripe Identity"
  provider_key: z.string(),                          // e.g. "stripe_identity"
  supported_layers: z.array(TrustLayer),             // which layers this provider supports
  claim_types: z.array(z.string()),                  // e.g. ["verified_human", "verified_identity"]
  assurance_level: AssuranceLevel,
  verification_endpoint: z.string().url().optional(),
  jwks_uri: z.string().url().optional(),
  active: z.boolean(),
});
export type IdentityProvider = z.infer<typeof IdentityProvider>;

// ─── Verification flow input schemas ────────────────────────────────

export const InitiateVerificationInput = z.object({
  provider_key: z.string(),
  requested_claims: z.array(z.string()).min(1),
  return_url: z.string().url().optional(),
});
export type InitiateVerificationInput = z.infer<typeof InitiateVerificationInput>;

export const CompleteVerificationInput = z.object({
  provider_key: z.string(),
  session_ref: z.string(),
});
export type CompleteVerificationInput = z.infer<typeof CompleteVerificationInput>;

/**
 * Where a verification session stands. `pending` waits for the person at the provider; `completed` and `failed` are
 * the provider's answer; `expired` is a session nobody finished by its `expires_at`, which is final.
 */
export const IDENTITY_VERIFICATION_SESSION_STATUSES = ['pending', 'completed', 'failed', 'expired'] as const;
export const IdentityVerificationSessionStatus = z.enum(IDENTITY_VERIFICATION_SESSION_STATUSES);
export type IdentityVerificationSessionStatus = z.infer<typeof IdentityVerificationSessionStatus>;

/** One verification session as the API returns it: no provider data and nothing about the person. */
export const IdentityVerificationSessionView = z.object({
  session_id: z.string(),
  provider_key: z.string(),
  session_ref: z.string(),
  status: IdentityVerificationSessionStatus,
  requested_claims: z.array(z.string()),
  created_at: z.string(),
  expires_at: z.string(),
  completed_at: z.string().nullable(),
});
export type IdentityVerificationSessionView = z.infer<typeof IdentityVerificationSessionView>;

// ─── OIDC IdP configuration (enterprise SSO) ────────────────────────

/** Roles a member may be auto-provisioned into by SSO. */
export const SsoDefaultMemberRole = z.enum(['readonly', 'standard', 'admin']);

/**
 * https only, everywhere. An IdP reached over http means the ID token and
 * the client secret cross the wire in clear, which defeats the point of
 * verifying a signature at the other end.
 */
const HttpsUrl = z.string().url().regex(/^https:\/\//, 'must use https://');

/**
 * The slug in /login/sso/<slug>. Lowercase, url-safe, and long enough not
 * to be guessed at random — it is not a secret, but it does name an
 * organisation publicly, so no single characters.
 */
const SsoSlug = z
  .string()
  .min(3)
  .max(63)
  .regex(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/, 'lowercase letters, digits and hyphens only');

export const OidcIdpConfigCreateInput = z.object({
  display_name: z.string().max(120).optional(),
  issuer_uri: HttpsUrl,
  client_id: z.string().min(1).max(512),
  /** Write-only. Never returned by any read path. */
  client_secret: z.string().min(1).max(2048),
  audience: z.string().max(512).optional().nullable(),
  redirect_uri: HttpsUrl,
  scopes: z.array(z.string().min(1)).min(1).optional(),
  claim_mapping_policy: z.record(z.string(), z.unknown()).optional().nullable(),
  jwks_cache_ttl_seconds: z.number().int().min(SSO_JWKS_CACHE_MIN_SECONDS).max(SSO_JWKS_CACHE_MAX_SECONDS).optional(),
  /** Origins a verification handoff may return to. Empty = dashboard only. */
  allowed_return_origins: z.array(HttpsUrl).max(10).optional().nullable(),
  sso_slug: SsoSlug.optional().nullable(),
  /**
   * Deliberately absent from create: a connection is never born enabled.
   * The admin tests it first, then enables it. See the enable input below.
   */
  default_member_role: SsoDefaultMemberRole.optional(),
  active: z.boolean().optional(),
});
export type OidcIdpConfigCreateInput = z.infer<typeof OidcIdpConfigCreateInput>;

export const OidcIdpConfigUpdateInput = OidcIdpConfigCreateInput.partial().extend({
  /**
   * Turning SSO login on is its own explicit field rather than part of the
   * general patch, so it can never be flipped as a side effect of editing
   * an unrelated setting.
   */
  sso_login_enabled: z.boolean().optional(),
});
export type OidcIdpConfigUpdateInput = z.infer<typeof OidcIdpConfigUpdateInput>;

// ─── Verified domains of single sign-on (spec/sso-login/SPEC.md section 9.5) ────────────────────────
//
// An account proves it controls an e-mail domain with a DNS TXT record. The domain is checked and
// normalised by the service (a name that is not one is SSO_DOMAIN_INVALID), so the input is the text.

export const SsoDomainAddInput = z
  .object({
    /** The e-mail domain, such as `corp.example.com`. An exact name: a subdomain is a domain of its own. */
    domain: z.string().min(1).max(253),
  })
  .strict();
export type SsoDomainAddInput = z.infer<typeof SsoDomainAddInput>;

export const SsoDomainStatusEnum = z.enum(SSO_DOMAIN_STATUSES);
export const SsoDomainCheckResultEnum = z.enum(SSO_DOMAIN_CHECK_RESULTS);

/** One domain of an account, with the record that proves it. */
export const SsoDomainView = z.object({
  id: z.string(),
  domain: z.string(),
  status: SsoDomainStatusEnum,
  /** The DNS record to publish: a TXT record at `name` with exactly `value`. */
  record: z.object({ type: z.literal('TXT'), name: z.string(), value: z.string() }),
  verified_at: z.string().nullable(),
  last_checked_at: z.string().nullable(),
  /** What the last lookup found; null before the first one. */
  last_check: SsoDomainCheckResultEnum.nullable(),
  /** Since when the record has been seen missing (null while it is there, or when no lookup has said it is gone). */
  missing_since: z.string().nullable(),
  created_at: z.string(),
});
export type SsoDomainView = z.infer<typeof SsoDomainView>;

export const SsoDomainList = z.object({ domains: z.array(SsoDomainView) });
export type SsoDomainList = z.infer<typeof SsoDomainList>;

/** The answer to a check: the domain as it now stands, and what the lookup found. */
export const SsoDomainCheckResponse = z.object({
  domain: SsoDomainView,
  check: SsoDomainCheckResultEnum,
});
export type SsoDomainCheckResponse = z.infer<typeof SsoDomainCheckResponse>;

export const GrantDelegationInput = z.object({
  delegated_scopes: z.array(z.string()).min(1),      // e.g. ["tax:file", "tax:read"]
});
export type GrantDelegationInput = z.infer<typeof GrantDelegationInput>;

export const SetServiceRequirementInput = z.object({
  layer: TrustLayer,
  requires_claim: z.string(),
  minimum_assurance: AssuranceLevel,
  accepted_providers: z.array(z.string()).default([]),
  required_scopes: z.array(z.string()).optional(),
  requires_pii: z.boolean().default(false),
  lawful_basis: z.string().optional(),
});
export type SetServiceRequirementInput = z.infer<typeof SetServiceRequirementInput>;
