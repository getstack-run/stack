import { z } from 'zod';

/**
 * identity_claim — signed record of an identity verification event.
 *
 * of the Signed Primitive epic. Migration target
 * for the existing `identity_claims` table.
 *
 * **Critical PII discipline:** this envelope carries the PUBLIC shape
 * of an identity verification (layer, assurance level, validity window,
 * a HASH of the provider assertion). NO PII fields. The legacy
 * `identity_claims` table is exempt from any future "drop legacy"
 * sweep — it remains the encrypted-PII source-of-truth via
 * `payload_encrypted` (KMS-bound under the operator's CMEK when active).
 *
 * **Subject scope:** identity_claim is OPERATOR-scoped, not passport-
 * scoped. The envelope's subject URI is `stack://operator/{op_id}`
 * (via `subjectForOperator`) rather than the passport URI. Passport-
 * issuance still embeds identity claim refs (PII resolution server-side
 * via `resolvePii`) — that path is unchanged.
 */
export const IdentityClaim = z.object({
  type: z.literal('identity_claim'),

  /** identity_claims.id — the legacy row this claim mirrors. */
  identity_claim_row_id: z.string(),

  /** Provider key. Examples: 'cloudflare_turnstile', 'stripe_identity'. */
  provider_key: z.string(),

  /** Verification layer. */
  layer: z.enum(['humanity', 'identity', 'delegation']),

  /**
   * Provider-emitted claim_type. Free-form string — providers use
   * different vocabularies (e.g. 'verified_human', 'verified_identity',
   * 'delegated_authority'). Catalog membership is NOT validated here;
   * producer-side discipline preserves consistency.
   */
  claim_type: z.string(),

  /** RFC 8485 assurance. */
  assurance_level: z.enum(['low', 'substantial', 'high']),

  /** unix ms — when the provider asserted verification. */
  verified_at: z.number().int(),

  /**
   * unix ms — when the verification expires per provider policy + the
   * operator's identity_claim_ttl setting (capped server-side). After
   * expiry the claim no longer satisfies L1/L2 trust requirements.
   */
  expires_at: z.number().int(),

  /**
   * SHA-256 of the encrypted provider assertion bytes. Binds the
   * envelope to the assertion stored in identity_claims.assertion_encrypted
   * without revealing its content. A verifier with access to the legacy
   * row can confirm assertion integrity by hashing the ciphertext and
   * comparing.
   */
  assertion_hash: z.string().regex(/^[0-9a-f]{64}$/, 'assertion_hash must be 64 hex chars (sha256)'),

  /**
   * Layer 3 (delegation) only — the granted scope strings. Empty for
   * humanity/identity claims.
   */
  delegated_scopes: z.array(z.string()).optional(),
});

export type IdentityClaim = z.infer<typeof IdentityClaim>;
