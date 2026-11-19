/**
 * Claim envelope — the SCITT Signed Statement structure that every
 * claim attaches to the passport as.
 *
 * Wire format: COSE_Sign1 (locked 2026-05-12, see
 * the claims registry design design decision Q1).
 * COSE conformance with the SCITT spec is the unlock for "any
 * SCITT-compatible verifier accepts STACK claims natively, zero
 * STACK-specific adapter."
 *
 * Cryptographic serialization to COSE_Sign1 happens at signing time
 * in `packages/vault/src/crypto/claim-signer.ts` ( work, not
 * shipped yet at the time of this file). This file describes the
 * LOGICAL envelope shape; the wire bytes are produced by signing
 * the canonical-JSON form of this envelope as a COSE_Sign1 payload.
 *
 * Signing algorithm is pluggable. v1 ships `alg: "EdDSA"` (matching
 * passport signing). Envelope accepts `alg: "ML-DSA-65"` (NIST FIPS
 * 204 post-quantum) when the JOSE/COSE draft lands at RFC.
 *
 * Schema-versioning rule: envelope structure additive-only for 24
 * months from each `envelope_version`'s first ship date. Breaking
 * changes require a new `envelope_version` AND a published migration
 * window AND a re-sign of affected historical claims. See ADR
 * decision Q4.
 */
import { z } from 'zod';
import { ClaimType } from './types.js';
import { SubjectURI } from './subject.js';
import { Receipt } from './receipt.js';

/**
 * Co-signature on a claim envelope. The primary signer wraps the
 * envelope in a COSE_Sign1; any number of additional signers can
 * independently sign the same payload bytes and attach their signature
 * here. Each entry is a standalone COSE_Sign1 message signing the same
 * canonical payload_bytes the primary signed.
 *
 * of the Signed Primitive epic. ADR
 * Design Decision 1.
 *
 * Verifier flow: primary signature is verified via the existing
 * `ClaimSigner.verify(primaryCose, ...)` path. Co-signatures are
 * verified independently — each `cose_sign1` decodes to a standalone
 * COSE_Sign1; the verifier checks its protected header matches
 * `signer_kid`, resolves the kid via JWKS, and verifies the signature
 * against the same payload bytes as the primary.
 *
 * Storage shape: co_signatures live ALONGSIDE the primary `envelope_cose`
 * in the claim registry (separate column lands in). The
 * primary's claim_hash = sha256(envelope_cose) stays stable when
 * co-signatures are appended; co-signatures don't enter the audit-chain
 * hash binding. This means a co-signature can be added or revoked
 * post-issuance without invalidating the primary's signature OR the
 * audit chain's integrity check.
 *
 * Threat model:
 * - Primary signature attests "this envelope was issued by the
 *   primary signer."
 * - Each co-signature attests "this co-signer ALSO signed this exact
 *   envelope."
 * - Stripping a co-signature does NOT break the primary (the primary
 *   doesn't cover co-signatures). This is intentional — co-signatures
 *   are additive attestations, not load-bearing structural fields.
 * - Appending a fake co-signature fails ITS OWN verification (the
 *   attacker can't sign with the co-signer's key). The verifier
 *   reports it as `valid: false` for that co-signature; the primary
 *   stays valid.
 *
 * `signer_role` distinguishes WHY the co-signer attached their
 * signature:
 * - `operator_attestation`: STACK as the operator-side authority
 *   attesting that the action was allowed under the passport's policy.
 *   Used in `co_signed` mode where both the agent's
 *   key and the operator's key sign the same Intent envelope.
 * - `agent_self`: An agent attesting an envelope that was primarily
 *   signed by STACK on its behalf. Used as a future bridge from
 *   `stack_managed` mode to `customer_managed` mode when an agent
 *   acquires its own key after the envelope was already issued.
 * - `witness`: An independent third party (federated registry,
 *   regulator's witness, partner operator) attesting that they
 *   observed this envelope at a specific point in time. Reserved
 *   transparency-log dual-publishing and future
 *   federated-witness work.
 */
export const CoSignature = z.object({
  /**
   * The kid of the co-signer's key. Must match an entry in some
   * operator's JWKS so verifiers can resolve the pubkey.
   */
  signer_kid: z.string().min(1),

  /**
   * Why this signer attached a signature. Determines downstream
   * semantic interpretation (operator-attestation gates differently
   * than witness-observation).
   */
  signer_role: z.enum(['operator_attestation', 'agent_self', 'witness']),

  /**
   * Standalone base64url-encoded COSE_Sign1 message signed by the
   * co-signer over the same canonical payload_bytes as the primary.
   * Decodes to a 4-element CBOR array per RFC 9052 §4.2.
   */
  cose_sign1: z.string().min(1),
});
export type CoSignature = z.infer<typeof CoSignature>;

/**
 * The envelope every passport claim is wrapped in. The `payload`
 * field carries the typed claim body, validated separately against
 * the schema registered for the envelope's `claim_type` via
 * `PASSPORT_CLAIM_SCHEMAS` in `./index.ts`.
 *
 * Fields:
 *
 * - `envelope_version` (1) — schema version of the envelope itself.
 *   Bumps require migration. v1 is the only ever-shipped version
 *   while the additive-only rule holds.
 *
 * - `issuer` — STACK operator identifier (`op_*`). Identifies which
 *   operator's signing key was used. Verifier looks this up in the
 *   operator's JWKS at `/.well-known/jwks.json` keyed by `kid` from
 *   the COSE protected header.
 *
 * - `subject` — what the claim is about. `stack://operator/{op_id}/
 *   passport/{ppt_jti}`; future claim types may target
 *   other subject paths. See `./subject.ts`.
 *
 * - `issued_at` — unix ms timestamp when the envelope was signed.
 *   Inside the signed payload so cannot be tampered after issuance.
 *
 * - `claim_type` — discriminator identifying which typed payload is
 *   inside. Must be a name registered in `./types.ts`. Verifier
 *   selects the payload validator by this field.
 *
 * - `claim_version` — schema version of this specific claim type's
 *   payload. Bumps when a claim type's payload schema changes per
 *   the additive-only rule. v1 of every claim type today.
 *
 * - `payload` — opaque-at-envelope-level. Validated by the claim
 *   type's registered Zod schema in `ClaimRegistryService.register-
 *   Claim()`. Service rejects with SchemaValidationError on payload
 *   shape mismatch.
 *
 * - `receipt` — proof of registration with a Transparent Registry.
 *   `null` (no registry yet). Populated when
 *   the claim is published to Rekor or STACK's own SCITT-conformant
 *   log. See `./receipt.ts`.
 */
export const ClaimEnvelope = z.object({
  envelope_version: z.literal(1),
  issuer: z.string().regex(/^op_[\w-]+$/, 'issuer must be an operator id'),
  subject: SubjectURI,
  issued_at: z.number().int(),
  claim_type: ClaimType,
  claim_version: z.number().int().min(1),
  payload: z.unknown(),
  receipt: Receipt.nullable(),

  /**
   * Optional additional signatures from co-signers. Each entry is an
   * independent COSE_Sign1 over the same canonical payload bytes as
   * the primary signature. Logical-level field — physically stored
   * alongside the primary envelope_cose in a separate column (lands
   * when co_signed mode wires up) so the primary's
   * claim_hash stays stable.
   *
   * (ADR Design Decision 1). See
   * `CoSignature` above for full threat model + semantic notes.
   *
   * Default empty array (no co-signatures attached). Adding a
   * co-signature is purely additive — never changes the primary
   * signature artifact.
   */
  co_signatures: z.array(CoSignature).default([]),
});
export type ClaimEnvelope = z.infer<typeof ClaimEnvelope>;

/**
 * Helper: build a v1 envelope around a typed payload. Does NOT sign
 * — signing happens in `packages/vault/src/crypto/claim-signer.ts`
 * which consumes this object, canonicalises it, and produces a
 * COSE_Sign1 message.
 *
 * Callers in `ClaimRegistryService.registerClaim()`:
 *   const env = buildClaimEnvelope({
 *     issuer: operatorId,
 *     subject: subjectForPassport(operatorId, passportJti),
 *     claim_type: 'svid_attestation',
 *     claim_version: 1,
 *     payload: validatedSvidAttestationBody,
 *   });
 *   const signedCoseSign1 = await claimSigner.sign(env, { alg: 'EdDSA' });
 */
export function buildClaimEnvelope(input: {
  issuer: string;
  subject: string;
  claim_type: ClaimType;
  claim_version: number;
  payload: unknown;
}): ClaimEnvelope {
  return {
    envelope_version: 1,
    issuer: input.issuer,
    subject: input.subject,
    issued_at: Date.now(),
    claim_type: input.claim_type,
    claim_version: input.claim_version,
    payload: input.payload,
    receipt: null,
    co_signatures: [],
  };
}
