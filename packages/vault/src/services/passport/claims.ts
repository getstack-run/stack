import {
  ids,
  computePassportClaimHash,
  ForbiddenError,
  NotFoundError,
  PassportRevokedError,
  PASSPORT_CLAIM_SCHEMAS,
  SchemaValidationError,
  type PassportClaim,
  type PassportClaimType,
} from '@stack/shared';
import type { PassportContext } from './types.js';

/**
 * Attach a typed claim to a passport via the claim registry.
 *
 * Flow:
 *   1. Validate body against PASSPORT_CLAIM_SCHEMAS[type] (Zod gate).
 *   2. Compute deterministic claim_hash binding (passport_id, type, body).
 *   3. Sign the attachment via the passport signer's EdDSA key.
 *      The signature is a compact JWS fetchable verifiers can verify
 *      against /.well-known/jwks.json.
 *   4. Insert into passport_claims (append-only with soft-revoke).
 *
 * The route layer follows attach with an audit.write call; the audit
 * service auto-resolves passport_claims_at_event from the claims
 * repo at write time, so the chain entry hashes-in the new
 * claim alongside any pre-existing ones on the passport.
 */
export async function attachPassportClaim(
  ctx: PassportContext,
  passportId: string,
  claim: PassportClaim,
) {
  if (claim.type === 'intent_claim' && claim.policy_decision) throw new ForbiddenError();

  // Belt-and-braces: validate via the registered schema even though
  // the typed input is Zod-derived. Defensively rejects bodies that
  // bypass type checking (e.g. JSON deserialization at the route).
  const schema = PASSPORT_CLAIM_SCHEMAS[claim.type as PassportClaimType];
  if (!schema) {
    throw new SchemaValidationError({
      reason: 'unknown_claim_type',
      type: claim.type,
    });
  }
  const parsed = schema.safeParse(claim);
  if (!parsed.success) {
    throw new SchemaValidationError({
      reason: 'invalid_claim_body',
      type: claim.type,
      zod_issues: parsed.error.issues,
    });
  }

  // Confirm the passport exists and is not already revoked.
  const passport = await ctx.passportRepo.findByJti(passportId);
  if (!passport) throw new NotFoundError('Passport', passportId);
  if (passport.revoked_at) throw new PassportRevokedError();

  const claimId = ids.passportClaim();
  // The body persisted to body_json is the validated claim with
  // `type` stripped: the type lives in its own column. Storing it
  // both places would invite drift between column and json.
  const { type: _type, ...body } = parsed.data;
  void _type;
  const claimHash = computePassportClaimHash({
    passport_id: passportId,
    type: claim.type,
    body: body as Record<string, unknown>,
  });
  const signature = await ctx.signer.signClaimAttachment({
    claim_id: claimId,
    passport_id: passportId,
    claim_hash: claimHash,
    type: claim.type,
  });

  const attachedAt = new Date();
  const row = await ctx.passportClaimsRepo.insert({
    claim_id: claimId,
    passport_id: passportId,
    type: claim.type,
    body_json: body as Record<string, unknown>,
    claim_hash: claimHash,
    signature,
    attached_at: attachedAt,
  });

  return {
    claim_id: row.claim_id,
    claim_hash: row.claim_hash,
    signature: row.signature,
    attached_at: row.attached_at,
  };
}
