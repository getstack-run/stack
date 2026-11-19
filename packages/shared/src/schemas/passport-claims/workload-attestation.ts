import { z } from 'zod';

/**
 * workload_attestation — typed passport claim recording that a
 * non-SPIFFE workload-identity token was accepted as the attestation
 * root for a passport. Part of the Signed Primitive epic.
 *
 * Generalises svid_attestation: WIMSE (Workload Identity in Multi-
 * System Environments — IETF working group) and future workload-
 * attestation formats that don't follow the SPIFFE URI scheme attach
 * via this claim type instead.
 *
 * Distinct from svid_attestation:
 *   - workload_id is a generic URI (the WIT `sub`), not constrained
 *     to spiffe://<trust_domain>/<path>
 *   - trust anchor is the issuer URI itself (issuer claim), no
 *     trust_domain concept
 *   - confirmation_jwk records the WIT `cnf` claim if present (for
 *     proof-of-possession audit; PoP verification itself is a v2
 *     follow-up, see workload route notes)
 *
 * Carries no PII. Workload identity is runtime-property identity.
 */
export const WorkloadAttestationClaim = z.object({
  type: z.literal('workload_attestation'),
  workload_id: z.string(),                       // WIT `sub` — URI identifying the workload
  issuer: z.string(),                            // WIT `iss` — issuer URI (must match wimse_issuers.issuer_uri)
  audience: z.string().optional(),               // WIT `aud` if present
  not_after_token: z.number(),                   // unix ts (from WIT `exp`)
  attested_at: z.number(),                       // unix ts when STACK accepted the WIT
  token_format: z.enum(['wimse-wit']),           // future formats added additively
  confirmation_jwk: z.record(z.unknown()).optional(), // WIT `cnf` JWK; recorded but not verified in v1
});
export type WorkloadAttestationClaim = z.infer<typeof WorkloadAttestationClaim>;
