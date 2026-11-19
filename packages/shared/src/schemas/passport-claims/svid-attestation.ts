import { z } from 'zod';

/**
 * svid_attestation — typed passport claim recording that a SPIFFE SVID
 * was accepted as the attestation root for a passport. Attached to a
 * passport via the claim registry (see passport-service.attachClaim).
 *
 * Carries no PII. Workload identity is runtime-property identity, not
 * personal data — safe to surface in audits and exported chains.
 */
export const SvidAttestationClaim = z.object({
  type: z.literal('svid_attestation'),
  spiffe_id: z.string(),                       // spiffe://<trust_domain>/<path>
  trust_domain: z.string(),
  not_after_svid: z.number(),                  // unix ts
  issuer: z.string(),                          // for federated SPIRE
  attested_at: z.number(),                     // unix ts when STACK accepted the SVID
  svid_format: z.enum(['jwt-svid', 'x509-svid']),
});
export type SvidAttestationClaim = z.infer<typeof SvidAttestationClaim>;
