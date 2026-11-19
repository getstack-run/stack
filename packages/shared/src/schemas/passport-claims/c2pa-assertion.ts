import { z } from 'zod';

/**
 * c2pa_assertion — passport claim recording a C2PA Content
 * Credentials (ISO/IEC 22144) signed manifest attached to a piece of
 * content the agent produced. Part of the Signed
 * Primitive epic.
 *
 * The C2PA Manifest itself is content-attached (embedded in the
 * media file or sidecar JSON-LD); STACK records the manifest's
 * identifying digest plus the key signing-info fields here, so an
 * agent's audit trail surfaces which signed manifests it produced.
 *
 * v1 SCOPE — schema only. Composing this claim with proxy-side
 * outbound content signing (the proxy stamps a C2PA manifest onto
 * every generated image / audio / video and attaches this claim to
 * the invocation's passport automatically) is a follow-up. Until
 * then, the customer's agent runtime is expected to produce the
 * manifest externally and submit the reference here.
 *
 * Supports EU AI Act Article 50 (generated-content disclosure) and
 * media-industry provenance requirements.
 */
export const C2paAssertionClaim = z.object({
  type: z.literal('c2pa_assertion'),

  /**
   * Where the C2PA manifest is published, if a separate sidecar
   * artifact. Optional — when null, the manifest is embedded in the
   * content artifact itself (referenced by content_digest).
   */
  manifest_uri: z.string().optional(),

  /** sha256 of the canonical manifest bytes, hex-encoded. */
  manifest_sha256: z.string().regex(/^[0-9a-f]{64}$/, 'must be 64-char hex sha256').optional(),

  /**
   * Free-text identifier of the C2PA toolchain that produced the
   * manifest. Spec recommends a UA-string shape, e.g.
   * 'STACK Proxy/0.5 (c2pa/0.42)'.
   */
  claim_generator: z.string().optional(),

  /**
   * Information about the signing identity. Issuer (CN or x509
   * subject) plus a thumbprint of the certificate that signed the
   * manifest. Full chain verification is a relying-party concern;
   * STACK records what it observed.
   */
  signature_info: z.object({
    issuer: z.string().optional(),
    cert_thumbprint: z.string().regex(/^[0-9a-f]{40,128}$/, 'must be hex thumbprint').optional(),
    signature_alg: z.string().optional(),         // e.g. 'ES256', 'EdDSA'
  }).optional(),

  /**
   * Digest of the content artifact this assertion covers. Keyed by
   * algorithm (sha256, sha512, ...) → hex digest. At least one
   * algorithm required — a C2PA assertion without a content bind is
   * a manifest about nothing.
   */
  content_digest: z.record(z.string(), z.string()).refine(
    (d) => Object.keys(d).length > 0,
    { message: 'content_digest must contain at least one algorithm entry' },
  ),

  /**
   * Optional MIME type of the content, for quick filtering ("which
   * passports produced signed video?").
   */
  content_type: z.string().optional(),

  /** unix ts when STACK accepted the assertion */
  attested_at: z.number(),
});
export type C2paAssertionClaim = z.infer<typeof C2paAssertionClaim>;
