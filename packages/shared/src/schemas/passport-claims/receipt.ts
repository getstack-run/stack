/**
 * Receipt schema for the claim envelope.
 *
 * A receipt is proof that a claim has been registered with a
 * Transparent Registry (Sigstore Rekor v2; a self-hosted
 * Rekor as fallback; possibly a STACK-operated SCITT transparent
 * service when shipped). carries `receipt: null` on every
 * claim — the registry infrastructure does not exist yet.
 *
 * Shape is deliberately rich to absorb every documented
 * transparency-log receipt format we may need across-5
 * WITHOUT requiring an envelope-version bump. The `proof.format`
 * enum + opaque `proof.bytes` is the escape hatch for any format we
 * have not anticipated — same pattern Sigstore uses with
 * `canonicalized_body`.
 *
 * Locked 2026-05-12 per the claims registry design
 * design decision Q3.
 */
import { z } from 'zod';

/**
 * Inline cryptographic proof of registration. always null
 * populates `format='stack-merkle-v1'`
 * cross-witness adds a `rekor-v2-tle` entry to the `witnesses` array.
 *
 * `bytes` carries the full proof in its native format
 * (base64url-encoded). Verifiers select the right parser based on
 * `format`. Hash + path fields are surfaced for convenience and quick
 * lookup; the canonical proof IS the `bytes`.
 */
export const ReceiptProof = z.object({
  format: z.enum([
    'scitt-cose-receipt',  // SCITT receipt as defined in draft-ietf-scitt-architecture
    'rekor-v2-tle',        // Sigstore Rekor v2 TransparencyLogEntry proto
    'stack-merkle-v1',     // STACK-operated Merkle log
  ]),
  bytes: z.string(),                       // base64url-encoded native proof
  log_index: z.number().int().nullable(),
  tree_size: z.number().int().nullable(),
  root_hash: z.string().nullable(),        // base64url-encoded Merkle root
});
export type ReceiptProof = z.infer<typeof ReceiptProof>;

/**
 * Cross-witness from a parallel transparency log.
 * dual-publishing puts the same chain head into multiple logs so a
 * single registry going dark does not break verifiability. First
 * additional witness is `rekor:public` (public Sigstore Rekor) on
 * top of STACK's own log.
 */
export const ReceiptWitness = z.object({
  registry: z.string(),                  // e.g. "rekor:public", "rekor:stack-eu"
  registry_entry_uri: z.string(),
  proof_bytes: z.string().nullable(),    // independent witness's own proof
});
export type ReceiptWitness = z.infer<typeof ReceiptWitness>;

/**
 * The receipt itself. `receipt` is `Receipt | null` on the envelope
 * — `null` whenever the claim has not (yet) been registered with any
 * transparent log.
 */
export const Receipt = z.object({
  registry: z.string(),                    // canonical registry identifier
  registered_at: z.number().int(),         // unix ms
  registry_entry_uri: z.string().nullable(),
  proof: ReceiptProof.nullable(),
  witnesses: z.array(ReceiptWitness).nullable(),
});
export type Receipt = z.infer<typeof Receipt>;
