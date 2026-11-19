import { z } from 'zod';

/**
 * rats_evidence — passport claim recording that a hardware- or TEE-
 * rooted Remote Attestation (RFC 9334 RATS) was produced by the
 * attested workload and accepted by STACK as part of the passport's
 * trust evidence. Part of the Signed Primitive epic.
 *
 * The claim records the ATTESTATION RESULT — the verifier's decoded
 * facts about the workload's environment — plus an optional pointer
 * to the original evidence bytes (held off-chain in S3 / IPFS / a
 * transparency log) and a sha256 digest for tamper-evidence.
 *
 * v1 SCOPE — schema and registry surface only. Deep per-TEE evidence
 * verification (AWS Nitro PCR replay against the AWS root cert chain,
 * Intel TDX quote verification, AMD SEV-SNP attestation chain, etc.)
 * is a chunked follow-up per TEE format. The submitting client is
 * expected to verify the evidence before attaching the claim in v1;
 * follow-ups add server-side per-format verifiers.
 *
 * For regulated settings (FedRAMP, EU NIS2, regulated finance)
 * that cannot accept software-only attestation.
 */
export const RatsEvidenceClaim = z.object({
  type: z.literal('rats_evidence'),

  /**
   * Evidence format produced by the attesting TEE / hardware root.
   * 'generic-eat' is RFC 9711 EAT (Entity Attestation Token) shape —
   * the format-agnostic fallback for any vendor we don't explicitly
   * call out. New formats added additively per the schema rule.
   */
  evidence_format: z.enum([
    'aws-nitro-enclave',
    'tpm-eat',
    'amd-sev-snp',
    'intel-tdx',
    'arm-cca',
    'generic-eat',
  ]),

  /**
   * Per-format measurements / configuration values the verifier
   * extracted from the evidence. For Nitro this is the PCR map
   * (PCR0..PCR8 hex digests); for SEV-SNP the launch_digest /
   * launch_measurement; for TDX the MRTD / RTMR set; for generic-eat
   * the claims-set keys. Empty record is invalid — at least one
   * measurement must be present for the claim to carry meaning.
   */
  measurements: z.record(z.string(), z.string()).refine(
    (m) => Object.keys(m).length > 0,
    { message: 'measurements must contain at least one entry' },
  ),

  /**
   * The attested workload's public key, if the evidence bound one
   * (cnf-style proof-of-possession key). Binds the attestation to
   * the workload identity for subsequent PoP checks. JWK shape.
   */
  pubkey_jwk: z.record(z.unknown()).optional(),

  /**
   * Anti-replay nonce that was challenged by STACK or a relying
   * party before the workload produced the evidence. When present,
   * verifiers re-check that the nonce was issued recently and
   * single-use.
   */
  nonce: z.string().optional(),

  /**
   * Where the original evidence bytes are published. Optional; if
   * absent, the claim carries no external pointer. Common formats:
   *   - HTTPS URL into operator-controlled storage
   *   - rekor://entry/<uuid>
   *   - ipfs://<cid>
   */
  evidence_uri: z.string().optional(),

  /**
   * sha256 of the original evidence bytes (hex-encoded), so a
   * verifier dereferencing evidence_uri can confirm what they
   * fetched matches what STACK attested.
   */
  evidence_sha256: z.string().regex(/^[0-9a-f]{64}$/, 'must be 64-char hex sha256').optional(),

  /** unix ts when STACK accepted the evidence */
  attested_at: z.number(),
});
export type RatsEvidenceClaim = z.infer<typeof RatsEvidenceClaim>;
