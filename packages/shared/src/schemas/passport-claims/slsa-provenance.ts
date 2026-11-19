import { z } from 'zod';

/**
 * slsa_provenance — passport claim recording an in-toto / SLSA
 * Provenance predicate for the workload's build artifact(s).
 * chunk C of the Signed Primitive epic.
 *
 * Conforms to SLSA Provenance v1.0 predicate shape (predicate_type
 * `https://slsa.dev/provenance/v1`). When a customer's CI pipeline
 * emits SLSA provenance for the agent it builds, that provenance
 * attaches to the agent's passport as a signed claim, making the
 * build chain visible inside STACK's audit log.
 *
 * STACK's own SDK and CLI publishing SLSA L3 provenance for every
 * release is a outbound follow-up (the GitHub Actions
 * workflow generates the provenance; this claim shape is what we
 * record once it's attached to a STACK release passport).
 */
export const SlsaProvenanceClaim = z.object({
  type: z.literal('slsa_provenance'),

  /** SLSA spec version this claim was authored against. */
  predicate_type: z.literal('https://slsa.dev/provenance/v1'),

  /**
   * Identifier for the build type / toolchain shape. URI form per
   * SLSA spec. Example: 'https://github.com/actions/runner/github-hosted@v1'.
   */
  build_type: z.string(),

  /** The trusted build system that produced the artifact. */
  builder: z.object({
    id: z.string(),                                       // URI identifying the builder
    version: z.record(z.string(), z.string()).optional(),
    builder_dependencies: z.array(z.object({
      uri: z.string(),
      digest: z.record(z.string(), z.string()),
    })).optional(),
  }),

  /**
   * How the build was invoked. Source repo URI + digest are the
   * load-bearing fields; parameters carry env-specific knobs.
   */
  invocation: z.object({
    config_source: z.object({
      uri: z.string(),
      digest: z.record(z.string(), z.string()),
      entry_point: z.string().optional(),
    }).optional(),
    parameters: z.record(z.unknown()).optional(),
    environment: z.record(z.unknown()).optional(),
  }).optional(),

  /** Cryptographic digest(s) of the built artifact the claim attests. */
  subject_digest: z.record(z.string(), z.string()).refine(
    (d) => Object.keys(d).length > 0,
    { message: 'subject_digest must contain at least one algorithm entry' },
  ),

  /**
   * Self-asserted SLSA level (0-4). v1 of this claim type does not
   * verify the level against the builder's actual posture — it's
   * recorded as the asserting party's claim. Per-builder L3+
   * verification is a follow-up.
   */
  slsa_level: z.number().int().min(0).max(4).optional(),

  /** unix ts when STACK accepted the provenance */
  attested_at: z.number(),
});
export type SlsaProvenanceClaim = z.infer<typeof SlsaProvenanceClaim>;
