import { z } from 'zod';

/**
 * ai_bom_ref — passport claim referencing a CycloneDX AI/ML-BOM
 * (Software Bill of Materials, AI/ML extension) document attached to
 * the agent. Part of the Signed Primitive epic.
 *
 * The BOM document itself is large (model card, training data refs,
 * dependencies, prompt templates) and lives outside the claim — in
 * customer-controlled storage with a published URI. The claim
 * records the BOM's identifying digest plus headline summary fields
 * for quick lookup, so a relying party can dereference and confirm
 * the agent's declared AI surface without parsing every claim.
 *
 * v1 SCOPE — schema only. The full CycloneDX-generator that builds
 * the BOM document from STACK's view of the agent is deferred to a
 * follow-up; until that ships, the customer's tooling is expected to
 * produce the BOM out-of-band and submit its reference here.
 *
 * Supports EU AI Act Article 13 (transparency obligations) and
 * NIST AI RMF documentation requirements.
 */
export const AiBomRefClaim = z.object({
  type: z.literal('ai_bom_ref'),

  /** Always 'CycloneDX' in v1; future formats added additively. */
  bom_format: z.literal('CycloneDX'),

  /** CycloneDX spec version the BOM was authored against. */
  spec_version: z.string(),                         // e.g. '1.6'

  /**
   * Where the BOM is published. STACK does NOT fetch this URI as
   * part of claim attachment — the URI is a pointer the relying
   * party dereferences when they need the full document.
   */
  bom_uri: z.string(),

  /**
   * sha256 of the canonical CycloneDX JSON, hex-encoded. Tamper-
   * evidence: a relying party fetching bom_uri must compute this
   * over the response body and refuse mismatches.
   */
  bom_sha256: z.string().regex(/^[0-9a-f]{64}$/, 'must be 64-char hex sha256'),

  /**
   * Headline model list — surface here for fast filtering ("which
   * passports reference GPT-4?") without dereferencing every BOM.
   * Details (parameters, training-data refs, dependencies) live
   * inside the referenced document.
   */
  models: z.array(z.object({
    name: z.string(),
    version: z.string().optional(),
    /** Provider URI, e.g. 'https://openai.com/api/models/gpt-4' */
    source: z.string().optional(),
    /** Optional licence identifier (SPDX) */
    license: z.string().optional(),
  })).optional(),

  /** Optional free-text summary of training-data provenance. */
  training_data_summary: z.string().optional(),

  /** unix ts when STACK accepted the BOM reference */
  attested_at: z.number(),
});
export type AiBomRefClaim = z.infer<typeof AiBomRefClaim>;
