/**
 * TwinDivergenceClaim.
 *
 * Twin runtime is Mission Layer Pillar 2's ground-truth substrate: the
 * agent's actions run a SECOND time against a different model or
 * provider in parallel, and the divergence between the real chain and
 * the twin chain becomes a signed claim. Pillar 1 (mission) gives
 * "what should have happened"; the twin gives "what an independent
 * runtime saw"; the divergence between them is the ground truth a
 * heuristic-only detector chain can't produce.
 *
 * One TwinDivergenceClaim per mission close. Produced by
 * TwinOrchestrationService (5.3.2-5.3.4) at the terminal mission
 * transition. Consumed by the operator surface in 5.3.6+ (dashboard +
 * MCP read tool).
 *
 * Signed for every account whose Mission ran a twin.
 *
 * Schema is locked here in 5.3.1 so 5.3.2-5.3.6 light up against a
 * stable wire shape. Same pattern as 5.1.1 (BehavioralGenomeClaim
 * schema landed before producer/consumer wiring).
 */

import { z } from 'zod';

/**
 * Per-dimension severity grade. Distinct enum from
 * SecurityEventSeverity ('info' | 'warning' | 'critical') — twin
 * runtime uses a finer 4-level grade per the macro spec. A small
 * output_shape diff might be 'low'; a counterparty mismatch is at
 * least 'medium'; a critical-severity detector_signal divergence is
 * 'critical'. Keep enums separate to avoid coupling the two semantic
 * domains.
 */
export const TwinDivergenceSeverity = z.enum(['low', 'medium', 'high', 'critical']);
export type TwinDivergenceSeverity = z.infer<typeof TwinDivergenceSeverity>;

/**
 * Four canonical divergence axes the evaluator measures:
 *
 *   - `output_shape`: real vs twin response shape / content differs
 *     (different text, missing fields, extra steps, etc.)
 *   - `counterparty`: real vs twin called different upstream endpoints
 *     (e.g. real hit api.foo.com, twin hit api.bar.com)
 *   - `cost`: real vs twin wallet_cents or token delta exceeded a
 *     threshold the producer sets
 *   - `detector_signal_set`: real vs twin tripped different detectors
 *     (e.g. one path triggered prompt_injection_output, the other
 *     didn't)
 *
 * Additive enum — future divergence axes ship as new values. Existing
 * consumers that switch on dimension MUST default to handle the
 * unknown case gracefully.
 */
export const TwinDivergenceDimension = z.enum([
  'output_shape',
  'counterparty',
  'cost',
  'detector_signal_set',
]);
export type TwinDivergenceDimension = z.infer<typeof TwinDivergenceDimension>;

/**
 * One row in the `divergence_dimensions` array. `diff` is free-form
 * jsonb because each dimension's diff shape is fundamentally
 * different (output_shape might carry `{real, twin, schema_path}`;
 * counterparty might carry `{real_endpoint, twin_endpoint}`; cost
 * might carry `{real_cents, twin_cents, delta_pct}`). v1 keeps `diff`
 * flexible so 5.3.4 producer can iterate. v2 may tighten per-dimension
 * if patterns solidify; backward-compat is trivial since `z.record`
 * accepts anything stricter.
 */
export const TwinDivergenceEntry = z.object({
  dimension: TwinDivergenceDimension,
  severity: TwinDivergenceSeverity,
  /** Free-form per-dimension diff shape. Producer + consumer agree on
   * the shape per-dimension; schema doesn't constrain. */
  diff: z.record(z.string(), z.unknown()),
});
export type TwinDivergenceEntry = z.infer<typeof TwinDivergenceEntry>;

/**
 * TwinDivergenceClaim — terminal-state claim emitted at mission close
 * comparing the real agent's intent_outcome chain to the twin's.
 */
export const TwinDivergenceClaim = z.object({
  type: z.literal('twin_divergence'),

  /** The passport whose mission window this twin run covered. */
  passport_jti: z.string().min(1),

  /**
   * REQUIRED — twin runtime ALWAYS executes under a mission. Unlike
   * most claim types (which carry mission_ref as nullable), this one
   * rejects at parse time if absent. The producer never has reason
   * to emit a TwinDivergenceClaim outside a mission close.
   */
  mission_ref: z
    .string()
    .regex(/^ms_[\w-]+$/, 'mission_ref must be a mission id (ms_*)'),

  /**
   * Ordered claim_ids of the real agent's intent_outcome chain within
   * the mission window. Empty array is valid for a no-op mission
   * (passport authorised but agent took zero actions).
   */
  real_intent_outcomes: z
    .array(z.string().regex(/^pc_[\w-]+$/, 'must be a passport-claim id (pc_*)'))
    .default([]),

  /**
   * Ordered claim_ids of the twin's intent_outcome chain within the
   * same mission window. May be shorter or longer than real — a
   * length mismatch is itself a divergence and gets a
   * `dimension: 'output_shape'` entry below.
   */
  twin_intent_outcomes: z
    .array(z.string().regex(/^pc_[\w-]+$/, 'must be a passport-claim id (pc_*)'))
    .default([]),

  /**
   * One entry per divergence axis observed. Empty array == zero
   * divergence (real and twin agreed on every measured dimension)
   * which is the desired outcome — proof the agent's actions
   * survived re-execution against an independent runtime.
   */
  divergence_dimensions: z.array(TwinDivergenceEntry).default([]),

  /**
   * Human-readable summary surfaced in the operator dashboard. Max
   * 2048 chars to match IntentClaim.reason convention.
   */
  diff_summary: z.string().max(2048),

  /**
   * Unix milliseconds when the divergence evaluation ran.
   * TwinOrchestrationService computes at mission close, BEFORE this
   * claim is signed and attached.
   */
  evaluated_at_ms: z.number().int().nonnegative(),
});

export type TwinDivergenceClaim = z.infer<typeof TwinDivergenceClaim>;
