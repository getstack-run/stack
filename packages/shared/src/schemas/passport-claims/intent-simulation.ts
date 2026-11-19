import { z } from 'zod';

/**
 * intent_simulation — signed pre-execution dry-run result.
 *
 * of the Signed Primitive epic. ADR
 * at the intent claims design (Design Decision 8).
 *
 * SCHEMA ONLY ships — the producer is's
 * `IntentSimulationService`. Locking the wire shape now means
 * lands clean against a known substrate.
 *
 * The simulation runs PRE-execution and produces this signed claim;
 * actual execution produces a paired `intent_outcome` claim. Divergence
 * between the two (simulation predicted `allowed=true` → actual denied,
 * or simulated_cost vs cost_actual) is a security signal worth
 * surfacing on the operator dashboard.
 *
 * The prediction is emitted as a verifiable artifact, queryable against the
 * actual outcome.
 *
 * Separate claim type from `intent_outcome` per ADR D3 — keeps the
 * Intent envelope immutable, separates pre-execution prediction from
 * post-execution result.
 */
export const IntentSimulationClaim = z.object({
  type: z.literal('intent_simulation'),

  /**
   * The Intent claim this simulation pairs with. Optional — simulations
   * can run for hypothetical (not-yet-submitted) Intents during a
   * `dry-run` operator inspection flow. Most simulations in production
   * will have this populated.
   */
  intent_claim_ref: z.string().regex(/^pc_[\w-]+$/, 'intent_claim_ref must be a passport-claim id (pc_*)').optional(),

  /**
   * Would the simulated execution succeed? `true` = simulation predicts
   * execution proceeds; `false` = simulation predicts denial.
   */
  allowed: z.boolean(),

  /**
   * If `allowed=false`, the predicted denial reasons. Empty array when
   * `allowed=true`. Enum matches `IntentDenialClaim.denial_reason` so
   * simulation and actual denial use the same vocabulary.
   */
  denial_reasons: z.array(z.enum([
    'constraint_violation',
    'scope_mismatch',
    'accountability_monotonicity',
    'detector_block',
    'tier_limit',
    'requires_unmet',
  ])).default([]),

  /**
   * Projected cost. Same shape as Intent.estimated_cost and
   * IntentOutcome.cost_actual so the three are directly comparable.
   * The simulation may project more accurately than the Intent's
   * estimate if it has access to runtime context (current token
   * pricing, current gas estimates) the Intent submission did not.
   */
  simulated_cost: z.object({
    wallet_cents: z.number().nonnegative().nullable(),
    tokens: z.number().int().nonnegative().nullable(),
    gas_gwei: z.number().nonnegative().nullable(),
  }),

  /**
   * Projected detector fires that would occur on execution. Each entry
   * is (detector_key, severity). Empty = simulation predicted no
   * detector fires. The simulator runs the heuristic + regex layers of
   * the detector chain (LLM layer skipped — expensive, low value at
   * simulation time).
   */
  predicted_detector_fires: z.array(z.object({
    detector_key: z.string().regex(/^[a-z][\w]*$/),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
  })).default([]),

  /**
   * For HTTP intents: the projected response shape (status code +
   * header summary — response body is NOT simulated, that requires
   * actually calling upstream). Optional; only populated for http_call
   * intent simulations.
   */
  projected_http: z.object({
    status_code: z.number().int(),
    headers_summary: z.record(z.string(), z.string()).default({}),
  }).optional(),

  /** unix ms — when STACK ran the simulation. */
  simulated_at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved by producers from the passport's
   * mission_ids when exactly one is bound. Mirrors the simulated
   * intent's mission_ref so simulations filter by mission cleanly.
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

export type IntentSimulationClaim = z.infer<typeof IntentSimulationClaim>;
