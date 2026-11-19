import { z } from 'zod';

/**
 * detector_signal — canonical record of a detector firing.
 *
 * of the Signed Primitive epic. ADR
 * at the intent claims design (Design Decision 6).
 *
 * Promotes `detector_signal` from the ADR's reserved-name list
 * to an active claim type with a v1 payload schema. Every detector
 * fire emits a detector_signal claim alongside the existing
 * `security_events` row (dual-write window). After
 * legacy-to-view cutover, `security_events` becomes
 * a SQL VIEW over `claim_registry WHERE claim_type = 'detector_signal'`.
 *
 * The `detector_key` field is loose-string with a snake_case shape
 * constraint. Same reasoning as IntentClaim.named_intent: the detector
 * catalog (23 entries today, growing) lives in
 * `packages/shared/src/constants/detectors.ts` and binding the schema
 * to runtime catalog state would make every catalog addition a
 * schema-version event. Producer-side validation
 * (`SecurityEventService.record()`) checks catalog membership before
 * emitting the claim.
 *
 * `intent_claim_ref` is optional — populated when the detector fires
 * inside an Intent's execution path (proxy, skills, A2A, Shroud), null
 * when the fire is detached (background sweep, scheduled scan).
 */
export const DetectorSignalClaim = z.object({
  type: z.literal('detector_signal'),

  /**
   * Detector catalog key (snake_case). Examples: 'prompt_injection_llm',
   * 'scope_drift', 'output_injection', 'behavior_drift_zscore'.
   * Catalog membership validated producer-side.
   */
  detector_key: z.string().regex(/^[a-z][\w]*$/, 'detector_key must be snake_case'),

  /**
   * Severity recorded at fire time. Matches the existing detector
   * catalog severity enum.
   */
  severity: z.enum(['low', 'medium', 'high', 'critical']),

  /**
   * Pipeline that produced the fire. Mirrors the existing detector
   * catalog's `pipeline` field. 'heuristic' = regex/Aho-Corasick;
   * 'llm' = LLM classifier (e.g. prompt-injection L3);
   * 'detection-chain' = multi-layer chain (e.g. the 8-layer
   * prompt-injection detector).
   */
  pipeline: z.enum(['heuristic', 'llm', 'detection-chain']),

  /**
   * The Intent claim that triggered this detector fire. Populated when
   * the fire happens inside an Intent's execution path (proxy, skills,
   * A2A, Shroud-LITE bidirectional inspection). Null when the fire is
   * detached from any specific Intent (background sweep, scheduled
   * scan, manual replay).
   */
  intent_claim_ref: z.string().regex(/^pc_[\w-]+$/, 'intent_claim_ref must be a passport-claim id (pc_*)').optional(),

  /**
   * The agent associated with the detected behaviour. Optional — some
   * detectors fire without a specific agent context (operator-level
   * scans).
   */
  agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/).optional(),

  /**
   * Free-form metadata bag — detector-specific output. Common entries:
   * - `matched_patterns: string[]` (heuristic detectors)
   * - `confidence_score: number` (LLM detectors)
   * - `redaction_count: number` (secret-scanner)
   * - `cost_cents: number` (LLM detectors with COGS)
   * - `model: string` (LLM detectors)
   *
   * Schema does NOT validate metadata shape — producer-specific.
   */
  metadata: z.record(z.string(), z.unknown()).default({}),

  /** unix ms — when STACK accepted the detector fire. */
  detected_at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved from the passport's mission_ids when
   * exactly one is bound. Detector signals fired under a mission
   * filter by mission cleanly in the dashboard replay surface.
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

export type DetectorSignalClaim = z.infer<typeof DetectorSignalClaim>;
