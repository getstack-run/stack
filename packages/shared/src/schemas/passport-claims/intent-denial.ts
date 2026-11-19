import { z } from 'zod';
import { IntentClaim } from './intent-claim.js';

/**
 * intent_denial — signed record of an Intent being refused.
 *
 * of the Signed Primitive epic. ADR
 * at the intent claims design (Design Decision 7).
 *
 * Every denial path (constraint violation, scope mismatch,
 * accountability monotonicity violation, detector block, tier limit,
 * simulation failure, prerequisite unmet) leaves a signed claim. This
 * is the "negative-space" primitive: every refusal is recorded as a signed
 * claim that can be queried and verified afterwards.
 *
 * Dedup strategy (D2 lock): producer computes
 * `parameters_hash = sha256(canonical(attempted_intent.parameters))`
 * and queries the registry for an active denial claim with matching
 * `(passport_jti, attempted_intent.named_intent, parameters_hash)`.
 * If found, increments the existing claim's `metadata.retry_count` via
 * UPDATE on the indexed metadata column. If not found, writes a fresh
 * signed claim with retry_count=1.
 *
 * The signed envelope is IMMUTABLE — retry_count lives in the schema
 * for verifier completeness (so the verifier can see the count) but
 * the canonical signed version shows retry_count=1 (the first denial).
 * The storage layer's `metadata.retry_count` column carries the live
 * current count for query convenience. Verifier interpretation: the
 * signed claim attests to the original denial event; the storage
 * column tracks retry behaviour for operational visibility.
 *
 * Open architecture note (per ADR Design Decision 7): if regulators
 * push back on the dedup model, alternate shape is a separate
 * `denial_repeat` claim type per retry — higher write rate, finer
 * signed history. Current implementation is the pragmatic shape.
 */
export const IntentDenialClaim = z.object({
  type: z.literal('intent_denial'),

  /**
   * The Intent that was denied. Embedded full IntentClaim payload —
   * the denial captures the canonical denial record even if the
   * original Intent never landed in the claim registry (denial can
   * occur before Intent registration in pre-check paths).
   */
  attempted_intent: IntentClaim,

  /**
   * Why the denial happened. Closed enum.
   *
   * - `constraint_violation`: action violated a named-intent constraint
   *   (URL/method mismatch, parameter out of range, etc.)
   * - `scope_mismatch`: passport scope does not cover the attempted
   *   action
   * - `accountability_monotonicity`: parent passport is `enforced` and
   *   the child tried to delegate to `logged` or `standard`
   * - `detector_block`: a detector fired with severity above block
   *   threshold
   * - `tier_limit`: operator's tier overage cap exceeded
   * - `simulation_failure`: pre-execution simulation predicted failure
   * - `requires_unmet`: a prerequisite outcome in Intent.requires was
   *   missing or had status != 'succeeded'
   */
  denial_reason: z.enum([
    'constraint_violation',
    'scope_mismatch',
    'accountability_monotonicity',
    'detector_block',
    'tier_limit',
    'simulation_failure',
    'requires_unmet',
  ]),

  /**
   * If a specific detector triggered the denial, which one. Optional —
   * non-detector denials leave this null. Follows the same loose-string
   * snake_case shape as detector_signal.detector_key for catalog
   * agnosticism.
   */
  denying_detector_key: z.string().regex(/^[a-z][\w]*$/).optional(),

  /**
   * Human-readable reason for the operator / auditor. Brief — full
   * detail (matched patterns, failed constraints) belongs in metadata.
   * Capped at 1024 chars.
   */
  message: z.string().max(1024),

  /**
   * sha256(canonical(attempted_intent.parameters)) as hex. Used by
   * producer-side dedup logic to detect repeated denials of the same
   * Intent shape. Required so dedup matches are deterministic.
   */
  parameters_hash: z.string().regex(/^[0-9a-f]{64}$/, 'must be 64-char hex sha256'),

  /**
   * Number of retry attempts caught by dedup within the dedup window
   * (passport TTL). First denial = 1; subsequent matching retries
   * increment this on the storage layer (the signed envelope shows
   * the original value 1 forever).
   */
  retry_count: z.number().int().positive().default(1),

  /**
   * Free-form metadata bag. Common entries:
   * - `matched_constraints: string[]` (constraint_violation)
   * - `requested_scope: string[]` (scope_mismatch)
   * - `failing_requires: string[]` (requires_unmet — claim_ids that
   *   were missing or failed)
   * - `detector_confidence: number` (detector_block)
   * - `tier_dimension: string` (tier_limit — which limit was hit)
   */
  metadata: z.record(z.string(), z.unknown()).default({}),

  /** unix ms — when STACK recorded the denial. */
  denied_at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved by producers from the passport's
   * mission_ids when exactly one is bound. Mirrors the attempted
   * intent's mission_ref so denials filter by mission cleanly.
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

export type IntentDenialClaim = z.infer<typeof IntentDenialClaim>;
