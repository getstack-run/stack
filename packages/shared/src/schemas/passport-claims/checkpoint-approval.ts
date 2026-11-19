import { z } from 'zod';

/**
 * checkpoint_approval — signed record of a checkpoint submission for an
 * enforced or logged passport.
 *
 * of the Signed Primitive epic. Migration target
 * for the existing `passport_checkpoints` table.
 *
 * Today every checkpoint already lands as a row in `passport_checkpoints`
 * via `AccountabilityService.submitCheckpoint`. dual-writes a
 * signed COSE_Sign1 claim alongside, then the legacy table becomes a
 * denormalised projection (the user-facing read path keeps its indexes
 * + columns; the cryptographic substrate lives in the claim).
 *
 * Semantic note: the claim records the SUBMISSION event itself
 * (checkpoint emitted by the passport-holder agent / its operator),
 * NOT a separate operator-side approval. Whether the platform later
 * surfaces an operator-side approval/rejection flow on top of
 * checkpoints is a separate product question; the claim shape stays
 * minimal so it doesn't pre-commit to a workflow.
 */
export const CheckpointApprovalClaim = z.object({
  type: z.literal('checkpoint_approval'),

  /** passport_checkpoints.id — the legacy row this claim mirrors. */
  checkpoint_id: z.string().regex(/^chk_[\w-]+$/, 'checkpoint_id must be a passport_checkpoints id (chk_*)'),

  /**
   * Checkpoint interval for the passport at submission time. Populated
   * for enforced-mode passports (where the interval extends expiry on
   * each submission), null for logged-mode passports.
   */
  interval_seconds: z.number().int().positive().nullable(),

  /** Services the agent reports using since the last checkpoint. */
  services_used: z.array(z.string()).default([]),

  /** Action count since last checkpoint (caller-reported). */
  actions_count: z.number().int().nonnegative(),

  /** Whether a free-form summary was attached at submission. */
  has_summary: z.boolean().default(false),

  /** Agent IDs delegated to during this checkpoint window, if any. */
  delegated_to: z.array(z.string()).default([]),

  /**
   * Operator id of the submitter. The passport-holder's operator —
   * matches passport_checkpoints.operator_id. NOT an "approving member"
   * — see the semantic note in the docstring.
   */
  submitted_by: z.string(),

  /** unix ms — when STACK accepted the checkpoint submission. */
  submitted_at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved from the passport's mission_ids when
   * exactly one is bound. Lets the dashboard surface render mission-
   * scoped checkpoint sub-timelines alongside the per-passport view.
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

export type CheckpointApprovalClaim = z.infer<typeof CheckpointApprovalClaim>;
