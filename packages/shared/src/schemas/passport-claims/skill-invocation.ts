import { z } from 'zod';

/**
 * skill_invocation — signed record of a sealed-skill or open-mode skill
 * invocation, emitted at three lifecycle transitions: submitted (the
 * agent requested the invocation), completed (the provider/sealed
 * executor returned an output), failed (execution errored).
 *
 * of the Signed Primitive epic. Migration target
 * for the existing skill invocation record. The legacy record keeps
 * the encrypted input/output + tracking fields (input_encrypted,
 * output_encrypted, llm_tokens_*, execution_duration_ms); the claim
 * envelope carries hashes + lifecycle metadata only.
 *
 * Single schema across three statuses — the lifecycle is small enough
 * that one shape with status-conditional optionals is clearer than a
 * three-arm discriminated union. Producer-side enforcement:
 * `output_hash` + `duration_ms` populated only on `completed`; `error`
 * only on `failed`; `input_hash` always populated.
 *
 * Note vs intent_claim/intent_outcome: those capture the AGENT's
 * declaration + actual outcome (what the agent SAID it would do; what
 * the agent observed). This claim captures STACK's execution record
 * (what the sealed executor/provider actually ran). Different
 * audiences; not redundant. Both attach to the same passport.
 */
export const SkillInvocationClaim = z.object({
  type: z.literal('skill_invocation'),

  /** The id of the legacy invocation row this claim mirrors. */
  invocation_id: z.string().regex(/^inv_[\w-]+$/, 'invocation_id must be a skill invocation id (inv_*)'),

  /** The skill being invoked. */
  skill_id: z.string(),

  /** The skill publisher's operator. */
  provider_operator_id: z.string(),

  /** How STACK ran the skill. */
  execution_mode: z.enum(['sealed', 'open', 'source']),

  /** sha256(canonical(input)) — bound at submit time. */
  input_hash: z.string(),

  /** Lifecycle phase this claim represents. */
  status: z.enum(['submitted', 'completed', 'failed']),

  /** sha256(canonical(output)) — populated on `completed` only. */
  output_hash: z.string().optional(),

  /** Wall-clock execution duration in milliseconds — `completed` only. */
  duration_ms: z.number().int().nonnegative().optional(),

  /**
   * Actual cost charged to the consumer's wallet — `completed` only.
   * `wallet_cents` is the cents debited (publisher take + STACK markup);
   * `tokens` is the LLM token total for sealed-LLM steps (0 for
   * non-LLM skills).
   */
  cost_actual: z
    .object({
      wallet_cents: z.number().int().nonnegative(),
      tokens: z.number().int().nonnegative(),
    })
    .optional(),

  /** Error envelope — `failed` only. */
  error: z
    .object({
      code: z.string(),
      message: z.string(),
    })
    .optional(),

  /**
   * unix ms — when STACK accepted the invocation submission (for
   * `submitted` status) OR when the invocation reached its terminal
   * state (for `completed` / `failed`).
   */
  at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved from the passport's mission_ids when
   * exactly one is bound. Skill invocations under a mission count
   * toward max_actions and max_actions_per_service caps.
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

export type SkillInvocationClaim = z.infer<typeof SkillInvocationClaim>;
