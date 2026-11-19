import { z } from 'zod';

/**
 * sandbox_run — STACK's signed record of one run of an agent's code in the
 * account sandbox, emitted once when the run ends. It binds the hashes of the
 * code, its input and its output (`sha256(canonical(value))`) to the Passport
 * the run used, so the output an agent or operator reads can be checked
 * against what STACK observed. Content stays in the sandbox run record,
 * KMS-encrypted; the claim carries hashes and outcome only.
 */
export const SandboxRunClaim = z.object({
  type: z.literal('sandbox_run'),
  run_id: z.string().regex(/^sbr_[\w-]+$/, 'run_id must be a sandbox run id (sbr_*)'),
  account_id: z.string().min(1),
  runtime: z.enum(['javascript', 'python']),
  script_hash: z.string(),
  input_hash: z.string(),
  status: z.enum(['succeeded', 'failed', 'timed_out', 'cancelled']),
  /** Hash of `{ output, logs }`; present when the runner returned a result. */
  output_hash: z.string().optional(),
  /** Machine time on STACK's clock, from machine creation to stop. */
  duration_ms: z.number().int().nonnegative(),
  /** Budget cents settled for the run. */
  cost_cents: z.number().int().nonnegative(),
  error_code: z.string().optional(),
  /** unix ms when the run ended. */
  at: z.number().int(),
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)'),
});

export type SandboxRunClaim = z.infer<typeof SandboxRunClaim>;
