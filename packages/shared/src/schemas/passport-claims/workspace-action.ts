import { z } from 'zod';

/**
 * workspace_action — STACK's signed record of one action of an agent in its account's workspace: a command run, a file
 * read or written, a file saved to the drive, a workspace stopped. It binds the hashes of what was asked and of what
 * came back to the Passport the agent acted under, so the record can be checked against what STACK observed. A command
 * is recorded as a hash of all of it and a clipped preview, never an environment value; a preview that looks like a
 * credential is replaced by a note saying so. The workspace has its own internet access: STACK records the actions it
 * is asked for, not every byte that leaves the machine.
 */
export const WorkspaceActionClaim = z.object({
  type: z.literal('workspace_action'),
  action: z.enum(['exec', 'read_file', 'write_file', 'save_file', 'stop']),
  workspace_id: z.string().regex(/^wsp_[\w-]+$/, 'workspace_id must be a workspace id (wsp_*)'),
  account_id: z.string().min(1),
  status: z.enum(['succeeded', 'failed', 'timed_out']),
  /** exec: sha256 of the whole command. */
  command_hash: z.string().optional(),
  /** exec: the first characters of the command, or a note that it was withheld because it looks like a credential. */
  command_preview: z.string().max(260).optional(),
  /** exec: the command was given a Passport of this agent (STACK access). */
  stack_access: z.boolean().optional(),
  /** File actions: the path inside the workspace, clipped. */
  path: z.string().max(320).optional(),
  /** exec: sha256 of the output as the agent was given it. File actions: sha256 of the bytes. */
  content_hash: z.string().optional(),
  exit_code: z.number().int().optional(),
  /** stop: whether the workspace was deleted or paused. */
  deleted: z.boolean().optional(),
  duration_ms: z.number().int().nonnegative(),
  error_code: z.string().optional(),
  /** unix ms when the action ended. */
  at: z.number().int(),
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)'),
});

export type WorkspaceActionClaim = z.infer<typeof WorkspaceActionClaim>;
