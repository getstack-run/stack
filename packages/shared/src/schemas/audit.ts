import { z } from 'zod';

export const AuditLayer = z.enum(['vault', 'dropoff', 'skills', 'hire', 'system', 'billing']);
export type AuditLayer = z.infer<typeof AuditLayer>;

export const AuditOutcome = z.enum(['success', 'failure', 'pending', 'blocked']);
export type AuditOutcome = z.infer<typeof AuditOutcome>;

export const AuditEntry = z.object({
  entry_id: z.string(),
  trace_id: z.string(),
  span_id: z.string(),
  parent_span_id: z.string().nullable(),
  timestamp: z.number(), // unix milliseconds
  operator_id: z.string(),
  agent_id: z.string(),
  passport_jti: z.string(),
  layer: AuditLayer,
  action: z.string(),
  outcome: AuditOutcome,
  duration_ms: z.number().nullable(),
  payload_hash: z.string().nullable(),
  error: z
    .object({
      code: z.string(),
      message: z.string(),
    })
    .nullable(),
  // Chain integrity
  prev_entry_hash: z.string(),
  entry_hash: z.string(),
});
export type AuditEntry = z.infer<typeof AuditEntry>;
