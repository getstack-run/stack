import { z } from 'zod';

// The wire shapes of workload identity exchange (spec/workload-identity): a
// SPIFFE JWT-SVID or a WIMSE Workload Identity Token presented as the bearer
// of POST /v1/workload/passport or POST /v1/workload/wit, in exchange for a
// Passport. The request body names the Mission the Passport is bound to.

export const WorkloadPassportInput = z.object({
  mission_id: z.string().regex(/^ms_[\w-]+$/),
}).strict();
export type WorkloadPassportInput = z.infer<typeof WorkloadPassportInput>;

/** POST /v1/workload/passport: the 201 answer. */
export const WorkloadSvidPassportResult = z.object({
  passport: z.string().min(1),
  jti: z.string().min(1),
  expires_at: z.string().datetime(),
  spiffe_id: z.string().regex(/^spiffe:\/\/[^/]+(\/.*)?$/),
  trust_domain: z.string().min(1),
  claim_id: z.string().min(1),
  ttl_seconds: z.number().int().positive(),
});
export type WorkloadSvidPassportResult = z.infer<typeof WorkloadSvidPassportResult>;

/** POST /v1/workload/wit: the 201 answer. */
export const WorkloadWitPassportResult = z.object({
  passport: z.string().min(1),
  jti: z.string().min(1),
  expires_at: z.string().datetime(),
  workload_id: z.string().min(1),
  issuer: z.string().min(1),
  claim_id: z.string().min(1),
  ttl_seconds: z.number().int().positive(),
});
export type WorkloadWitPassportResult = z.infer<typeof WorkloadWitPassportResult>;
