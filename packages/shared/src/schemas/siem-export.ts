import { z } from 'zod';
import { SIEM_SEVERITIES } from '../constants/siem-export.js';

// The record of the security-monitoring export (spec/siem-export). The exporter builds its records with these
// types, and the specification's JSON Schemas are generated from them by scripts/generate-spec.mjs.

const Severity = z.enum(SIEM_SEVERITIES);

/** What a record of the `security` stream says beyond the common members. */
export const SiemSecurityFields = z.object({
  passport_jti: z.string().nullable(),
  mission_id: z.string().nullable(),
  /** The detector's own sentence about what it saw. */
  message: z.string(),
  /** The detector's structured detail, as stored on the security event. */
  metadata: z.record(z.string(), z.unknown()).nullable(),
  /** Whether the event was resolved when it was exported. */
  resolved: z.boolean(),
}).passthrough();
export type SiemSecurityFields = z.infer<typeof SiemSecurityFields>;

/** What a record of the `audit` stream says beyond the common members: the public fields of one audit log row. */
export const SiemAuditFields = z.object({
  passport_jti: z.string(),
  layer: z.string(),
  outcome: z.string(),
  error_code: z.string().nullable(),
  trace_id: z.string(),
  /** The row's hash in the operator's hash chain. */
  entry_hash: z.string(),
}).passthrough();
export type SiemAuditFields = z.infer<typeof SiemAuditFields>;

/** A record shrunk to fit one syslog message: the identifying members stay, the detail goes. */
export const SiemTruncatedFields = z.object({ truncated: z.literal(true) }).passthrough();

const Common = {
  /** Unique within its stream: a collector drops a repeat by the pair of stream and id. */
  id: z.string().min(1),
  /** When it happened, ISO 8601 UTC with milliseconds. */
  time: z.string().datetime(),
  severity: Severity,
  operator_id: z.string().min(1),
  agent_id: z.string().min(1),
  /** What happened, in the stream's own words: a signal type, an audit action. */
  event: z.string().min(1),
};

export const SiemSecurityRecord = z.object({
  stream: z.literal('security'),
  ...Common,
  fields: z.union([SiemSecurityFields, SiemTruncatedFields]),
}).passthrough();

export const SiemAuditRecord = z.object({
  stream: z.literal('audit'),
  ...Common,
  fields: z.union([SiemAuditFields, SiemTruncatedFields]),
}).passthrough();

/** One exported record: the JSON object of a syslog message's body and of one line of a batch to an HTTPS collector. */
export const SiemRecord = z.discriminatedUnion('stream', [SiemSecurityRecord, SiemAuditRecord]);
export type SiemRecord = z.infer<typeof SiemRecord>;
