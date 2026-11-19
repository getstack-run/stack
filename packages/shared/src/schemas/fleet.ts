import { z } from 'zod';
import { Constraint } from './passport.js';
import { IntentRef } from '../intents/types.js';

const exactId = z.string().min(1).max(128).regex(/^[\w.-]+$/);
const exactNames = z.array(z.string().min(1).max(128).refine(v => v !== '*')).max(64);

// A connection is an account, not merely a provider name. Never choose one
// implicitly when multiple accounts of the same provider are connected.
export const FleetAccess = z.object({
  connection_id: z.string().regex(/^scon_[\w-]+$/),
  scopes: exactNames.min(1),
  intents: z.array(IntentRef).max(32).default([]),
  constraints: z.array(Constraint).max(32).default([]),
  allow_data_from: exactNames.default([]),
}).strict();
export type FleetAccess = z.infer<typeof FleetAccess>;

export const FleetRule = z.object({
  id: exactId,
  effect: z.enum(['allow', 'review', 'deny']),
  access: FleetAccess,
}).strict();
export type FleetRule = z.infer<typeof FleetRule>;

export const FleetOperationAccess = z.object({
  producer: z.enum(['skill', 'a2a', 'dropoff']),
  target_id: exactId,
  action: z.enum(['invoke', 'tasks/send', 'create', 'deposit', 'collect']),
  constraints: z.array(Constraint).max(32).default([]),
}).strict().refine(v => v.producer === 'skill' ? v.action === 'invoke'
  : v.producer === 'a2a' ? v.action === 'tasks/send' : ['create', 'deposit', 'collect'].includes(v.action), { message: 'Invalid input' });
export type FleetOperationAccess = z.infer<typeof FleetOperationAccess>;
export const FleetOperationRule = z.object({ id: exactId, effect: z.enum(['allow', 'review', 'deny']), access: FleetOperationAccess }).strict();
export type FleetOperationRule = z.infer<typeof FleetOperationRule>;

export const FleetLimits = z.object({
  max_actions: z.number().int().positive().max(1_000_000),
  max_concurrent_actions: z.number().int().positive().max(10_000),
  // No maximum of its own: the Mission still ends with its policy. The bound is the integer the Mission's column holds (about 68 years).
  max_duration_seconds: z.number().int().positive().max(2_147_483_647),
  max_dropoff_bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  max_spend_cents: z.number().int().nonnegative().max(100_000_000).optional(),
}).strict();
export type FleetLimits = z.infer<typeof FleetLimits>;

export const FleetWorkloadTrust = z.object({
  kind: z.enum(['spiffe', 'wimse']),
  issuer: z.string().min(1).max(512),
  audience: z.string().min(1).max(512),
  subjects: z.array(z.string().min(1).max(1024)).min(1).max(256),
}).strict();

export const FleetPolicyInput = z.object({
  name: z.string().min(1).max(128),
  rules: z.array(FleetRule).max(64).default([]),
  operation_rules: z.array(FleetOperationRule).max(64).default([]),
  limits: FleetLimits,
  window_seconds: z.number().int().min(60).max(2_678_400),
  max_members: z.number().int().positive(),
  max_enrollments_per_hour: z.number().int().positive(),
  identity_lease_seconds: z.number().int().min(60).max(86_400),
  provisioner_agent_ids: z.array(z.string().regex(/^agt_[\w-]+$/)).max(64).default([]),
  workload_trust: z.array(FleetWorkloadTrust).max(16).default([]),
  allow_delegation: z.boolean().default(false),
  expires_at: z.string().datetime(),
}).strict().superRefine((value, ctx) => {
  const rules = [...value.rules, ...value.operation_rules];
  if (rules.length === 0 || new Set(rules.map(r => r.id)).size !== rules.length) {
    ctx.addIssue({ code: 'custom', path: ['rules'], message: 'Invalid input' });
  }
  if (value.provisioner_agent_ids.length === 0 && value.workload_trust.length === 0) {
    ctx.addIssue({ code: 'custom', path: ['provisioner_agent_ids'], message: 'Invalid input' });
  }
});
export type FleetPolicyInput = z.infer<typeof FleetPolicyInput>;

export const FleetMissionStartInput = z.object({
  fleet_policy_id: z.string().regex(/^flp_[\w-]+$/),
  idempotency_key: z.string().min(8).max(128),
  intent_summary: z.string().min(1).max(500),
  requested_access: z.array(FleetAccess).max(32).default([]),
  requested_operations: z.array(FleetOperationAccess).max(32).default([]),
  limits: FleetLimits,
  expected_output_shape: z.record(z.string(), z.unknown()).optional(),
  authority_binding_ids: z.array(z.string().regex(/^abn_[\w-]+$/)).max(8).optional(),
}).strict().refine(v => v.requested_access.length + v.requested_operations.length > 0 && new Set(v.requested_access.map(a => a.connection_id)).size === v.requested_access.length, {
  message: 'Invalid input', path: ['requested_access'],
});
export type FleetMissionStartInput = z.infer<typeof FleetMissionStartInput>;

export const FleetEnrollmentInput = z.object({
  idempotency_key: z.string().min(8).max(128),
  name: z.string().min(1).max(128),
  public_key: z.object({ kty: z.literal('OKP'), crv: z.literal('Ed25519'), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict(),
  challenge_id: z.string().min(1).max(128),
  proof: z.string().min(1).max(1024),
  previous_key_proof: z.string().min(1).max(1024).optional(),
}).strict();
export type FleetEnrollmentInput = z.infer<typeof FleetEnrollmentInput>;
