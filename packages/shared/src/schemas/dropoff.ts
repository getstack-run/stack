import { z } from 'zod';
import { DROPOFF_TTL_INT_MAX } from '../constants/index.js';
import { InvalidRequestError } from '../errors/index.js';
import { assertBoundedJsonValue, assertSafeJsonSchema } from '../utils/json-schema-policy.js';

const SafeJsonSchema = z.record(z.unknown()).superRefine((schema, ctx) => {
  try {
    assertSafeJsonSchema(schema);
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : 'Unsafe JSON Schema',
    });
  }
});

const BoundedPayload = z.record(z.unknown()).superRefine((payload, ctx) => {
  try {
    assertBoundedJsonValue(payload);
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : 'Payload exceeds validation limits',
    });
  }
});

export const DropoffStatus = z.enum([
  'created',    // drop-off created, awaiting deposit
  'deposited',  // package deposited, awaiting collection
  'collected',  // package collected, custody transferred
  'expired',    // TTL exceeded without collection
  'failed',     // terminal failure
]);
export type DropoffStatus = z.infer<typeof DropoffStatus>;

export const OnExpireAction = z.enum(['notify', 'retry', 'fail']);
export type OnExpireAction = z.infer<typeof OnExpireAction>;

export const CreateDropoffInput = z.object({
  from_agent: z.string(),
  /** The one agent the drop-off is for. Name this or `to_agents`, not both. */
  to_agent: z.string().optional(),
  /**
   * Several of your agents: each can see it and is woken, and the first to collect it takes it. Name this or
   * `to_agent`, not both.
   */
  to_agents: z.array(z.string().min(1)).min(1).optional(),
  schema: SafeJsonSchema, // bounded safe JSON Schema subset
  ttl_seconds: z.number().int().min(60).max(DROPOFF_TTL_INT_MAX).optional(), // default 1800 (30 min), any time the sender names
  on_expire: OnExpireAction.optional().default('notify'),
});
export type CreateDropoffInput = z.infer<typeof CreateDropoffInput>;

/**
 * The agents a create request names, in the order named. Exactly one of `to_agent` and `to_agents`; no agent twice;
 * a group never names its own sender. Throws `InvalidRequestError`.
 */
export function namedDropoffRecipients(input: Pick<CreateDropoffInput, 'from_agent' | 'to_agent' | 'to_agents'>): string[] {
  const { to_agent: single, to_agents: group } = input;
  if ((single === undefined) === (group === undefined)) {
    throw new InvalidRequestError('Name the receiving agent in to_agent, or several in to_agents, but not both');
  }
  if (single !== undefined) {
    if (single === '') throw new InvalidRequestError('to_agent cannot be empty');
    return [single];
  }
  const agents = group!;
  if (new Set(agents).size !== agents.length) {
    throw new InvalidRequestError('to_agents names an agent more than once');
  }
  if (agents.includes(input.from_agent)) {
    throw new InvalidRequestError('A drop-off cannot name its own sender in to_agents');
  }
  return agents;
}

export const DepositInput = z.object({
  dropoff_id: z.string(),
  payload: BoundedPayload, // validated against declared schema
});
export type DepositInput = z.infer<typeof DepositInput>;

export const CollectInput = z.object({
  dropoff_id: z.string(),
});
export type CollectInput = z.infer<typeof CollectInput>;

export const Dropoff = z.object({
  id: z.string(),
  operator_id: z.string(),
  from_agent_id: z.string(),
  /** The first agent named; with several, see `to_agent_ids`. */
  to_agent_id: z.string(),
  /** Every agent that can see and collect it, in the order named. */
  to_agent_ids: z.array(z.string()),
  /** The agent that collected it; null until then. */
  collected_by_agent_id: z.string().nullable(),
  schema: z.record(z.unknown()),
  status: DropoffStatus,
  on_expire: OnExpireAction,
  // Payload fingerprints and encrypted envelopes are deliberately absent:
  // this is the public DTO, not the storage row.
  mission_id: z.string().nullable(),
  deposited_bytes: z.number().int().nonnegative(),
  created_at: z.date(),
  deposited_at: z.date().nullable(),
  collected_at: z.date().nullable(),
  expires_at: z.date(),
});
export type Dropoff = z.infer<typeof Dropoff>;
