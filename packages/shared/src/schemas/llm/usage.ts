// wire schemas for LLM usage list + summary endpoints.
//
// Shape source for:
//   - apps/api/src/routes/llm-gateway/usage-routes.ts (GET /v1/llm/usage[/summary])
//   - packages/vault/src/repositories/llm-usage-repo.ts (list + summary)
//   - packages/sdk/src/services/llm.ts (TS SDK usage.list + usage.summary)
//   - sdk-python/src/getstack/llm.py (Python SDK mirror)
//   - packages/mcp-server/src/tools/llm.ts (stack_llm_usage_list + summary tools)
//   - the Console usage view (operator-facing table)
//
// Schema is the source of truth. Wire shape never diverges from these.

import { z } from 'zod';

/** The surfaces the engine records model usage on. A deployment records its own beside them. */
export const ENGINE_LLM_USAGE_SURFACES = ['gateway', 'sealed_execution', 'prompt_injection_l3', 'intent_deviation'] as const;

/** A lowercase name: the engine's (above) or one a deployment adds. */
export const LlmUsageSurface = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);
export const LlmUsageProviderPayer = z.enum([
  'customer_provider',
  'stack_plan',
  'stack_wallet',
  'stack_comped',
]);
export const LlmUsageFeePayer = z.enum([
  'stack_plan',
  'stack_wallet',
  'stack_comped',
  'none',
]);

/** One row from the `llm_usage` table. Serialized timestamps because
 * Postgres `timestamptz` round-trips through JSON as ISO strings. */
export const LlmUsageRow = z.object({
  id: z.string(),
  operator_id: z.string(),
  agent_id: z.string(),
  passport_jti: z.string(),
  /** Null when the call had no mission binding. */
  mission_id: z.string().nullable(),
  provider: z.enum(['anthropic', 'openai', 'openrouter']),
  /** Echoed from the response body. */
  model: z.string(),
  prompt_tokens: z.number().int().nonnegative(),
  completion_tokens: z.number().int().nonnegative(),
  total_tokens: z.number().int().nonnegative(),
  /** Null on pricing-lookup miss (model not in catalog). */
  provider_cost_cents: z.number().int().nonnegative().nullable(),
  markup_cents: z.number().int().nonnegative().nullable(),
  total_cost_cents: z.number().int().nonnegative().nullable(),
  provider_cost_microcents: z.number().int().nonnegative().nullable(),
  markup_microcents: z.number().int().nonnegative().nullable(),
  total_cost_microcents: z.number().int().nonnegative().nullable(),
  cost_basis: z.enum(['provider_reported', 'catalog']).nullable(),
  cached_prompt_tokens: z.number().int().nonnegative().nullable(),
  /** False when pricing miss OR insufficient balance. */
  wallet_debited: z.boolean(),
  surface: LlmUsageSurface,
  provider_payer: LlmUsageProviderPayer,
  stack_fee_payer: LlmUsageFeePayer,
  wallet_hold_id: z.string().nullable(),
  streaming: z.boolean(),
  /** ISO 8601 timestamp. */
  created_at: z.string(),
});

export type LlmUsageRow = z.infer<typeof LlmUsageRow>;

/** Filter + pagination params for `GET /v1/llm/usage`. */
export const ListLlmUsageQuery = z.object({
  /** Page size (default 20, max 100). */
  limit: z.coerce.number().int().min(1).max(100).optional().default(20),
  /** Cursor from prior page's `next_cursor`. Shape: `${created_at_iso}__${id}`. */
  cursor: z.string().optional(),
  provider: z.enum(['anthropic', 'openai', 'openrouter']).optional(),
  passport_jti: z.string().optional(),
  mission_id: z.string().optional(),
  agent_id: z.string().optional(),
  surface: LlmUsageSurface.optional(),
  provider_payer: LlmUsageProviderPayer.optional(),
  stack_fee_payer: LlmUsageFeePayer.optional(),
  /** ISO timestamp, inclusive lower bound on `created_at`. */
  since: z.string().optional(),
  /** ISO timestamp, exclusive upper bound on `created_at`. */
  until: z.string().optional(),
});

export type ListLlmUsageQueryInput = z.input<typeof ListLlmUsageQuery>;
export type ListLlmUsageQuery = z.infer<typeof ListLlmUsageQuery>;

export const ListLlmUsageResult = z.object({
  items: z.array(LlmUsageRow),
  /** Opaque pagination cursor; null when no more pages. */
  next_cursor: z.string().nullable(),
});

export type ListLlmUsageResult = z.infer<typeof ListLlmUsageResult>;

/** Filter params for `GET /v1/llm/usage/summary`. */
export const SummaryLlmUsageQuery = z.object({
  provider: z.enum(['anthropic', 'openai', 'openrouter']).optional(),
  passport_jti: z.string().optional(),
  mission_id: z.string().optional(),
  agent_id: z.string().optional(),
  surface: LlmUsageSurface.optional(),
  provider_payer: LlmUsageProviderPayer.optional(),
  stack_fee_payer: LlmUsageFeePayer.optional(),
  since: z.string().optional(),
  until: z.string().optional(),
  /** When false, groups by provider + day only (collapses across models).
   * Default true — operator wants per-model resolution by default. */
  group_by_model: z.coerce.boolean().optional().default(true),
});

export type SummaryLlmUsageQueryInput = z.input<typeof SummaryLlmUsageQuery>;
export type SummaryLlmUsageQuery = z.infer<typeof SummaryLlmUsageQuery>;

/** One aggregate bucket from the summary endpoint. */
export const LlmUsageSummaryBucket = z.object({
  provider: z.string(),
  /** Null when query had `group_by_model=false` (collapsed across models). */
  model: z.string().nullable(),
  surface: LlmUsageSurface,
  provider_payer: LlmUsageProviderPayer,
  stack_fee_payer: LlmUsageFeePayer,
  /** YYYY-MM-DD (UTC). */
  day: z.string(),
  call_count: z.number().int().nonnegative(),
  total_prompt_tokens: z.number().int().nonnegative(),
  total_completion_tokens: z.number().int().nonnegative(),
  /** Sum of `total_cost_cents` over rows in the bucket; excludes NULL-cost rows. */
  total_cost_cents: z.number().int().nonnegative(),
  total_markup_cents: z.number().int().nonnegative(),
  /** Exact aggregate. Consumers should sum this field across buckets and round once. */
  total_cost_microcents: z.number().int().nonnegative(),
  total_markup_microcents: z.number().int().nonnegative(),
  /** True for legacy or catalog-priced rows. False only when every cost came from the provider. */
  cost_is_estimated: z.boolean(),
});

export type LlmUsageSummaryBucket = z.infer<typeof LlmUsageSummaryBucket>;

export const SummaryLlmUsageResult = z.object({
  buckets: z.array(LlmUsageSummaryBucket),
});

export type SummaryLlmUsageResult = z.infer<typeof SummaryLlmUsageResult>;
