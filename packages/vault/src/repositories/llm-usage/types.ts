// Input, result and filter types for the llm_usage repository. Re-exported from
// llm-usage-repo.ts, which stays the import path for every other package.

import type { Database, llmUsage } from '@stack/shared';
import type { LlmProvider } from '../../services/llm-gateway-service.js';

/** The transaction a usage row is written in; a deployment's own writes join it. */
export type LlmUsageTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface InsertLlmUsageInput {
  id: string;
  operator_id: string;
  agent_id: string;
  passport_jti: string;
  mission_id: string | null;
  provider: LlmProvider;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  /** NULL when pricing lookup missed (unknown model in catalog). */
  provider_cost_cents: number | null;
  markup_cents: number | null;
  total_cost_cents: number | null;
  /** the precise figures. The cent fields above are a rounded view. */
  provider_cost_microcents: number | null;
  markup_microcents: number | null;
  total_cost_microcents: number | null;
  /** 'provider_reported' | 'catalog'. NULL on a pricing miss. */
  cost_basis: string | null;
  cached_prompt_tokens: number | null;
  wallet_debited: boolean;
  surface: LlmUsageSurface;
  provider_payer: LlmUsageProviderPayer;
  stack_fee_payer: LlmUsageFeePayer;
  wallet_hold_id: string | null;
  wallet_fee_kind?: string | null;
  wallet_fee_microcents?: number | null;
  skill_id?: string | null;
  invocation_id?: string | null;
  sealed_step_index?: number | null;
  streaming: boolean;
}

/** What the wallet froze for one captured LLM call: the cents due and how the fee splits between LLM and machine time. */
export interface PreparedLlmWalletSettlement {
  centsDue: number;
  llmAllocatedMicrocents: number;
  machineAllocatedMicrocents: number;
}

/** A lowercase name: the engine's are `gateway`, `sealed_execution`, `prompt_injection_l3` and `intent_deviation`; a deployment adds its own. */
export type LlmUsageSurface = string;

export type LlmUsageProviderPayer =
  | 'customer_provider'
  | 'stack_plan'
  | 'stack_wallet'
  | 'stack_comped';

export type LlmUsageFeePayer = 'stack_plan' | 'stack_wallet' | 'stack_comped' | 'none';

export interface ListArgs {
  operatorId: string;
  limit: number;
  cursor?: string;
  provider?: LlmProvider;
  passportJti?: string;
  missionId?: string;
  agentId?: string;
  surface?: LlmUsageSurface;
  providerPayer?: LlmUsageProviderPayer;
  stackFeePayer?: LlmUsageFeePayer;
  since?: string;
  until?: string;
}

export interface SummaryArgs {
  operatorId: string;
  groupByModel: boolean;
  provider?: LlmProvider;
  passportJti?: string;
  missionId?: string;
  agentId?: string;
  surface?: LlmUsageSurface;
  providerPayer?: LlmUsageProviderPayer;
  stackFeePayer?: LlmUsageFeePayer;
  since?: string;
  until?: string;
}

export interface SummaryBucket {
  provider: string;
  model: string | null;
  surface: LlmUsageSurface;
  provider_payer: LlmUsageProviderPayer;
  stack_fee_payer: LlmUsageFeePayer;
  day: string;
  call_count: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_cents: number;
  total_markup_cents: number;
  total_cost_microcents: number;
  total_markup_microcents: number;
  cost_is_estimated: boolean;
}

/** Shape returned by `db.select().from(llmUsage)` — Drizzle infers it
 * from the schema. Exported so the service + route can type the items. */
export type LlmUsageRowSelect = typeof llmUsage.$inferSelect;
