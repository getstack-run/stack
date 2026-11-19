// LLM gateway usage and fee accounting.

import {
  pgTable,
  text,
  timestamp,
  integer,
  boolean,
  bigint,
  index,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

// ─── LLM usage ─────────────────────────────────────────
//
// One row per successful /v1/llm/<provider>/* call. Records tokens
// + estimated provider cost + STACK markup + whether the wallet debit
// landed. Read by:
//   - LlmUsageRepository.sumTotalCostByMission → mission cap gross-spend
//     enforcement (mission-service.checkGate Option A: count gross
//     provider cost, not just STACK markup, so operators reason about
//     full LLM bill under the mission rather than STACK's slice).
//   - Future dashboard surface (5.2.6) for per-operator usage drill-down.
//
// NULLable cost columns capture the pricing-lookup-miss case (model
// not in the hardcoded catalog) — the call STILL recorded, just without
// a debit. operator gets a security_event of severity 'info' in that
// case so the dashboard surfaces the gap.
//
// Indexes:
//   - llm_usage_operator_time_idx — per-operator timeline (dashboard).
//   - llm_usage_passport_time_idx — per-passport drill-down + token-field
//     genome (5.2.5 consumer).
//   - llm_usage_mission_idx — partial on mission_id IS NOT NULL for
//     the mission cap sum.
export const llmUsage = pgTable(
  'llm_usage',
  {
    id: text('id').primaryKey(), // usg_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    agent_id: text('agent_id').notNull(),
    passport_jti: text('passport_jti').notNull(),
    mission_id: text('mission_id'), // NULL when call has no mission binding
    provider: text('provider').notNull(), // 'anthropic' | 'openai' | 'openrouter'
    model: text('model').notNull(),
    prompt_tokens: integer('prompt_tokens').notNull(),
    completion_tokens: integer('completion_tokens').notNull(),
    total_tokens: integer('total_tokens').notNull(),
    provider_cost_cents: integer('provider_cost_cents'), // NULL on pricing miss
    markup_cents: integer('markup_cents'), // NULL on pricing miss
    total_cost_cents: integer('total_cost_cents'), // NULL on pricing miss
    // the three columns above are a ROUNDED VIEW for display. These
    // are the money. Whole cents cannot express a call that costs 0.003 of one,
    // and the old ceil() to a whole cent overstated small calls by orders of
    // magnitude while the list-price arithmetic overstated cached ones by 6x.
    // Anything summing spend sums micro-cents and rounds once, at the end.
    provider_cost_microcents: bigint('provider_cost_microcents', { mode: 'number' }),
    markup_microcents: bigint('markup_microcents', { mode: 'number' }),
    total_cost_microcents: bigint('total_cost_microcents', { mode: 'number' }),
    // 'provider_reported' (exact, what we were billed) | 'catalog' (list-price
    // estimate). NULL on legacy rows and on a pricing miss.
    cost_basis: text('cost_basis'),
    // Prompt tokens served from the provider's cache, when reported. The reason
    // a catalog estimate and the real bill diverge.
    cached_prompt_tokens: integer('cached_prompt_tokens'),
    wallet_debited: boolean('wallet_debited').notNull().default(false),
    // Product surface and payer make unlike bills impossible to merge in the
    // console. Legacy rows are gateway calls paid on the customer's key.
    surface: text('surface').notNull().default('gateway'),
    provider_payer: text('provider_payer').notNull().default('customer_provider'),
    stack_fee_payer: text('stack_fee_payer').notNull().default('stack_wallet'),
    // A plain column here: the hold is the wallet's. A deployment with a wallet has the database
    // constraint to the deployment's hold table (the migrations that made it are unchanged); an install has none.
    wallet_hold_id: text('wallet_hold_id'),
    // Exact wallet fee owned by this call. Remaining value is reduced only
    // when a settlement_pending hold receives a durable allocation row.
    wallet_fee_kind: text('wallet_fee_kind'),
    wallet_fee_microcents: bigint('wallet_fee_microcents', { mode: 'number' }),
    wallet_fee_microcents_remaining: bigint('wallet_fee_microcents_remaining', { mode: 'number' }),
    // Exact sealed execution context. These stay null on every other surface.
    // Plain columns for the same reason: the skills marketplace is a deployment's own.
    skill_id: text('skill_id'),
    invocation_id: text('invocation_id'),
    sealed_step_index: integer('sealed_step_index'),
    streaming: boolean('streaming').notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('llm_usage_operator_time_idx').on(table.operator_id, table.created_at),
    index('llm_usage_operator_surface_time_idx').on(
      table.operator_id,
      table.surface,
      table.created_at,
    ),
    index('llm_usage_passport_time_idx').on(table.passport_jti, table.created_at),
    // The partial index on mission_id IS NOT NULL is declared in the SQL migration,
    // like missions_active_idx and pc_subject_active_idx.
    index('llm_usage_mission_idx').on(table.mission_id),
    check(
      'llm_usage_wallet_fee_pair_check',
      sql`((${table.wallet_fee_kind} is null and ${table.wallet_fee_microcents} is null and ${table.wallet_fee_microcents_remaining} is null) or (${table.wallet_fee_kind} is not null and ${table.wallet_fee_microcents} >= 0 and ${table.wallet_fee_microcents_remaining} >= 0 and ${table.wallet_fee_microcents_remaining} <= ${table.wallet_fee_microcents}))`,
    ),
    check(
      'llm_usage_sealed_step_check',
      sql`${table.sealed_step_index} is null or ${table.sealed_step_index} >= 0`,
    ),
  ],
);
