// Operator-scoped reads over llm_usage: the per-mission cost sum the mission cap reads, the
// cursor-paginated list and the daily summary.

import { and, asc, desc, eq, gte, isNotNull, lt, or, sql, type SQL } from 'drizzle-orm';
import { llmUsage, type Database } from '@stack/shared';
import {
  type LlmUsageSurface,
  type LlmUsageProviderPayer,
  type LlmUsageFeePayer,
  type ListArgs,
  type SummaryArgs,
  type SummaryBucket,
  type LlmUsageRowSelect,
} from './types.js';

/**
 * Sum total_cost_cents for all llm_usage rows attributed to the given
 * mission of the given operator. NULL rows (pricing-lookup-miss case)
 * contribute 0 — we never invent a number we don't have. Uses the partial
 * `llm_usage_mission_idx`.
 */
export async function sumTotalCostByMission(
  db: Database,
  operatorId: string,
  missionId: string,
  before?: Date,
  since?: Date,
): Promise<number> {
  const [row] = await db
    .select({
      // sum micro-cents and round ONCE. Legacy rows (pre-0034)
      // have no micro-cent value; fall back to their cent column scaled up
      // so an old mission's cap still reflects what was recorded then.
      total: sql<string>`COALESCE(SUM(COALESCE(${llmUsage.total_cost_microcents}, ${llmUsage.total_cost_cents} * 1000000)), 0) / 1000000.0`,
    })
    .from(llmUsage)
    .where(
      and(
        eq(llmUsage.operator_id, operatorId),
        eq(llmUsage.mission_id, missionId),
        isNotNull(llmUsage.total_cost_cents),
        before ? lt(llmUsage.created_at, before) : undefined,
        since ? gte(llmUsage.created_at, since) : undefined,
      ),
    );
  // SUM returns a string in pg (numeric arithmetic). Round once, here.
  return Math.round(Number(row?.total ?? 0));
}

/**
 * Cursor-paginated list, operator-scoped. Cursor shape:
 * `${created_at_iso}__${id}` — composite for stable tiebreaker when
 * multiple rows share a timestamp. ORDER BY created_at DESC, id DESC.
 * LIMIT N+1 internally to detect "more pages" without a second query.
 */
export async function list(
  db: Database,
  args: ListArgs,
): Promise<{ items: LlmUsageRowSelect[]; nextCursor: string | null }> {
  const conditions: SQL[] = [eq(llmUsage.operator_id, args.operatorId)];
  if (args.provider) conditions.push(eq(llmUsage.provider, args.provider));
  if (args.passportJti) conditions.push(eq(llmUsage.passport_jti, args.passportJti));
  if (args.missionId) conditions.push(eq(llmUsage.mission_id, args.missionId));
  if (args.agentId) conditions.push(eq(llmUsage.agent_id, args.agentId));
  if (args.surface) conditions.push(eq(llmUsage.surface, args.surface));
  if (args.providerPayer) conditions.push(eq(llmUsage.provider_payer, args.providerPayer));
  if (args.stackFeePayer) conditions.push(eq(llmUsage.stack_fee_payer, args.stackFeePayer));
  if (args.since) conditions.push(gte(llmUsage.created_at, new Date(args.since)));
  if (args.until) conditions.push(lt(llmUsage.created_at, new Date(args.until)));

  // Cursor predicate: rows where (created_at, id) < (cursor_ts, cursor_id)
  // under our DESC ordering. Composite tiebreaker keeps pagination
  // stable across rows sharing a timestamp.
  if (args.cursor) {
    const parsed = parseCursor(args.cursor);
    if (parsed) {
      conditions.push(
        or(
          lt(llmUsage.created_at, new Date(parsed.createdAtIso)),
          and(
            eq(llmUsage.created_at, new Date(parsed.createdAtIso)),
            lt(llmUsage.id, parsed.id),
          )!,
        )!,
      );
    }
  }

  const rows = await db
    .select()
    .from(llmUsage)
    .where(and(...conditions))
    .orderBy(desc(llmUsage.created_at), desc(llmUsage.id))
    .limit(args.limit + 1);

  const hasMore = rows.length > args.limit;
  const items = hasMore ? rows.slice(0, args.limit) : rows;
  const last = items[items.length - 1];
  const nextCursor = hasMore && last ? buildCursor(last.created_at, last.id) : null;
  return { items, nextCursor };
}

/**
 * GROUP BY provider [+ model] + UTC day, with SUM tokens/cost + COUNT
 * calls. Filters mirror list(). NULL-cost rows contribute to the
 * count but zero to the sum (COALESCE in the aggregate). Sorted by
 * day DESC, provider ASC, model ASC for stable rendering.
 */
export async function summary(db: Database, args: SummaryArgs): Promise<SummaryBucket[]> {
  const conditions: SQL[] = [eq(llmUsage.operator_id, args.operatorId)];
  if (args.provider) conditions.push(eq(llmUsage.provider, args.provider));
  if (args.passportJti) conditions.push(eq(llmUsage.passport_jti, args.passportJti));
  if (args.missionId) conditions.push(eq(llmUsage.mission_id, args.missionId));
  if (args.agentId) conditions.push(eq(llmUsage.agent_id, args.agentId));
  if (args.surface) conditions.push(eq(llmUsage.surface, args.surface));
  if (args.providerPayer) conditions.push(eq(llmUsage.provider_payer, args.providerPayer));
  if (args.stackFeePayer) conditions.push(eq(llmUsage.stack_fee_payer, args.stackFeePayer));
  if (args.since) conditions.push(gte(llmUsage.created_at, new Date(args.since)));
  if (args.until) conditions.push(lt(llmUsage.created_at, new Date(args.until)));

  const dayExpr = sql<string>`to_char(date_trunc('day', ${llmUsage.created_at} AT TIME ZONE 'UTC'), 'YYYY-MM-DD')`;
  const callCountExpr = sql<string>`COUNT(*)`;
  const promptSumExpr = sql<string>`COALESCE(SUM(${llmUsage.prompt_tokens}), 0)`;
  const completionSumExpr = sql<string>`COALESCE(SUM(${llmUsage.completion_tokens}), 0)`;
  // aggregate in micro-cents and round once. Summing the rounded
  // per-row cent columns loses every sub-cent call entirely, which is most
  // of them. Legacy rows (pre-0034) fall back to their cent column.
  const costMicroSumExpr = sql<string>`COALESCE(SUM(COALESCE(${llmUsage.total_cost_microcents}, ${llmUsage.total_cost_cents} * 1000000)), 0)`;
  const markupMicroSumExpr = sql<string>`COALESCE(SUM(COALESCE(${llmUsage.markup_microcents}, ${llmUsage.markup_cents} * 1000000)), 0)`;
  const costSumExpr = sql<string>`${costMicroSumExpr} / 1000000.0`;
  const markupSumExpr = sql<string>`${markupMicroSumExpr} / 1000000.0`;
  const estimatedCostExpr = sql<boolean>`BOOL_OR(${llmUsage.cost_basis} IS DISTINCT FROM 'provider_reported')`;

  if (args.groupByModel) {
    const rows = await db
      .select({
        provider: llmUsage.provider,
        model: llmUsage.model,
        surface: llmUsage.surface,
        provider_payer: llmUsage.provider_payer,
        stack_fee_payer: llmUsage.stack_fee_payer,
        day: dayExpr,
        call_count: callCountExpr,
        total_prompt_tokens: promptSumExpr,
        total_completion_tokens: completionSumExpr,
        total_cost_cents: costSumExpr,
        total_markup_cents: markupSumExpr,
        total_cost_microcents: costMicroSumExpr,
        total_markup_microcents: markupMicroSumExpr,
        cost_is_estimated: estimatedCostExpr,
      })
      .from(llmUsage)
      .where(and(...conditions))
      .groupBy(
        llmUsage.provider,
        llmUsage.model,
        llmUsage.surface,
        llmUsage.provider_payer,
        llmUsage.stack_fee_payer,
        dayExpr,
      )
      .orderBy(desc(dayExpr), asc(llmUsage.surface), asc(llmUsage.provider), asc(llmUsage.model));
    return rows.map((r) => ({
      provider: r.provider,
      model: r.model,
      surface: r.surface as LlmUsageSurface,
      provider_payer: r.provider_payer as LlmUsageProviderPayer,
      stack_fee_payer: r.stack_fee_payer as LlmUsageFeePayer,
      day: r.day,
      call_count: Number(r.call_count),
      total_prompt_tokens: Number(r.total_prompt_tokens),
      total_completion_tokens: Number(r.total_completion_tokens),
      total_cost_cents: Math.round(Number(r.total_cost_cents)),
      total_markup_cents: Math.round(Number(r.total_markup_cents)),
      total_cost_microcents: Number(r.total_cost_microcents),
      total_markup_microcents: Number(r.total_markup_microcents),
      cost_is_estimated: Boolean(r.cost_is_estimated),
    }));
  }

  const rows = await db
    .select({
      provider: llmUsage.provider,
      surface: llmUsage.surface,
      provider_payer: llmUsage.provider_payer,
      stack_fee_payer: llmUsage.stack_fee_payer,
      day: dayExpr,
      call_count: callCountExpr,
      total_prompt_tokens: promptSumExpr,
      total_completion_tokens: completionSumExpr,
      total_cost_cents: costSumExpr,
      total_markup_cents: markupSumExpr,
      total_cost_microcents: costMicroSumExpr,
      total_markup_microcents: markupMicroSumExpr,
      cost_is_estimated: estimatedCostExpr,
    })
    .from(llmUsage)
    .where(and(...conditions))
    .groupBy(
      llmUsage.provider,
      llmUsage.surface,
      llmUsage.provider_payer,
      llmUsage.stack_fee_payer,
      dayExpr,
    )
    .orderBy(desc(dayExpr), asc(llmUsage.surface), asc(llmUsage.provider));
  return rows.map((r) => ({
    provider: r.provider,
    model: null,
    surface: r.surface as LlmUsageSurface,
    provider_payer: r.provider_payer as LlmUsageProviderPayer,
    stack_fee_payer: r.stack_fee_payer as LlmUsageFeePayer,
    day: r.day,
    call_count: Number(r.call_count),
    total_prompt_tokens: Number(r.total_prompt_tokens),
    total_completion_tokens: Number(r.total_completion_tokens),
    total_cost_cents: Math.round(Number(r.total_cost_cents)),
    total_markup_cents: Math.round(Number(r.total_markup_cents)),
    total_cost_microcents: Number(r.total_cost_microcents),
    total_markup_microcents: Number(r.total_markup_microcents),
    cost_is_estimated: Boolean(r.cost_is_estimated),
  }));
}

// ── Cursor helpers ───────────────────────────────────────────────────

function buildCursor(createdAt: Date, id: string): string {
  return `${createdAt.toISOString()}__${id}`;
}

function parseCursor(cursor: string): { createdAtIso: string; id: string } | null {
  const idx = cursor.lastIndexOf('__');
  if (idx <= 0 || idx === cursor.length - 2) return null;
  const createdAtIso = cursor.slice(0, idx);
  const id = cursor.slice(idx + 2);
  // Validate the timestamp half is parseable.
  if (Number.isNaN(new Date(createdAtIso).getTime())) return null;
  return { createdAtIso, id };
}
