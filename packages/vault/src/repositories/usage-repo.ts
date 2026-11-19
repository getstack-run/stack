import { and, eq, gte, inArray, lt, or, sql } from 'drizzle-orm';
import {
  type Database,
  auditLog,
  operators,
  usageDaily,
  usageDailyByAction,
  usageMonthlyAllowances,
} from '@stack/shared';

export type UsageDetailCoverage = 'complete' | 'partial' | 'unavailable';
export type UsageTotalCoverage = 'complete' | 'lower_bound';

export interface UsageRangeResult {
  meteredTotal: number;
  activityTotal: number;
  nonMetered: number | null;
  totalCoverage: UsageTotalCoverage;
  detailCoverage: UsageDetailCoverage;
  byKind?: Record<string, number>;
}

export interface MonthlyActionAllowance {
  month: string;
  tier: string;
  actions_limit: number | null;
}

export interface UsageSliceInput {
  historicalDays: Array<{
    actions: number;
    actions_total: number | null;
    actions_detail_complete: boolean;
  }>;
  historicalByKind: Record<string, number>;
  liveByAction: Record<string, number>;
  /** The audit actions that count against the allowance. Absent: none does, as in an engine with no meter. */
  meteredActions?: readonly string[];
}

/** What a deployment tells the usage reads about its meter. */
export interface UsageRepositoryOptions {
  /** The audit actions the deployment's meter counts. Absent: none (an engine alone meters nothing). */
  meteredActions?: readonly string[];
}

/** Merge durable closed days with the live, incomplete UTC day. */
export function mergeUsageSlices(input: UsageSliceInput): UsageRangeResult {
  const meteredActionSet = new Set<string>(input.meteredActions ?? []);
  let historicalMetered = 0;
  let historicalActivity = 0;
  let incompleteDetailActions = 0;
  let completeDetailActions = 0;
  let totalCoverage: UsageTotalCoverage = 'complete';

  for (const day of input.historicalDays) {
    historicalMetered += day.actions;
    historicalActivity += day.actions_total ?? day.actions;
    if (day.actions_total === null) totalCoverage = 'lower_bound';
    if (day.actions_detail_complete) {
      completeDetailActions += day.actions;
    } else {
      incompleteDetailActions += day.actions;
    }
  }

  let liveActivity = 0;
  let liveMetered = 0;
  const byKind: Record<string, number> = { ...input.historicalByKind };
  for (const [action, count] of Object.entries(input.liveByAction)) {
    liveActivity += count;
    if (!meteredActionSet.has(action)) continue;
    liveMetered += count;
    byKind[action] = (byKind[action] ?? 0) + count;
  }

  const meteredTotal = historicalMetered + liveMetered;
  const activityTotal = historicalActivity + liveActivity;
  const historicalDetailTotal = Object.values(input.historicalByKind).reduce(
    (sum, count) => sum + count,
    0,
  );
  const detailMismatch = historicalDetailTotal !== completeDetailActions;
  const knownDetailActions = historicalDetailTotal + liveMetered;
  const unknownDetailActions = incompleteDetailActions + (detailMismatch ? 1 : 0);
  const detailCoverage: UsageDetailCoverage =
    unknownDetailActions === 0 ? 'complete' : knownDetailActions > 0 ? 'partial' : 'unavailable';

  return {
    meteredTotal,
    activityTotal,
    nonMetered: totalCoverage === 'complete' ? Math.max(0, activityTotal - meteredTotal) : null,
    totalCoverage,
    detailCoverage,
    ...(detailCoverage === 'complete' ? { byKind } : {}),
  };
}

export function applyHistoricalBoundaryCoverage(
  usage: UsageRangeResult,
  lowerBound: boolean,
): UsageRangeResult {
  if (!lowerBound) return usage;
  const { byKind: _byKind, ...withoutBreakdown } = usage;
  return {
    ...withoutBreakdown,
    nonMetered: null,
    totalCoverage: 'lower_bound',
    detailCoverage:
      usage.detailCoverage === 'unavailable' || usage.meteredTotal === 0
        ? 'unavailable'
        : 'partial',
  };
}

function utcDayStart(date: Date): Date {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function dayKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export interface UsageWindowSlices {
  historical: { startDay: string; endDay: string } | null;
  live: { sinceMs: number; untilMs: number } | null;
  historicalBoundaryLowerBound: boolean;
}

/** Split one range at the current UTC midnight. The two slices never overlap. */
export function splitUsageWindow(
  since: Date,
  until: Date | undefined,
  now: Date,
): UsageWindowSlices {
  const sinceMs = since.getTime();
  const effectiveUntilMs = Math.min(until?.getTime() ?? now.getTime(), now.getTime());
  if (effectiveUntilMs <= sinceMs) {
    return { historical: null, live: null, historicalBoundaryLowerBound: false };
  }

  const todayStart = utcDayStart(now);
  const todayStartMs = todayStart.getTime();
  const historicalEndMs = Math.min(effectiveUntilMs, todayStartMs);
  const sinceDayStartMs = utcDayStart(since).getTime();
  const historicalEndDayStartMs = utcDayStart(new Date(historicalEndMs)).getTime();
  const historicalStartMs = sinceMs === sinceDayStartMs ? sinceMs : sinceDayStartMs + 86_400_000;
  const historicalBoundaryLowerBound =
    (sinceMs < historicalEndMs && sinceMs !== sinceDayStartMs) ||
    (historicalEndMs < todayStartMs &&
      historicalEndMs > sinceMs &&
      historicalEndMs !== historicalEndDayStartMs);
  const liveStartMs = Math.max(sinceMs, todayStartMs);

  return {
    historical:
      historicalStartMs < historicalEndDayStartMs
        ? {
            startDay: dayKey(new Date(historicalStartMs)),
            endDay: dayKey(new Date(historicalEndDayStartMs)),
          }
        : null,
    live:
      liveStartMs < effectiveUntilMs ? { sinceMs: liveStartMs, untilMs: effectiveUntilMs } : null,
    historicalBoundaryLowerBound,
  };
}

/**
 * Read usage for one operator.
 *
 * Closed UTC days come only from the durable daily tables. The current UTC
 * day comes only from the hot audit log. This split prevents double counting.
 */
export class UsageRepository {
  private readonly meteredActions: readonly string[];

  constructor(
    private db: Database,
    options: UsageRepositoryOptions = {},
  ) {
    this.meteredActions = options.meteredActions ?? [];
  }

  async getMonthlyActionAllowance(
    operatorId: string,
    month: string,
  ): Promise<MonthlyActionAllowance | null> {
    const [row] = await this.db
      .select({
        month: usageMonthlyAllowances.month,
        tier: usageMonthlyAllowances.tier,
        actions_limit: usageMonthlyAllowances.actions_limit,
      })
      .from(usageMonthlyAllowances)
      .where(
        and(
          eq(usageMonthlyAllowances.operator_id, operatorId),
          eq(usageMonthlyAllowances.month, month),
        ),
      )
      .limit(1);
    return row ?? null;
  }

  async getRange(
    operatorId: string,
    since: Date,
    until?: Date,
    now = new Date(),
  ): Promise<UsageRangeResult> {
    const slices = splitUsageWindow(since, until, now);
    if (!slices.historical && !slices.live) {
      return applyHistoricalBoundaryCoverage(
        mergeUsageSlices({
          historicalDays: [],
          historicalByKind: {},
          liveByAction: {},
          meteredActions: this.meteredActions,
        }),
        slices.historicalBoundaryLowerBound,
      );
    }

    const [historicalDays, historicalDetailRows, liveRows] = await Promise.all([
      slices.historical
        ? this.db
            .select({
              actions: usageDaily.actions,
              actions_total: usageDaily.actions_total,
              actions_detail_complete: usageDaily.actions_detail_complete,
            })
            .from(usageDaily)
            .where(
              and(
                eq(usageDaily.operator_id, operatorId),
                gte(usageDaily.day, slices.historical.startDay),
                lt(usageDaily.day, slices.historical.endDay),
              ),
            )
        : Promise.resolve([]),
      slices.historical
        ? this.db
            .select({
              action: usageDailyByAction.action,
              count: usageDailyByAction.count,
            })
            .from(usageDailyByAction)
            .innerJoin(
              usageDaily,
              and(
                eq(usageDaily.operator_id, usageDailyByAction.operator_id),
                eq(usageDaily.day, usageDailyByAction.day),
              ),
            )
            .where(
              and(
                eq(usageDailyByAction.operator_id, operatorId),
                eq(usageDaily.actions_detail_complete, true),
                gte(usageDailyByAction.day, slices.historical.startDay),
                lt(usageDailyByAction.day, slices.historical.endDay),
              ),
            )
        : Promise.resolve([]),
      slices.live
        ? this.db
            .select({
              action: auditLog.action,
              count: sql<number>`count(*)::int`,
            })
            .from(auditLog)
            .where(
              and(
                eq(auditLog.operator_id, operatorId),
                gte(auditLog.timestamp, slices.live.sinceMs),
                lt(auditLog.timestamp, slices.live.untilMs),
              ),
            )
            .groupBy(auditLog.action)
        : Promise.resolve([]),
    ]);

    const historicalByKind: Record<string, number> = {};
    for (const row of historicalDetailRows) {
      historicalByKind[row.action] = (historicalByKind[row.action] ?? 0) + row.count;
    }

    const liveByAction: Record<string, number> = {};
    for (const row of liveRows) {
      liveByAction[row.action] = (liveByAction[row.action] ?? 0) + row.count;
    }

    const merged = mergeUsageSlices({ historicalDays, historicalByKind, liveByAction, meteredActions: this.meteredActions });
    return applyHistoricalBoundaryCoverage(merged, slices.historicalBoundaryLowerBound);
  }

  /**
   * Metered actions for a billing account's whole pool: the account itself
   * plus every white-label tenant it has ever had (revoked tenants' usage
   * still counted against the month it happened in). Closed UTC days come
   * from usage_daily, the current day from the audit log, with the same
   * split as getRange. Two grouped queries, no per-tenant round trips.
   */
  async getPoolMeteredTotals(
    billingOperatorId: string,
    since: Date,
    until?: Date,
    now = new Date(),
  ): Promise<{ total: number; byOperator: Record<string, number>; tenantCount: number }> {
    const members = await this.db
      .select({ id: operators.id })
      .from(operators)
      .where(or(eq(operators.id, billingOperatorId), eq(operators.parent_operator_id, billingOperatorId)));
    const ids = members.map((row) => row.id);
    const byOperator: Record<string, number> = Object.fromEntries(ids.map((id) => [id, 0]));
    const tenantCount = ids.filter((id) => id !== billingOperatorId).length;
    if (ids.length === 0) return { total: 0, byOperator, tenantCount };

    const slices = splitUsageWindow(since, until, now);
    const [historicalRows, liveRows] = await Promise.all([
      slices.historical
        ? this.db
            .select({
              operatorId: usageDaily.operator_id,
              count: sql<number>`coalesce(sum(${usageDaily.actions}), 0)::bigint`,
            })
            .from(usageDaily)
            .where(and(
              inArray(usageDaily.operator_id, ids),
              gte(usageDaily.day, slices.historical.startDay),
              lt(usageDaily.day, slices.historical.endDay),
            ))
            .groupBy(usageDaily.operator_id)
        : Promise.resolve([]),
      slices.live
        ? this.db
            .select({
              operatorId: auditLog.operator_id,
              count: sql<number>`count(*)::bigint`,
            })
            .from(auditLog)
            .where(and(
              inArray(auditLog.operator_id, ids),
              inArray(auditLog.action, [...this.meteredActions]),
              gte(auditLog.timestamp, slices.live.sinceMs),
              lt(auditLog.timestamp, slices.live.untilMs),
            ))
            .groupBy(auditLog.operator_id)
        : Promise.resolve([]),
    ]);

    let total = 0;
    for (const row of [...historicalRows, ...liveRows]) {
      const count = Number(row.count);
      if (!row.operatorId) continue;
      byOperator[row.operatorId] = (byOperator[row.operatorId] ?? 0) + count;
      total += count;
    }
    return { total, byOperator, tenantCount };
  }
}
