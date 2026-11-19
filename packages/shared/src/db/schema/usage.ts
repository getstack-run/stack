// Usage counters and allowances.

import {
  pgTable,
  text,
  timestamp,
  integer,
  boolean,
  index,
  primaryKey,
  date,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

// ─── Usage rollup (survives audit-log retention) ────────────────────

/**
 * How much an operator used STACK, per day, kept forever.
 *
 * The audit log is DELETED at the tier's retention, and every activity graph
 * read that table — so an account's own growth curve vanished with the rows.
 * The RECORD (which agent did what) is what retention sells; the SHAPE ("40k
 * actions in March") is one row per operator per day and there is no reason
 * to take it away.
 *
 * Written by the worker BEFORE the prune runs, so a day is counted while its
 * rows still exist. Idempotent per (operator_id, day).
 */
export const usageDaily = pgTable(
  'usage_daily',
  {
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    /** UTC date. Stored as a real DATE — a day is a day, not an instant. */
    day: date('day').notNull(),
    /** METERED actions that day — the billable subset, what the allowance
     * counts (Money tab). */
    actions: integer('actions').notNull().default(0),
    /** EVERY audit entry that day — what happened, what the activity graphs
     * draw (the graph shows activity, not billing).
     * NULL means unknown: the day was rolled up before this column existed
     * and its audit rows are gone, so reads fall back to `actions` - a
     * lower bound, never an invention. */
    actions_total: integer('actions_total'),
    /** True only when usage_daily_by_action has the complete metered-action
     * split for this closed UTC day. Existing historical rows default false
     * because a zero detail set must never be presented as zero usage. */
    actions_detail_complete: boolean('actions_detail_complete').notNull().default(false),
    agents_registered: integer('agents_registered').notNull().default(0),
    computed_at: timestamp('computed_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.operator_id, table.day] }),
    index('usage_daily_operator_day_idx').on(table.operator_id, table.day),
  ],
);

/**
 * Durable metered-action detail for a closed UTC day.
 *
 * The audit log is hot storage. These small rows preserve the customer-facing
 * split after the source audit rows enter the cold archive. The composite FK
 * makes the detail share usage_daily's lifecycle and tenant key.
 */
export const usageDailyByAction = pgTable(
  'usage_daily_by_action',
  {
    operator_id: text('operator_id').notNull(),
    day: date('day').notNull(),
    action: text('action').notNull(),
    count: integer('count').notNull(),
    computed_at: timestamp('computed_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.operator_id, table.day, table.action] }),
    foreignKey({
      columns: [table.operator_id, table.day],
      foreignColumns: [usageDaily.operator_id, usageDaily.day],
      name: 'usage_daily_by_action_usage_day_fk',
    }).onDelete('cascade'),
    check('usage_daily_by_action_count_nonnegative', sql`${table.count} >= 0`),
  ],
);

// ─── Operator email transfer ────────────────────────────────────────

/**
 * Transferring the address an account signs in with.
 *
 * There are no passwords here: the email IS the credential, so this is a
 * transfer of control, not a profile edit. Two tokens, both sha256 at rest:
 * `confirm` goes to the new address (nothing moves until it is used), and
 * `cancel` goes to the old one immediately, so the real owner is told the
 * moment a transfer is attempted and can kill it first.
 */
/**
 * The action allowance that applied to one UTC calendar month.
 *
 * A current tier cannot answer a historical quota question after an upgrade
 * or downgrade. This small snapshot keeps that answer without copying usage.
 * A null actions_limit means the recorded tier was unlimited.
 */
export const usageMonthlyAllowances = pgTable(
  'usage_monthly_allowances',
  {
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    month: date('month').notNull(),
    tier: text('tier').notNull(),
    actions_limit: integer('actions_limit'),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.operator_id, table.month] }),
    check(
      'usage_monthly_allowances_tier_check',
      sql`${table.tier} in ('free', 'developer', 'pro', 'business', 'enterprise')`,
    ),
    check(
      'usage_monthly_allowances_limit_nonnegative',
      sql`${table.actions_limit} is null or ${table.actions_limit} >= 0`,
    ),
  ],
);
