// Passport checkpoints, checkouts and reviews.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  boolean,
  index,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { missions } from './missions.js';
import { operators } from './operators.js';
import { passports } from './passports.js';

// ─── Passport Checkpoints ───────────────────────────────────────────

export const passportCheckpoints = pgTable(
  'passport_checkpoints',
  {
    id: text('id').primaryKey(),
    passport_jti: text('passport_jti')
      .notNull()
      .references(() => passports.jti),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    submitted_at: timestamp('submitted_at', { withTimezone: true }).notNull().defaultNow(),
    services_used: text('services_used').array(),
    tool_calls: jsonb('tool_calls').$type<{ service: string; method: string; target?: string }[]>(),
    actions_count: integer('actions_count').notNull().default(0),
    delegations: text('delegations').array(),
    summary: text('summary'),
    total_actions: integer('total_actions').notNull().default(0),
    total_services: text('total_services').array(),
    // FK back-reference to the paired
    // checkpoint_approval claim in passport_claims. Best-effort
    // populated; legacy rows have it null.
    claim_id: text('claim_id'),
  },
  (table) => [
    index('chk_passport_idx').on(table.passport_jti),
    index('chk_operator_idx').on(table.operator_id),
    index('chk_claim_idx').on(table.claim_id),
  ],
);

// ─── Passport Checkouts ────────────────────────────────────────────

export const passportCheckouts = pgTable(
  'passport_checkouts',
  {
    id: text('id').primaryKey(),
    passport_jti: text('passport_jti')
      .notNull()
      .unique()
      .references(() => passports.jti),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    mission_id: text('mission_id'),
    submitted_at: timestamp('submitted_at', { withTimezone: true }).notNull().defaultNow(),
    services_used: text('services_used').array(),
    tool_calls: jsonb('tool_calls').$type<{ service: string; method: string; target?: string }[]>(),
    actions_count: integer('actions_count').notNull().default(0),
    delegations: text('delegations').array(),
    summary: text('summary'),
    review_status: text('review_status').notNull().default('pending'), // pending | clean | flagged | blocked
    review_flags:
      jsonb('review_flags').$type<{ type: string; severity: string; message: string }[]>(),
    reviewed_at: timestamp('reviewed_at', { withTimezone: true }),
  },
  (table) => [
    index('cout_operator_idx').on(table.operator_id),
    index('cout_status_idx').on(table.review_status),
    index('passport_checkouts_mission_idx').on(table.operator_id, table.mission_id),
    foreignKey({
      columns: [table.mission_id, table.operator_id],
      foreignColumns: [missions.mission_id, missions.operator_id],
      name: 'passport_checkouts_mission_operator_fk',
    }),
    check('passport_checkouts_review_status_check', sql`${table.review_status} IN ('pending', 'clean', 'flagged', 'blocked')`),
  ],
);

// ─── Passport Reviews ──────────────────────────────────────────────

export const passportReviews = pgTable(
  'passport_reviews',
  {
    id: text('id').primaryKey(),
    checkout_id: text('checkout_id')
      .notNull()
      .references(() => passportCheckouts.id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    decision: text('decision').notNull(), // approved | blocked
    notes: text('notes'),
    decided_at: timestamp('decided_at', { withTimezone: true }).notNull().defaultNow(),
    block_future: boolean('block_future').notNull().default(false),
  },
  (table) => [index('prev_agent_idx').on(table.agent_id)],
);
