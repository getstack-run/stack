// Drop-offs.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  bigint,
  index,
  check,
  foreignKey,
  primaryKey,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { missions } from './missions.js';
import { operators } from './operators.js';

// ─── Drop-offs ───────────────────────────────────────────────────────

export const dropoffs = pgTable(
  'dropoffs',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    from_agent_id: text('from_agent_id')
      .notNull()
      .references(() => agents.id),
    to_agent_id: text('to_agent_id')
      .notNull()
      .references(() => agents.id),
    schema: jsonb('schema').notNull().$type<Record<string, unknown>>(),
    status: text('status').notNull().default('created'), // created | deposited | collected | expired
    on_expire: text('on_expire').notNull().default('notify'), // notify | retry | fail
    payload_hash: text('payload_hash'),
    payload_encrypted: text('payload_encrypted'), // KMS-encrypted, deleted after collection
    // v1 rows predate dropoff_id-bound encryption context. v2 rows are bound
    // to the exact operator/store/dropoff tuple and never use a legacy retry.
    payload_envelope_version: integer('payload_envelope_version').notNull().default(2),
    // Immutable plaintext-size accounting. Retained after ciphertext purge so
    // a mission's cumulative transfer cap cannot be reclaimed by collecting.
    deposited_bytes: bigint('deposited_bytes', { mode: 'number' }).notNull().default(0),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    deposited_at: timestamp('deposited_at', { withTimezone: true }),
    collected_at: timestamp('collected_at', { withTimezone: true }),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    // mission attribution for max_dropoff_bytes
    // cap enforcement. Populated at deposit time when the from_agent's
    // passport carries an active mission_id. Null otherwise. Partial GIN
    // index in the SQL migration.
    mission_id: text('mission_id'),
    // Where the deposited content came from: the ORIGINAL services it was
    // read from, matched at deposit against the depositor's Mission
    // observations. The collector inherits these sources. The item maps hold
    // one-way digests only and are dropped at collection; the source list
    // stays as evidence. Shape: `DropoffProvenance`.
    provenance: jsonb('provenance').$type<Record<string, unknown>>(),
    // When the deployment's deposit hooks last ran to completion for this drop-off (STACK wakes the agents it names).
    // Null for a deposit whose hooks have not run, which a sweep finds and runs again; the hooks are idempotent.
    deposit_announced_at: timestamp('deposit_announced_at', { withTimezone: true }),
    // When the end of a deposited drop-off (collected or expired) was announced to the agent that deposited it (STACK
    // wakes it). Null for an end not yet announced, which a sweep finds; set at once when the depositor ended it itself.
    end_announced_at: timestamp('end_announced_at', { withTimezone: true }),
  },
  (table) => [
    index('dropoff_operator_idx').on(table.operator_id),
    index('dropoff_from_agent_idx').on(table.from_agent_id),
    index('dropoff_to_agent_idx').on(table.to_agent_id),
    index('dropoff_status_idx').on(table.status),
    index('dropoff_expires_idx').on(table.expires_at),
    index('dropoff_mission_idx').on(table.operator_id, table.mission_id),
    index('dropoff_end_unannounced_idx')
      .on(table.deposited_at)
      .where(sql`${table.status} IN ('collected', 'expired') AND ${table.end_announced_at} IS NULL AND ${table.deposited_at} IS NOT NULL`),
    foreignKey({
      columns: [table.mission_id, table.operator_id],
      foreignColumns: [missions.mission_id, missions.operator_id],
      name: 'dropoffs_mission_operator_fk',
    }),
    check('dropoffs_status_check', sql`${table.status} IN ('created', 'deposited', 'collected', 'expired')`),
  ],
);

// ─── Who a drop-off is for ───────────────────────────────────────────

// Every agent a drop-off names, the first included, in the order named. A
// drop-off for one agent has one row; a group drop-off has one per agent. Each
// named agent can see and collect it, and the first to collect takes it: the
// row of the agent that did carries `collected_at`, and the partial unique
// index lets only one row per drop-off ever carry it. `dropoffs.to_agent_id`
// stays the first agent named, so a reader that knows one recipient is
// unchanged, and a row from before this table is read as naming that agent
// alone (see the repository).
export const dropoffRecipients = pgTable(
  'dropoff_recipients',
  {
    dropoff_id: text('dropoff_id')
      .notNull()
      .references(() => dropoffs.id, { onDelete: 'cascade' }),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    // 0 is the first agent named.
    position: integer('position').notNull(),
    collected_at: timestamp('collected_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.dropoff_id, table.agent_id] }),
    index('dropoff_recipients_agent_idx').on(table.agent_id, table.dropoff_id),
    index('dropoff_recipients_operator_idx').on(table.operator_id),
    uniqueIndex('dropoff_recipients_one_collector_idx')
      .on(table.dropoff_id)
      .where(sql`${table.collected_at} IS NOT NULL`),
    check('dropoff_recipients_position_check', sql`${table.position} >= 0`),
  ],
);
