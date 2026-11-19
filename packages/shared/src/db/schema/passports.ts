// Passports.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  boolean,
  index,
  uniqueIndex,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { operators } from './operators.js';

// ─── Passports ───────────────────────────────────────────────────────

export const passports = pgTable(
  'passports',
  {
    jti: text('jti').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    session_id: text('session_id').notNull(),
    delegation_depth: integer('delegation_depth').notNull().default(0),
    parent_passport_id: text('parent_passport_id'),
    issued_at: timestamp('issued_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'),
    // Accountability fields
    intent_summary: text('intent_summary'),
    intent_services: text('intent_services').array(),
    // Full intent refs (name + params) preserved for proxy telemetry.
    // NULL for passports issued before the column was added or for
    // callers that only sent summary + services.
    intent_refs: jsonb('intent_refs').$type<{ name: string; params: Record<string, unknown> }[]>(),
    intent_delegates: boolean('intent_delegates').notNull().default(false),
    estimated_duration_seconds: integer('estimated_duration_seconds'),
    checkpoint_interval_seconds: integer('checkpoint_interval_seconds'),
    last_checkpoint_at: timestamp('last_checkpoint_at', { withTimezone: true }),
    checkpoint_count: integer('checkpoint_count').notNull().default(0),
    checked_out_at: timestamp('checked_out_at', { withTimezone: true }),
    checkout_status: text('checkout_status'), // clean | flagged | blocked
    checkout_flags:
      jsonb('checkout_flags').$type<{ type: string; severity: string; message: string }[]>(),
    // Opt-in identity claims — tracks which claims this passport carries
    identity_claim_ids: jsonb('identity_claim_ids').$type<string[]>(),
    // denormalized list of mission_ids this
    // passport is bound to (mirrors the JWT's mission_ids claim).
    // GIN-indexed (declared in the SQL migration only — Drizzle DSL
    // doesn't support `using gin`) for the forward-cascade hot path:
    // mission revoked with reason=adversarial|cap_breach_hard → query
    // passports WHERE mission_ids @> ARRAY[ms_X] to find cascade targets.
    mission_ids: text('mission_ids').array(),
  },
  (table) => [
    index('passport_agent_idx').on(table.agent_id),
    index('passport_operator_idx').on(table.operator_id),
    index('passport_session_idx').on(table.session_id),
    uniqueIndex('passports_jti_operator_idx').on(table.jti, table.operator_id),
    check('passports_checkout_status_check', sql`${table.checkout_status} IN ('clean', 'flagged', 'blocked')`),
  ],
);
