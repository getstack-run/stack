// Intent approvals.

import {
  pgTable,
  text,
  timestamp,
  integer,
  boolean,
  index,
  uniqueIndex,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { operators } from './operators.js';
import { passports } from './passports.js';
import { passportClaims } from './signed-records.js';

// ─── Intent Approvals ───────────
// Pre-execution approval gate for enforced Intents. An agent (or its
// SDK) calls POST /v1/intents/submit with a candidate IntentClaim;
// STACK registers the intent_claim, optionally runs a simulation,
// creates a row here with status='pending', and notifies the operator.
// The operator approves or rejects via /v1/intents/:id/approve|reject.
// Rejection auto-revokes the passport (the agent went off-script —
// fail-closed). Expired pending rows (past TTL) flip to status='expired'.
//
// Opt-in for v1: callers explicitly use the submit endpoint. Existing
// producers (proxy.ts, skills.ts, a2a.ts) are NOT rewired — that's a
// separate change that wires one producer at a time.

export const intentApprovals = pgTable(
  'intent_approvals',
  {
    id: text('id').primaryKey(), // ia_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id, { onDelete: 'cascade' }),
    passport_jti: text('passport_jti')
      .notNull()
      .references(() => passports.jti, { onDelete: 'cascade' }),
    intent_claim_id: text('intent_claim_id')
      .notNull()
      .references(() => passportClaims.claim_id, { onDelete: 'cascade' }),
    // Optional: the paired intent_simulation claim that informed this
    // approval decision. Set when /submit ran simulation; null when
    // simulation was skipped (e.g. submit_only=true).
    simulated_claim_id: text('simulated_claim_id').references(() => passportClaims.claim_id, {
      onDelete: 'set null',
    }),
    status: text('status').notNull(), // 'pending' | 'approved' | 'consuming' | 'rejected' | 'expired' | 'consumed'
    // A deterministic operation may reclaim only its own crash-stranded
    // consuming reservation. Raw idempotency keys are never stored.
    consuming_owner_hash: text('consuming_owner_hash'),
    fleet_policy_id: text('fleet_policy_id'),
    fleet_policy_revision: integer('fleet_policy_revision'),
    fleet_mission_id: text('fleet_mission_id'),
    fleet_request_hash: text('fleet_request_hash'),
    fleet_review_key: text('fleet_review_key'),
    fleet_review_encrypted: text('fleet_review_encrypted'),
    fleet_review_key_ref: text('fleet_review_key_ref'),
    // 'consumed' added: gate flips
    // 'approved' → 'consumed' on first successful outcome via atomic CAS.
    // Prevents replay of the same approval id beyond a single successful
    // call. Failed calls (intent_outcome.status='failed') do NOT consume —
    // the agent can retry under the same approval until success lands.
    // Column type is `text` (not pg enum) so no DDL needed for the value
    // extension; app layer enforces the union.
    requested_at: timestamp('requested_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    decided_at: timestamp('decided_at', { withTimezone: true }),
    // For audit: which identity decided. operator_id alone if the
    // operator API key approved; populated member_id when a team
    // member approved via a dashboard or OAuth session.
    decided_by_member_id: text('decided_by_member_id'),
    notes: text('notes'), // operator's reason (capped at app layer)
    block_future: boolean('block_future').notNull().default(false), // reject + block agent in one shot
  },
  (table) => [
    uniqueIndex('ia_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('ia_fleet_review_key_unique').on(table.operator_id, table.fleet_review_key),
    check(
      'ia_fleet_review_custody_complete',
      sql`(${table.fleet_review_encrypted} IS NULL AND ${table.fleet_review_key_ref} IS NULL) OR (${table.fleet_review_encrypted} IS NOT NULL AND ${table.fleet_review_key_ref} IS NOT NULL AND ${table.fleet_policy_id} IS NOT NULL)`,
    ),
    index('ia_operator_idx').on(table.operator_id),
    index('ia_passport_idx').on(table.passport_jti),
    index('ia_status_idx').on(table.status), // hot path: list pending
    // The sweep that ends pending approvals whose time has passed and tells their agents.
    index('ia_pending_expiry_idx').on(table.expires_at).where(sql`${table.status} = 'pending'`),
    index('ia_intent_claim_idx').on(table.intent_claim_id),
    check(
      'ia_consuming_owner_check',
      sql`(${table.status} in ('approved', 'consuming', 'consumed') or ${table.consuming_owner_hash} is null) and (${table.consuming_owner_hash} is null or ${table.consuming_owner_hash} ~ '^[0-9a-f]{64}$')`,
    ),
    check('intent_approvals_status_check', sql`${table.status} IN ('pending', 'approved', 'rejected', 'consuming', 'consumed', 'expired')`),
  ],
);
