// Missions, their outputs and operator decisions.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  bigint,
  index,
  uniqueIndex,
  primaryKey,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';
import { passportClaims } from './signed-records.js';

// ─── Missions (of Signed Primitive epic) ──
// Denormalized cache of mission claims for proxy-gate hot path lookup.
// The signed MissionClaim envelope in passport_claims is canonical;
// completion/revocation emit NEW mission claims and update the row's
// claim_id pointer. terminal_state on the claim envelope is the
// audit-grade reason; the row's completed_at + revoked_at + revoked_reason
// are denormalized for filtering convenience.
//
// Partial indexes (missions_active_idx, missions_expires_active_idx)
// are declared in the SQL migration only — Drizzle DSL doesn't support
// WHERE clauses on index definitions. Same pattern as the
// `pc_subject_active_idx` partial on passport_claims.

export const missions = pgTable(
  'missions',
  {
    mission_id: text('mission_id').primaryKey(), // ms_*
    assigned_agent_id: text('assigned_agent_id'),
    authorization_digest: text('authorization_digest'),
    claim_id: text('claim_id')
      .notNull()
      .references(() => passportClaims.claim_id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    // baseline-source passport JTI. Operational read path
    // for MissionService.complete() + revoke() behavioral_diff
    // computation. Mirror of the schema field on MissionClaim. Nullable
    // for backward compat with missions that opened without
    // baseline snapshotting + missions opened post-5.1.5 without an
    // explicit passport_jti input.
    passport_jti: text('passport_jti'),
    intent_summary: text('intent_summary').notNull(),
    intent_services: text('intent_services').array().notNull().default([]),
    expected_counterparties: text('expected_counterparties').array().notNull().default([]),
    // Six caps. Null = unbounded for nullable caps; empty map = no
    // per-service limits.
    max_actions: integer('max_actions'),
    max_dropoff_bytes: bigint('max_dropoff_bytes', { mode: 'number' }),
    coverage_cap_cents: bigint('coverage_cap_cents', { mode: 'number' }),
    max_duration_seconds: integer('max_duration_seconds'),
    max_concurrent_intents: integer('max_concurrent_intents'),
    max_actions_per_service: jsonb('max_actions_per_service')
      .notNull()
      .$type<Record<string, number>>()
      .default({}),
    // What each cap does when it is reached: 'pause' (the default for a cap the map leaves out), 'refuse_action' or
    // 'end_mission'. Set at open. Kept on the row only: the signed Mission claim's schema is published and its
    // `cap_behavior` names the earlier values, so new claims carry an empty map there.
    cap_behavior: jsonb('cap_behavior')
      .notNull()
      .$type<Record<string, 'pause' | 'refuse_action' | 'end_mission'>>()
      .default({}),
    // Whether coverage_cap_cents counts the whole Mission ('mission') or one day ending at midnight in cap_time_zone.
    coverage_cap_period: text('coverage_cap_period').notNull().default('mission'),
    cap_time_zone: text('cap_time_zone').notNull().default('UTC'),
    // Set while a cap paused the Mission: every action is refused until the owner's review; the cap (and the service
    // of a per-service cap) that paused it. Cleared when the owner raises the limit or lets it continue.
    paused_at: timestamp('paused_at', { withTimezone: true }),
    paused_cap: text('paused_cap'),
    paused_service: text('paused_service'),
    // What the owner pre-approved of the Mission's print-on-demand orders, in cents across all of them. Null: none,
    // every order waits for the owner's yes.
    making_orders_up_to_cents: bigint('making_orders_up_to_cents', { mode: 'number' }),
    // Baseline genome snapshot frozen at mission open (an earlier change ships
    // real genome integration; v1 stores opaque jsonb).
    baseline_profile: jsonb('baseline_profile').$type<Record<string, unknown>>(),
    expected_output_shape: jsonb('expected_output_shape').$type<Record<string, unknown>>(),
    // Who this Mission may send to, for the policy send rules that leave their recipients to each Mission: a list of
    // { path, op: 'eq' | 'in', value } pins. Written at open; only the owner adds to them afterwards
    // (`MissionRepository.updateRecipientPins`). Null: no pins.
    recipient_pins: jsonb('recipient_pins').$type<Array<{ path: string; op: 'eq' | 'in'; value: string | number | string[] }>>(),
    started_at: timestamp('started_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    completed_at: timestamp('completed_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'), // 'adversarial' | 'cap_breach_hard' | 'operator_initiated_clean' | 'cascade_from_passport'
    terminal_state: text('terminal_state'), // matches MissionClaim.terminal_state enum
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('missions_operator_started_idx').on(table.operator_id, table.started_at),
    index('missions_active_idx').on(table.operator_id),
    index('missions_expires_active_idx').on(table.expires_at),
    index('missions_claim_idx').on(table.claim_id),
    uniqueIndex('missions_id_operator_idx').on(table.mission_id, table.operator_id),
    check('missions_coverage_cap_period_check', sql`${table.coverage_cap_period} IN ('mission', 'day')`),
    check('missions_making_allowance_check', sql`${table.making_orders_up_to_cents} IS NULL OR ${table.making_orders_up_to_cents} >= 0`),
    check(
      'missions_paused_cap_check',
      sql`${table.paused_cap} IS NULL OR ${table.paused_cap} IN ('coverage_cap_cents', 'max_dropoff_bytes', 'max_concurrent_intents', 'max_actions', 'max_duration_seconds', 'max_actions_per_service')`,
    ),
  ],
);

export const missionOutputs = pgTable(
  'mission_outputs',
  {
    mission_id: text('mission_id').primaryKey(),
    operator_id: text('operator_id').notNull(),
    output_digest: text('output_digest').notNull(),
    output_encrypted: text('output_encrypted').notNull(),
    key_ref: text('key_ref').notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    foreignKey({
      columns: [table.mission_id, table.operator_id],
      foreignColumns: [missions.mission_id, missions.operator_id],
    }).onDelete('cascade'),
    index('mission_outputs_operator_idx').on(table.operator_id),
    check('mission_outputs_output_digest_check', sql`${table.output_digest} ~ '^[0-9a-f]{64}$'`),
  ],
);

// Signed operator decisions.
export const operatorDecisions = pgTable(
  'operator_decisions',
  {
    id: text('id').primaryKey(),
    claim_id: text('claim_id')
      .notNull()
      .unique()
      .references(() => passportClaims.claim_id, { onDelete: 'cascade' }),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    mission_id: text('mission_id').notNull(),
    idempotency_key: text('idempotency_key').notNull(),
    action: text('action').notNull(),
    effect: text('effect').notNull(),
    effect_scope: text('effect_scope').notNull(),
    target_agent_id: text('target_agent_id'),
    author_kind: text('author_kind').notNull(),
    author_member_id: text('author_member_id'),
    author_role: text('author_role'),
    /** the partner whose human decided for this tenant. */
    author_partner_operator_id: text('author_partner_operator_id'),
    decided_at: timestamp('decided_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('operator_decisions_operator_id_idempotency_key_key').on(
      table.operator_id,
      table.idempotency_key,
    ),
    uniqueIndex('operator_decisions_id_operator_idx').on(table.id, table.operator_id),
    index('operator_decisions_mission_idx').on(
      table.operator_id,
      table.mission_id,
      table.decided_at,
    ),
    foreignKey({
      columns: [table.mission_id, table.operator_id],
      foreignColumns: [missions.mission_id, missions.operator_id],
      name: 'operator_decisions_mission_operator_fk',
    }).onDelete('cascade'),
    check(
      'operator_decisions_effect_scope_check',
      sql`${table.effect_scope} IN ('mission', 'agent_global')`,
    ),
    check(
      'operator_decisions_author_check',
      sql`(${table.author_kind} = 'operator_owner' AND ${table.author_member_id} IS NULL AND ${table.author_role} IS NULL AND ${table.author_partner_operator_id} IS NULL)
        OR (${table.author_kind} = 'team_member' AND ${table.author_member_id} IS NOT NULL AND ${table.author_role} IN ('standard', 'admin') AND ${table.author_partner_operator_id} IS NULL)
        OR (${table.author_kind} = 'partner_admin' AND ${table.author_partner_operator_id} IS NOT NULL
          AND ${table.action} IN ('governance_approved', 'governance_rejected')
          AND ((${table.author_member_id} IS NULL AND ${table.author_role} IS NULL)
            OR (${table.author_member_id} IS NOT NULL AND ${table.author_role} = 'admin')))`,
    ),
  ],
);

export const operatorDecisionSources = pgTable(
  'operator_decision_sources',
  {
    decision_id: text('decision_id').notNull(),
    operator_id: text('operator_id').notNull(),
    source_type: text('source_type').notNull(),
    source_id: text('source_id').notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.decision_id, table.source_type, table.source_id] }),
    uniqueIndex('operator_decision_sources_operator_id_source_type_source_id_key').on(
      table.operator_id,
      table.source_type,
      table.source_id,
    ),
    foreignKey({
      columns: [table.decision_id, table.operator_id],
      foreignColumns: [operatorDecisions.id, operatorDecisions.operator_id],
      name: 'operator_decision_sources_decision_operator_fk',
    }).onDelete('cascade'),
    check(
      'operator_decision_sources_type_check',
      sql`${table.source_type} IN ('checkout', 'security_event', 'detector_claim', 'approval')`,
    ),
  ],
);

export const twinRuns = pgTable(
  'twin_runs',
  {
    id: text('id').primaryKey(), // twr_*
    mission_id: text('mission_id')
      .notNull()
      .references(() => missions.mission_id, { onDelete: 'cascade' }), // ms_*
    real_passport_jti: text('real_passport_jti').notNull(), // pas_*
    twin_passport_jti: text('twin_passport_jti').notNull(), // pas_*
    started_at: timestamp('started_at', { withTimezone: true }).notNull().defaultNow(),
    evaluated_at: timestamp('evaluated_at', { withTimezone: true }),
    /** Populated by evaluateDivergence when the TwinDivergenceClaim emits.
     * Soft FK (no constraint) — passport_claims may roll off the chain
     * via retention prune, the divergence_claim_id here is informational. */
    divergence_claim_id: text('divergence_claim_id'),
    /** 'running' → 'evaluated' (terminal) or 'failed' (terminal). */
    status: text('status').notNull().default('running'),
    /** Append-only jsonb pair-tracking. mirrorIntent/mirrorOutcome push
     * { real_claim_id, twin_claim_id, kind: 'intent' | 'outcome' }.
     * evaluateDivergence reads sequentially at mission close — a
     * dedicated join table would be over-engineered for the small
     * cardinality (a mission has tens of intents, not thousands). */
    claim_pairs: jsonb('claim_pairs')
      .notNull()
      .$type<Array<{ real_claim_id: string; twin_claim_id: string; kind: 'intent' | 'outcome' }>>()
      .default([]),
  },
  (table) => [
    index('twin_runs_mission_idx').on(table.mission_id),
    index('twin_runs_real_passport_idx').on(table.real_passport_jti),
    index('twin_runs_status_idx').on(table.status),
    check('twin_runs_status_check', sql`${table.status} IN ('running', 'evaluated', 'failed')`),
  ],
);
