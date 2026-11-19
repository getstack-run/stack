// Detector and PII configuration and security events.

import {
  pgTable,
  text,
  timestamp,
  jsonb,
  boolean,
  index,
  uniqueIndex,
  doublePrecision,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { missions } from './missions.js';
import { operators } from './operators.js';
import { passportClaims } from './signed-records.js';

// ─── Operator Detector Config (L7 — per-operator customization) ────
//
// Each row is one operator's customization for one named detector.
// custom_patterns / whitelist_patterns / severity_overrides shape:
//   custom_patterns:    Array<{ id: string; regex: string; severity: 'warning' | 'critical'; description: string }>
//   whitelist_patterns: Array<{ id: string; regex: string; description: string }>
//   severity_overrides: Record<pattern_id, 'warning' | 'critical'>
// Tier-gated to studio+ at the API layer. Cache-fronted (Redis 60s TTL)
// so the detector hot path doesn't DB-hit per scan.

export interface OperatorCustomPattern {
  id: string;
  regex: string;
  severity: 'warning' | 'critical';
  description: string;
}

export interface OperatorWhitelistPattern {
  id: string;
  regex: string;
  description: string;
}

export const operatorDetectorConfig = pgTable(
  'operator_detector_config',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    detector_key: text('detector_key').notNull(),
    custom_patterns: jsonb('custom_patterns')
      .notNull()
      .$type<OperatorCustomPattern[]>()
      .default([]),
    whitelist_patterns: jsonb('whitelist_patterns')
      .notNull()
      .$type<OperatorWhitelistPattern[]>()
      .default([]),
    severity_overrides: jsonb('severity_overrides')
      .notNull()
      .$type<Record<string, 'warning' | 'critical'>>()
      .default({}),
    enabled: boolean('enabled').notNull().default(true),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('odc_operator_detector_idx').on(table.operator_id, table.detector_key),
    index('odc_operator_idx').on(table.operator_id),
  ],
);

// ─── Per-operator PII redaction config (2026-08-05) ──────────────────
//
// One row per operator, not per agent: which countries you do business in is
// an account fact, not a per-bot one. The existing agents.llm_redact_pii stays
// as the per-agent kill switch.
//
// Both columns are nullable and null means "use the built-in", so an operator
// who only wants to narrow the country list does not have to restate the
// threshold and silently pin it against a future default change.
export const operatorPiiConfig = pgTable(
  'operator_pii_config',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    /** Master switch. False disables PII redaction for the whole account. */
    enabled: boolean('enabled').notNull().default(true),
    /** Minimum confidence to redact. NULL = PII_DEFAULT_THRESHOLD (0.4). */
    threshold: doublePrecision('threshold'),
    /**
     * ISO 3166-1 alpha-2 codes to scan for. NULL = every country, which is
     * the safe default and the noisy one. Country-neutral patterns (email,
     * card, IBAN, IP) run regardless of what is in here.
     *
     * doublePrecision on threshold rather than `real` on purpose: the float4
     * round-trip is what broke the audit chain in 2026-05 (see the comment on
     * audit_log.request_entropy), and a threshold compared against a float64
     * score has the same shape of bug.
     */
    countries: jsonb('countries').$type<string[]>(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex('opc_operator_idx').on(table.operator_id)],
);

// ─── Security Events ────────────────────────────────────────────────

export const securityEvents = pgTable(
  'security_events',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    agent_id: text('agent_id').notNull(),
    passport_jti: text('passport_jti'),
    mission_id: text('mission_id'),
    signal_type: text('signal_type').notNull(),
    severity: text('severity').notNull().default('warning'), // info | warning | critical
    message: text('message').notNull(),
    metadata: jsonb('metadata').$type<Record<string, unknown>>(),
    resolved: boolean('resolved').notNull().default(false),
    resolved_by: text('resolved_by'),
    resolved_at: timestamp('resolved_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    // (Option F) — FK to the paired
    // detector_signal claim in passport_claims, populated by the 1.17
    // producer-migration dual-write. NULL for operator-scope events
    // (no passport_jti, no claim emitted by design).
    claim_id: text('claim_id').references(() => passportClaims.claim_id, { onDelete: 'set null' }),
  },
  (table) => [
    index('idx_secevt_operator').on(table.operator_id),
    index('idx_secevt_agent').on(table.agent_id),
    index('idx_secevt_passport').on(table.passport_jti),
    index('idx_secevt_type').on(table.signal_type),
    index('idx_secevt_claim').on(table.claim_id),
    index('security_events_mission_idx').on(table.operator_id, table.mission_id),
    foreignKey({
      columns: [table.mission_id, table.operator_id],
      foreignColumns: [missions.mission_id, missions.operator_id],
      name: 'security_events_mission_operator_fk',
    }),
  ],
);
