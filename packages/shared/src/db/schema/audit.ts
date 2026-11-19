// Hash-chained audit log, archive segments and governance records.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  bigint,
  index,
  uniqueIndex,
  doublePrecision,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

// ─── Governance approvals (operate vs govern step up) ──────
//
// One row = one human-approval request for a gated governance action
// initiated from a Bearer-credential context (operator key or
// OAuth token — i.e. potentially an agentic MCP session). The request
// is created server-side when the gated route is hit WITHOUT an
// X-Governance-Approval header; the human approves in the DASHBOARD
// (cookie session required — the approval decision itself can never be
// taken through a Bearer credential); the original caller retries with
// the id. payload_hash (sha256 of the canonical mutation body) binds
// the approval to EXACTLY the change that was shown to the human.
//
// State machine (all transitions CAS-guarded, intent-approvals pattern):
//   pending → approved → consumed        (single-use happy path)
//   pending → rejected                   (terminal)
//   pending → expired                    (15-min TTL, lazy + sweepable)
// Unknown/other state → deny (fail closed).
export const governanceApprovals = pgTable(
  'governance_approvals',
  {
    id: text('id').primaryKey(), // gvr_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    /** Team member that initiated the request, when applicable. */
    member_id: text('member_id'),
    /** Gated action key. Validated by GovernanceActionEnum at the API edge. */
    action: text('action').notNull(),
    /** The acted-on resource (detector_key, checkout id, agent id). */
    resource_id: text('resource_id').notNull(),
    /** sha256 of the canonical JSON mutation body — what was approved
     *  is exactly what executes. */
    payload_hash: text('payload_hash').notNull(),
    /** Human-readable action summary rendered on the approvals page. */
    summary: text('summary').notNull(),
    /** Fleet policy input only, schema-validated and credential-free. */
    policy_preview: jsonb('policy_preview').$type<Record<string, unknown>>(),
    /** Which credential class initiated: operator_key | member_session | oauth. */
    requested_via: text('requested_via').notNull(),
    status: text('status').notNull().default('pending'), // pending | approved | rejected | consumed | expired
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    /** Which member decided it. NULL = the operator themselves (no member
     *  context on the deciding session). Without this the audit trail can
     *  say an org approved an elevation but not who in it did. */
    decided_by_member_id: text('decided_by_member_id'),
    /** set when a white-label partner decided for its tenant
     *  (tenants have no human user). decided_by_member_id then names the
     *  partner's admin member, or is NULL for the partner's owner. */
    decided_by_partner_operator_id: text('decided_by_partner_operator_id'),
    decided_at: timestamp('decided_at', { withTimezone: true }),
    /** How the decision arrived: dashboard | chat_elicitation | bearer_reject.
     *  NULL for decisions recorded before the column existed. */
    decided_via: text('decided_via'),
    /** chat_elicitation only: hash of the MCP session that showed the
     *  confirmation, the one-time elicitation id (unique, so an attestation
     *  can never be replayed) and the OAuth client the person signed in with. */
    decided_mcp_session_hash: text('decided_mcp_session_hash'),
    decided_elicitation_id: text('decided_elicitation_id'),
    decided_oauth_client_id: text('decided_oauth_client_id'),
    /** chat_telegram | chat_sms | chat_slack only: the owner's bound chat identity and the single-use request that carried the decision (unique). */
    decided_chat_identity_id: text('decided_chat_identity_id'),
    decided_chat_request_id: text('decided_chat_request_id'),
    consumed_at: timestamp('consumed_at', { withTimezone: true }),
    /** Hash of the mutation Idempotency-Key for authority-only crash-safe replay. */
    consumed_idempotency_key_hash: text('consumed_idempotency_key_hash'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('gvr_operator_idx').on(table.operator_id),
    index('gvr_operator_status_idx').on(table.operator_id, table.status),
    uniqueIndex('gvr_decided_elicitation_uidx')
      .on(table.decided_elicitation_id)
      .where(sql`${table.decided_elicitation_id} is not null`),
    uniqueIndex('gvr_decided_chat_request_uidx')
      .on(table.decided_chat_request_id)
      .where(sql`${table.decided_chat_request_id} is not null`),
    check(
      'governance_approvals_decided_via_check',
      sql`${table.decided_via} is null
        or ${table.decided_via} in ('dashboard', 'bearer_reject')
        or (${table.decided_via} = 'chat_elicitation'
          and ${table.decided_mcp_session_hash} ~ '^[0-9a-f]{64}$'
          and ${table.decided_elicitation_id} is not null
          and ${table.decided_oauth_client_id} is not null)
        or (${table.decided_via} in ('chat_telegram', 'chat_sms', 'chat_slack')
          and ${table.decided_chat_identity_id} is not null
          and ${table.decided_chat_request_id} is not null)`,
    ),
    check(
      'governance_approvals_authority_idempotency_check',
      sql`(${table.consumed_idempotency_key_hash} is null and (
          ${table.action} not in ('fleet_policy_activate', 'authority_proof_erase', 'authority_binding_activate',
            'authority_receiver_key_add', 'authority_profile_activate',
            'authority_principal_erase', 'authority_binding_erase', 'authority_presentation_erase',
            'account_open')
          or ${table.status} <> 'consumed'))
        or (${table.consumed_idempotency_key_hash} ~ '^[0-9a-f]{64}$'
          and ${table.action} in ('fleet_policy_activate', 'authority_proof_erase', 'authority_binding_activate',
            'authority_receiver_key_add', 'authority_profile_activate',
            'authority_principal_erase', 'authority_binding_erase', 'authority_presentation_erase',
            'account_open')
          and ${table.status} = 'consumed' and ${table.consumed_at} is not null)`,
    ),
    check('governance_approvals_status_check', sql`${table.status} IN ('pending', 'approved', 'rejected', 'consumed', 'expired')`),
  ],
);

// ─── Admin Actions ──────────────────────────────────────────────────

export const adminActions = pgTable(
  'admin_actions',
  {
    id: text('id').primaryKey(),
    admin_operator_id: text('admin_operator_id')
      .notNull()
      .references(() => operators.id),
    target_operator_id: text('target_operator_id').references(() => operators.id, {
      onDelete: 'cascade',
    }),
    action: text('action').notNull(),
    reason: text('reason'),
    metadata: jsonb('metadata').$type<Record<string, unknown>>(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_admin_actions_admin').on(table.admin_operator_id),
    index('idx_admin_actions_target').on(table.target_operator_id),
    index('idx_admin_actions_created').on(table.created_at),
  ],
);

// ─── Audit Log ───────────────────────────────────────────────────────
// Append-only. DB user should have INSERT only, no UPDATE or DELETE.

/**
 * Index over the cold archive.
 *
 * One row per (operator, UTC day) segment written to object storage. Carries
 * the chain hashes at both ends so a verifier can walk cold -> hot across the
 * seam without a gap, and the content hash so a fetched segment can be checked
 * before anything in it is trusted.
 */
export const auditArchiveSegments = pgTable(
  'audit_archive_segments',
  {
    id: text('id').primaryKey(),
    // Migration 0045 installs this FK as NOT VALID. Existing orphan segment
    // rows remain, while all new rows are checked and hard deletion cascades.
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    from_timestamp: bigint('from_timestamp', { mode: 'number' }).notNull(),
    to_timestamp: bigint('to_timestamp', { mode: 'number' }).notNull(),
    row_count: integer('row_count').notNull(),
    object_key: text('object_key').notNull(),
    byte_size: integer('byte_size').notNull(),
    content_hash: text('content_hash').notNull(),
    first_entry_hash: text('first_entry_hash').notNull(),
    first_prev_entry_hash: text('first_prev_entry_hash'),
    last_entry_hash: text('last_entry_hash').notNull(),
    // The segment row is also the durable cold-retention job. It remains until
    // the object is confirmed absent. Failures record only a fixed error code.
    retention_attempt_count: integer('retention_attempt_count').notNull().default(0),
    retention_next_attempt_at: timestamp('retention_next_attempt_at', { withTimezone: true }),
    retention_last_error_code: text('retention_last_error_code'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('audit_archive_retention_due_idx').on(
      table.to_timestamp,
      table.retention_next_attempt_at,
    ),
  ],
);

export const auditLog = pgTable(
  'audit_log',
  {
    entry_id: text('entry_id').primaryKey(),
    trace_id: text('trace_id').notNull(),
    span_id: text('span_id').notNull(),
    parent_span_id: text('parent_span_id'),
    timestamp: bigint('timestamp', { mode: 'number' }).notNull(), // unix milliseconds
    // Migration 0045 installs this FK as NOT VALID. Legacy orphans remain,
    // while every new row is checked and account deletion cascades.
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    agent_id: text('agent_id').notNull(),
    passport_jti: text('passport_jti').notNull(),
    layer: text('layer').notNull(), // vault | dropoff | skills | hire | system
    action: text('action').notNull(),
    outcome: text('outcome').notNull(), // success | failure | pending | blocked
    duration_ms: integer('duration_ms'),
    payload_hash: text('payload_hash'),
    error_code: text('error_code'),
    error_message: text('error_message'),
    prev_entry_hash: text('prev_entry_hash').notNull(),
    entry_hash: text('entry_hash').notNull(),
    // Sorted set of passport_claims hashes attached at audit-write time
    // (chain tamper evidence binds claim state). NULL on legacy
    // rows; chain hash backward-compat preserved by computeAuditEntryHash
    // dropping the field when absent or empty.
    passport_claims_at_event: jsonb('passport_claims_at_event').$type<string[]>(),
    // body metrics for the behavioral_genome producer.
    // Populated by the proxy at audit-write time for HTTP-shape calls;
    // NULL for other layers (skills, drop-off, mcp). Included in
    // computeAuditEntryHash chain only when non-null, preserving
    // backward compat (same pattern as passport_claims_at_event).
    request_bytes: integer('request_bytes'),
    response_bytes: integer('response_bytes'),
    // follow-up — migration 0017 widened these from
    // `real` (float4) to `double precision` (float8). The float4
    // column rounded the writer's float64 entropy on INSERT, but
    // computeAuditEntryHash had already bound the un-rounded value;
    // the read-back float4-upcast-to-float64 then re-hashed to a
    // different value → chain break. Float8 preserves the writer's
    // bytes exactly. See the system architecture 2026-05-24
    // post-mortem entry.
    request_entropy: doublePrecision('request_entropy'), // Shannon entropy, bits/byte ∈ [0, 8]
    response_entropy: doublePrecision('response_entropy'), // Shannon entropy, bits/byte ∈ [0, 8]
    // partner-acting-for-user attribution. Set on entries written
    // under a grant-authenticated request: the entry lands on the USER's
    // chain, these two fields make the acting partner cryptographically
    // distinguishable from the user acting directly. Hash-bound via
    // computeAuditEntryHash's include-only-when-present pattern (same
    // backward-compat contract as request_bytes / passport_claims_at_event).
    actor_grant_id: text('actor_grant_id'),
    actor_partner_operator_id: text('actor_partner_operator_id'),
    // v1 is the historical partial-field hash. Every new row is v2, which
    // binds every security-relevant stored field and an explicit claim state.
    hash_version: integer('hash_version').notNull().default(2),
    claim_binding_status: text('claim_binding_status').notNull().default('legacy_unbound'),
  },
  (table) => [
    index('audit_trace_idx').on(table.trace_id),
    index('audit_operator_idx').on(table.operator_id),
    index('audit_agent_idx').on(table.agent_id),
    index('audit_passport_idx').on(table.passport_jti),
    index('audit_timestamp_idx').on(table.timestamp),
    index('audit_operator_timestamp_idx').on(table.operator_id, table.timestamp, table.entry_id),
    index('audit_layer_action_idx').on(table.layer, table.action),
    check(
      'audit_hash_version_binding_check',
      sql`(${table.hash_version} = 1 and ${table.claim_binding_status} = 'legacy_unbound') or (${table.hash_version} = 2 and ${table.claim_binding_status} in ('not_applicable', 'no_active_claims', 'bound'))`,
    ),
  ],
);
