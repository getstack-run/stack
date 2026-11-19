// The control socket: where a customer's actions are decided and where their
// record is streamed. One row per customer.
//
// control_sockets      the customer's choice: who decides (STACK's hosted
//                      controls, their own server, or nobody), the decision
//                      address and the events address with their signing
//                      secrets (KMS-encrypted, never stored in the clear), and
//                      which action kinds are checked.
// control_decisions    one slim row per decision: digest, verdict, latency,
//                      reason. The request as sent is kept only for a refusal
//                      or an unreachable server, and only for a while.
// control_event_outbox the customer's record waiting to be delivered. A row is
//                      inserted inside the audit write that created the event,
//                      so it commits or rolls back with it; delivered rows are
//                      deleted.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  bigint,
  boolean,
  index,
  primaryKey,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

export const controlSockets = pgTable(
  'control_sockets',
  {
    operator_id: text('operator_id')
      .primaryKey()
      .references(() => operators.id, { onDelete: 'cascade' }),
    socket_id: text('socket_id').notNull().unique(), // csk_*
    // auto: hosted checks while controls are on, none otherwise.
    decision_mode: text('decision_mode').notNull().default('auto'),
    decision_url: text('decision_url'),
    // A new address waits here, verified, until it replaces the current one.
    decision_candidate_url: text('decision_candidate_url'),
    decision_timeout_ms: integer('decision_timeout_ms').notNull().default(1500),
    // What happens when the customer's own server does not answer in time: refuse (the default) or allow.
    decision_on_unavailable: text('decision_on_unavailable').notNull().default('refuse'),
    decision_candidate_timeout_ms: integer('decision_candidate_timeout_ms'),
    decision_secret_encrypted: text('decision_secret_encrypted'),
    decision_secret_previous_encrypted: text('decision_secret_previous_encrypted'),
    decision_secret_rotated_at: timestamp('decision_secret_rotated_at', { withTimezone: true }),
    decision_status: text('decision_status').notNull().default('unverified'),
    decision_verified_at: timestamp('decision_verified_at', { withTimezone: true }),
    // Answers in a row that failed their signature check; 50 pause the socket.
    decision_bad_answers: integer('decision_bad_answers').notNull().default(0),
    // Null checks every action kind, including kinds added later.
    checked_types: text('checked_types').array(),
    events_url: text('events_url'),
    events_secret_encrypted: text('events_secret_encrypted'),
    events_secret_previous_encrypted: text('events_secret_previous_encrypted'),
    events_secret_rotated_at: timestamp('events_secret_rotated_at', { withTimezone: true }),
    events_status: text('events_status').notNull().default('off'),
    events_verified_at: timestamp('events_verified_at', { withTimezone: true }),
    // The last sequence number handed to an event, and the last one acknowledged.
    events_last_seq: bigint('events_last_seq', { mode: 'number' }).notNull().default(0),
    events_acked_seq: bigint('events_acked_seq', { mode: 'number' }).notNull().default(0),
    events_attempts: integer('events_attempts').notNull().default(0),
    events_client_errors: integer('events_client_errors').notNull().default(0),
    events_first_failure_at: timestamp('events_first_failure_at', { withTimezone: true }),
    events_next_attempt_at: timestamp('events_next_attempt_at', { withTimezone: true }),
    events_lease_until: timestamp('events_lease_until', { withTimezone: true }),
    // A short code (never a response body) for the last delivery failure.
    events_last_error: text('events_last_error'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    check('control_sockets_decision_mode_check', sql`${t.decision_mode} IN ('auto', 'none', 'hosted', 'remote')`),
    check('control_sockets_decision_status_check', sql`${t.decision_status} IN ('unverified', 'enforcing', 'paused')`),
    check('control_sockets_events_status_check', sql`${t.events_status} IN ('off', 'unverified', 'active', 'failing')`),
    check('control_sockets_timeout_check', sql`${t.decision_timeout_ms} BETWEEN 300 AND 2000`),
    check(
      'control_sockets_remote_check',
      sql`${t.decision_mode} <> 'remote' OR (${t.decision_url} IS NOT NULL AND ${t.decision_secret_encrypted} IS NOT NULL AND ${t.decision_status} <> 'unverified')`,
    ),
    check(
      'control_sockets_events_active_check',
      sql`${t.events_status} NOT IN ('active', 'failing') OR (${t.events_url} IS NOT NULL AND ${t.events_secret_encrypted} IS NOT NULL)`,
    ),
    check('control_sockets_seq_check', sql`${t.events_acked_seq} <= ${t.events_last_seq}`),
  ],
);

export const controlDecisions = pgTable(
  'control_decisions',
  {
    id: text('id').primaryKey(), // dec_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    socket_id: text('socket_id'),
    account_id: text('account_id'),
    agent_id: text('agent_id'),
    action_type: text('action_type').notNull(),
    decider: text('decider').notNull(),
    verdict: text('verdict').notNull(),
    reason_code: text('reason_code'),
    cause: text('cause'),
    latency_ms: integer('latency_ms').notNull(),
    // Whether a hosted check was charged for this decision.
    charged: boolean('charged').notNull().default(false),
    request_digest: text('request_digest').notNull(),
    // The request as sent, for a refusal or an unreachable server only.
    request: jsonb('request').$type<Record<string, unknown>>(),
    // Which rule of a hosted policy refused the action: the policy's side only, never a value from the call.
    evidence: jsonb('evidence').$type<Record<string, unknown>>(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('control_decisions_operator_created_idx').on(t.operator_id, t.created_at),
    index('control_decisions_account_created_idx').on(t.account_id, t.created_at),
    check('control_decisions_decider_check', sql`${t.decider} IN ('none', 'hosted', 'remote')`),
    check('control_decisions_verdict_check', sql`${t.verdict} IN ('allow', 'deny', 'unavailable')`),
  ],
);

export const controlEventOutbox = pgTable(
  'control_event_outbox',
  {
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    seq: bigint('seq', { mode: 'number' }).notNull(),
    entry_id: text('entry_id').notNull(),
    event: jsonb('event').notNull().$type<Record<string, unknown>>(),
    // pending: waiting for delivery. dead: refused three times or too old; announced once by a gap event.
    status: text('status').notNull().default('pending'),
    gap_announced: boolean('gap_announced').notNull().default(false),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.operator_id, t.seq] }),
    index('control_event_outbox_status_idx').on(t.operator_id, t.status, t.seq),
    check('control_event_outbox_status_check', sql`${t.status} IN ('pending', 'dead')`),
  ],
);

export type ControlSocketRow = typeof controlSockets.$inferSelect;
export type ControlDecisionRow = typeof controlDecisions.$inferSelect;
export type ControlEventOutboxRow = typeof controlEventOutbox.$inferSelect;
