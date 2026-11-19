// Policies and the actions they held for a person.
//
// control_policies          one active policy per agent and one customer-wide
//                           default. Stored server-side and keyed by customer;
//                           never bound into a Passport.
// control_policy_revisions  every revision, kept after a policy is deleted, so
//                           a refusal's policy id and revision can always be
//                           read back.
// control_reviews           an action a policy held for a person. Its states
//                           follow the intent approval gate (pending, approved,
//                           consuming, consumed), keyed on account and policy.

import {
  pgTable,
  text,
  timestamp,
  integer,
  bigint,
  primaryKey,
  jsonb,
  index,
  uniqueIndex,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

export const controlPolicies = pgTable(
  'control_policies',
  {
    id: text('id').primaryKey(), // cpl_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    // Null: the customer's default, for every agent without a policy of its own.
    agent_id: text('agent_id'),
    name: text('name').notNull(),
    revision: integer('revision').notNull().default(1),
    definition: jsonb('definition').notNull().$type<Record<string, unknown>>(),
    definition_digest: text('definition_digest').notNull(),
    status: text('status').notNull().default('active'),
    last_change: text('last_change').notNull().default('create'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('control_policies_scope_unique')
      .on(t.operator_id, sql`coalesce(${t.agent_id}, '')`)
      .where(sql`${t.status} = 'active'`),
    index('control_policies_operator_idx').on(t.operator_id, t.status),
    check('control_policies_status_check', sql`${t.status} IN ('active', 'deleted')`),
    check('control_policies_revision_check', sql`${t.revision} >= 1`),
  ],
);
export type ControlPolicyRow = typeof controlPolicies.$inferSelect;

export const controlPolicyRevisions = pgTable(
  'control_policy_revisions',
  {
    policy_id: text('policy_id').notNull(),
    revision: integer('revision').notNull(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    agent_id: text('agent_id'),
    definition: jsonb('definition').notNull().$type<Record<string, unknown>>(),
    definition_digest: text('definition_digest').notNull(),
    change: text('change').notNull(),
    // Who made it: the operator's key, a member, or an OAuth client, and the step-up approval when it loosened.
    actor: text('actor').notNull(),
    approval_id: text('approval_id'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.policy_id, t.revision] }),
    index('control_policy_revisions_operator_idx').on(t.operator_id, t.created_at),
    check(
      'control_policy_revisions_change_check',
      sql`${t.change} IN ('create', 'start_from_access', 'tighten', 'loosen', 'delete')`,
    ),
  ],
);
export type ControlPolicyRevisionRow = typeof controlPolicyRevisions.$inferSelect;

export const controlReviews = pgTable(
  'control_reviews',
  {
    id: text('id').primaryKey(), // crv_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    account_id: text('account_id').notNull(),
    agent_id: text('agent_id').notNull(),
    policy_id: text('policy_id').notNull(),
    policy_revision: integer('policy_revision').notNull(),
    // Which rule held it, as the refusal evidence names it.
    rule_section: text('rule_section').notNull(),
    rule_id: text('rule_id').notNull(),
    action_type: text('action_type').notNull(),
    // sha256 over the exact call (agent, action, target, amount and, for a proxy call, the normalized request).
    // The retry must reproduce it; the call itself is never stored.
    call_digest: text('call_digest').notNull(),
    // A line a person can read: what the agent wants to do and which rule held it. No call content.
    summary: text('summary').notNull(),
    governance_approval_id: text('governance_approval_id').notNull(),
    status: text('status').notNull().default('pending'),
    // The operation that reserved it, so only that operation settles or releases it. Hash only.
    consuming_owner_hash: text('consuming_owner_hash'),
    // A held payment (card purchase or wallet payment): what it costs at most, in USD cents, and which it is.
    // A chat may approve only a held payment, within the customer's own limits, bound to this amount.
    amount_cents: bigint('amount_cents', { mode: 'number' }),
    payment_surface: text('payment_surface'),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    decided_at: timestamp('decided_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    check(
      'control_reviews_payment_check',
      sql`(${t.payment_surface} IS NULL AND ${t.amount_cents} IS NULL)
        OR (${t.payment_surface} IN ('card', 'wallet') AND ${t.amount_cents} IS NOT NULL AND ${t.amount_cents} >= 0)`,
    ),
    uniqueIndex('control_reviews_call_unique')
      .on(t.operator_id, t.call_digest)
      .where(sql`${t.status} IN ('pending', 'approved', 'consuming')`),
    uniqueIndex('control_reviews_approval_unique').on(t.governance_approval_id),
    index('control_reviews_account_idx').on(t.account_id, t.status),
    index('control_reviews_operator_idx').on(t.operator_id, t.created_at),
    // The sweep that ends pending reviews nobody decided in time and tells their agents.
    index('control_reviews_pending_expiry_idx').on(t.expires_at).where(sql`${t.status} = 'pending'`),
    check(
      'control_reviews_status_check',
      sql`${t.status} IN ('pending', 'approved', 'consuming', 'consumed', 'rejected', 'expired')`,
    ),
    check(
      'control_reviews_owner_check',
      sql`${t.consuming_owner_hash} IS NULL OR ${t.consuming_owner_hash} ~ '^[0-9a-f]{64}$'`,
    ),
  ],
);
export type ControlReviewRow = typeof controlReviews.$inferSelect;
