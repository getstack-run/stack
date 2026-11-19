// Fleet policies, memberships and fleet-scoped missions and operations.

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
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { missions } from './missions.js';
import { operators } from './operators.js';
import { proxyOperations } from './proxy.js';

// Fleet rows retain revoked identities and usage. Re-enrollment and policy
// revision never create a fresh budget or erase a worker's lineage.
export const fleetPolicies = pgTable(
  'fleet_policies',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    root_agent_id: text('root_agent_id')
      .notNull()
      .references(() => agents.id),
    revision: integer('revision').notNull(),
    status: text('status').notNull().default('active'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('fleet_policy_root_unique').on(t.root_agent_id),
    check('fleet_policies_revision_check', sql`${t.revision} > 0`),
    check('fleet_policies_status_check', sql`${t.status} IN ('active', 'revoked')`),
  ],
);

export const fleetPolicyRevisions = pgTable(
  'fleet_policy_revisions',
  {
    policy_id: text('policy_id')
      .notNull()
      .references(() => fleetPolicies.id),
    revision: integer('revision').notNull(),
    definition: jsonb('definition')
      .notNull()
      .$type<import('../../schemas/fleet.js').FleetPolicyInput>(),
    approved_by: text('approved_by').notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.policy_id, t.revision] }),
    check('fleet_policy_revisions_revision_check', sql`${t.revision} > 0`),
  ],
);

export const fleetMemberships = pgTable(
  'fleet_memberships',
  {
    id: text('id').primaryKey(),
    policy_id: text('policy_id')
      .notNull()
      .references(() => fleetPolicies.id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    enrolled_by: text('enrolled_by').notNull(),
    enrollment_key_hash: text('enrollment_key_hash').notNull(),
    enrollment_payload_hash: text('enrollment_payload_hash').notNull(),
    identity_expires_at: timestamp('identity_expires_at', { withTimezone: true }).notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('fleet_member_agent_unique').on(t.agent_id),
    uniqueIndex('fleet_enrollment_key_unique').on(t.policy_id, t.enrollment_key_hash),
    index('fleet_member_policy_idx').on(t.policy_id),
  ],
);

export const fleetMissions = pgTable(
  'fleet_missions',
  {
    mission_id: text('mission_id')
      .primaryKey()
      .references(() => missions.mission_id),
    policy_id: text('policy_id')
      .notNull()
      .references(() => fleetPolicies.id),
    policy_revision: integer('policy_revision').notNull(),
    membership_id: text('membership_id')
      .notNull()
      .references(() => fleetMemberships.id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    access: jsonb('access')
      .notNull()
      .$type<import('../../utils/fleet-policy.js').ResolvedFleetAccess[]>(),
    operations: jsonb('operations')
      .notNull()
      .$type<import('../../utils/fleet-policy.js').ResolvedFleetOperation[]>()
      .default([]),
    limits: jsonb('limits').notNull().$type<import('../../schemas/fleet.js').FleetLimits>(),
    authority_binding_ids: jsonb('authority_binding_ids').notNull().$type<string[]>().default([]),
    session_id: text('session_id').notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [check('fleet_missions_policy_revision_check', sql`${t.policy_revision} > 0`)],
);

export const fleetOperations = pgTable(
  'fleet_operations',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    policy_id: text('policy_id')
      .notNull()
      .references(() => fleetPolicies.id),
    policy_revision: integer('policy_revision').notNull(),
    mission_id: text('mission_id')
      .notNull()
      .references(() => missions.mission_id),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    operation_key_hash: text('operation_key_hash').notNull(),
    request_hash: text('request_hash').notNull(),
    producer: text('producer').notNull(),
    rule_id: text('rule_id').notNull(),
    intent_claim_id: text('intent_claim_id'),
    proxy_operation_id: text('proxy_operation_id').references(() => proxyOperations.id),
    state: text('state').notNull().default('reserved'),
    reserved_spend_cents: bigint('reserved_spend_cents', { mode: 'number' }).notNull().default(0),
    reserved_bytes: bigint('reserved_bytes', { mode: 'number' }).notNull().default(0),
    window_start: timestamp('window_start', { withTimezone: true }).notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    settled_at: timestamp('settled_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('fleet_operation_key_unique').on(t.mission_id, t.operation_key_hash),
    index('fleet_operation_budget_idx').on(t.policy_id, t.created_at),
    index('fleet_operation_mission_idx').on(t.mission_id),
    check('fleet_operations_policy_revision_check', sql`${t.policy_revision} > 0`),
    check(
      'fleet_operations_state_check',
      sql`${t.state} IN ('reserved','dispatched','settled','unknown','cancelled')`,
    ),
    check('fleet_operations_reserved_spend_cents_check', sql`${t.reserved_spend_cents} >= 0`),
    check('fleet_operations_reserved_bytes_check', sql`${t.reserved_bytes} >= 0`),
    index('fleet_operations_proxy_recovery_idx')
      .on(t.proxy_operation_id)
      .where(sql`${t.state} IN ('dispatched', 'unknown')`),
  ],
);

export const fleetMissionStarts = pgTable(
  'fleet_mission_starts',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    policy_id: text('policy_id')
      .notNull()
      .references(() => fleetPolicies.id),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    key_hash: text('key_hash').notNull(),
    payload_hash: text('payload_hash').notNull(),
    mission_id: text('mission_id').notNull(),
    state: text('state').notNull().default('starting'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('fleet_start_key_unique').on(t.policy_id, t.agent_id, t.key_hash),
    check('fleet_mission_starts_state_check', sql`${t.state} IN ('starting','ready')`),
  ],
);
