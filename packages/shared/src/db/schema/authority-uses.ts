// Authority uses, approvals, presentations and receiver receipts.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  index,
  uniqueIndex,
  primaryKey,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { authorityProofs, authorityBindings } from './authority-bindings.js';
import {
  authorityPrincipals,
  authorityReceivers,
  authorityProfileVersions,
  authorityReceiverKeys,
} from './authority-registry.js';
import { missions } from './missions.js';
import { operators } from './operators.js';
import { passports } from './passports.js';
import { passportClaims } from './signed-records.js';

export const authorityUses = pgTable(
  'authority_uses',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    binding_id: text('binding_id').notNull(),
    binding_version: integer('binding_version').notNull(),
    passport_jti: text('passport_jti').notNull(),
    mission_id: text('mission_id'),
    agent_id: text('agent_id').notNull(),
    agent_key_thumbprint: text('agent_key_thumbprint').notNull(),
    receiver_id: text('receiver_id').notNull(),
    receiver_profile_version_id: text('receiver_profile_version_id')
      .notNull()
      .references(() => authorityProfileVersions.id),
    domain_profile_version_id: text('domain_profile_version_id').references(
      () => authorityProfileVersions.id,
    ),
    receiver_request_id: text('receiver_request_id').notNull(),
    action_uri: text('action_uri').notNull(),
    resource_hash: text('resource_hash'),
    request_hash: text('request_hash').notNull(),
    effective_scope_hash: text('effective_scope_hash').notNull(),
    proof_set_hash: text('proof_set_hash').notNull(),
    disclosure_manifest: jsonb('disclosure_manifest')
      .notNull()
      .$type<Array<{ fact_id: string; mode: string }>>(),
    verification_mode: text('verification_mode').notNull(),
    proof_strength: text('proof_strength').notNull(),
    status: text('status').notNull().default('pending'),
    denial_code: text('denial_code'),
    intent_claim_id: text('intent_claim_id').references(() => passportClaims.claim_id),
    outcome_claim_id: text('outcome_claim_id').references(() => passportClaims.claim_id),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    authorized_at: timestamp('authorized_at', { withTimezone: true }),
    dispatched_at: timestamp('dispatched_at', { withTimezone: true }),
    completed_at: timestamp('completed_at', { withTimezone: true }),
    result_hash: text('result_hash'),
  },
  (table) => [
    uniqueIndex('authority_uses_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('authority_uses_receiver_request_idx').on(
      table.receiver_id,
      table.receiver_request_id,
    ),
    uniqueIndex('authority_uses_operator_receiver_hash_idx').on(
      table.operator_id,
      table.receiver_id,
      table.request_hash,
    ),
    index('authority_uses_binding_idx').on(
      table.operator_id,
      table.binding_id,
      table.binding_version,
    ),
    index('authority_uses_passport_idx').on(table.operator_id, table.passport_jti),
    index('authority_uses_mission_idx').on(table.operator_id, table.mission_id),
    index('authority_uses_status_idx').on(table.operator_id, table.status),
    foreignKey({
      columns: [table.binding_id, table.binding_version, table.operator_id],
      foreignColumns: [
        authorityBindings.id,
        authorityBindings.version,
        authorityBindings.operator_id,
      ],
      name: 'authority_uses_binding_operator_fk',
    }),
    foreignKey({
      columns: [table.passport_jti, table.operator_id],
      foreignColumns: [passports.jti, passports.operator_id],
      name: 'authority_uses_passport_operator_fk',
    }),
    foreignKey({
      columns: [table.agent_id, table.operator_id],
      foreignColumns: [agents.id, agents.operator_id],
      name: 'authority_uses_agent_operator_fk',
    }),
    foreignKey({
      columns: [table.receiver_id, table.operator_id],
      foreignColumns: [authorityReceivers.id, authorityReceivers.managed_by_operator_id],
      name: 'authority_uses_receiver_operator_fk',
    }),
    foreignKey({
      columns: [table.mission_id, table.operator_id],
      foreignColumns: [missions.mission_id, missions.operator_id],
      name: 'authority_uses_mission_operator_fk',
    }),
    foreignKey({
      columns: [table.intent_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_uses_intent_claim_operator_fk',
    }),
    foreignKey({
      columns: [table.outcome_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_uses_outcome_claim_operator_fk',
    }),
    check(
      'authority_uses_verification_mode_check',
      sql`${table.verification_mode} in ('native_receiver', 'proxy_mediated')`,
    ),
    check(
      'authority_uses_proof_strength_check',
      sql`${table.proof_strength} in ('native_issuer_evidence', 'native_stack_attestation', 'proxy_stack_enforced')`,
    ),
    check(
      'authority_uses_status_check',
      sql`${table.status} in ('pending', 'waiting_approval', 'authorized', 'denied', 'dispatched', 'succeeded', 'failed')`,
    ),
  ],
);

export const authorityApprovalRequests = pgTable(
  'authority_approval_requests',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    binding_id: text('binding_id').notNull(),
    binding_version: integer('binding_version').notNull(),
    authority_use_id: text('authority_use_id'),
    phase: text('phase').notNull(),
    group_key: text('group_key').notNull(),
    request_hash: text('request_hash').notNull(),
    challenge_hash: text('challenge_hash').notNull(),
    required_weight: integer('required_weight').notNull(),
    collected_weight: integer('collected_weight').notNull().default(0),
    reject_mode: text('reject_mode').notNull(),
    status: text('status').notNull().default('pending'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    satisfied_at: timestamp('satisfied_at', { withTimezone: true }),
    consumed_at: timestamp('consumed_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('authority_approval_requests_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('authority_approval_requests_exact_idx').on(
      table.binding_id,
      table.binding_version,
      table.phase,
      table.group_key,
      table.request_hash,
    ),
    index('authority_approval_requests_operator_status_expiry_idx').on(
      table.operator_id,
      table.status,
      table.expires_at,
    ),
    foreignKey({
      columns: [table.binding_id, table.binding_version, table.operator_id],
      foreignColumns: [
        authorityBindings.id,
        authorityBindings.version,
        authorityBindings.operator_id,
      ],
      name: 'authority_approval_requests_binding_operator_fk',
    }),
    foreignKey({
      columns: [table.authority_use_id, table.operator_id],
      foreignColumns: [authorityUses.id, authorityUses.operator_id],
      name: 'authority_approval_requests_use_operator_fk',
    }),
    check(
      'authority_approval_requests_phase_check',
      sql`${table.phase} in ('activation', 'action', 'presentation')`,
    ),
    check(
      'authority_approval_requests_reject_mode_check',
      sql`${table.reject_mode} in ('any_reject', 'threshold_reject')`,
    ),
    check(
      'authority_approval_requests_status_check',
      sql`${table.status} in ('pending', 'satisfied', 'rejected', 'expired', 'consumed', 'cancelled')`,
    ),
    check(
      'authority_approval_requests_weights_check',
      sql`${table.required_weight} > 0 and ${table.collected_weight} >= 0`,
    ),
  ],
);

export const authorityApprovalDecisions = pgTable(
  'authority_approval_decisions',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    request_id: text('request_id').notNull(),
    authoriser_principal_id: text('authoriser_principal_id').notNull(),
    identity_proof_id: text('identity_proof_id').notNull(),
    identity_proof_version: integer('identity_proof_version').notNull(),
    capacity_proof_id: text('capacity_proof_id'),
    capacity_proof_version: integer('capacity_proof_version'),
    decision_proof_id: text('decision_proof_id').notNull(),
    decision_proof_version: integer('decision_proof_version').notNull(),
    decision: text('decision').notNull(),
    weight: integer('weight').notNull(),
    request_hash: text('request_hash').notNull(),
    decided_at: timestamp('decided_at', { withTimezone: true }).notNull(),
    expires_at: timestamp('expires_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('authority_approval_decisions_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('authority_approval_decisions_request_authoriser_idx').on(
      table.request_id,
      table.authoriser_principal_id,
    ),
    foreignKey({
      columns: [table.request_id, table.operator_id],
      foreignColumns: [authorityApprovalRequests.id, authorityApprovalRequests.operator_id],
      name: 'authority_approval_decisions_request_operator_fk',
    }),
    foreignKey({
      columns: [table.authoriser_principal_id, table.operator_id],
      foreignColumns: [authorityPrincipals.id, authorityPrincipals.operator_id],
      name: 'authority_approval_decisions_authoriser_operator_fk',
    }),
    foreignKey({
      columns: [table.identity_proof_id, table.identity_proof_version, table.operator_id],
      foreignColumns: [authorityProofs.id, authorityProofs.version, authorityProofs.operator_id],
      name: 'authority_approval_decisions_identity_proof_operator_fk',
    }),
    foreignKey({
      columns: [table.capacity_proof_id, table.capacity_proof_version, table.operator_id],
      foreignColumns: [authorityProofs.id, authorityProofs.version, authorityProofs.operator_id],
      name: 'authority_approval_decisions_capacity_proof_operator_fk',
    }),
    foreignKey({
      columns: [table.decision_proof_id, table.decision_proof_version, table.operator_id],
      foreignColumns: [authorityProofs.id, authorityProofs.version, authorityProofs.operator_id],
      name: 'authority_approval_decisions_decision_proof_operator_fk',
    }),
    check(
      'authority_approval_decisions_decision_check',
      sql`${table.decision} in ('approve', 'reject')`,
    ),
    check('authority_approval_decisions_weight_check', sql`${table.weight} > 0`),
    check(
      'authority_approval_decisions_capacity_ref_check',
      sql`(${table.capacity_proof_id} is null and ${table.capacity_proof_version} is null)
        or (${table.capacity_proof_id} is not null and ${table.capacity_proof_version} is not null)`,
    ),
  ],
);

export const authorityPresentations = pgTable(
  'authority_presentations',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    authority_use_id: text('authority_use_id').notNull().unique(),
    binding_id: text('binding_id').notNull(),
    binding_version: integer('binding_version').notNull(),
    receiver_id: text('receiver_id').notNull(),
    receiver_profile_version_id: text('receiver_profile_version_id')
      .notNull()
      .references(() => authorityProfileVersions.id),
    request_signing_key_id: text('request_signing_key_id').notNull(),
    response_encryption_key_id: text('response_encryption_key_id').notNull(),
    nonce_hash: text('nonce_hash').notNull(),
    state_hash: text('state_hash'),
    signed_request_hash: text('signed_request_hash').notNull(),
    request_payload_encrypted: text('request_payload_encrypted'),
    requested_fact_ids: text('requested_fact_ids').array().notNull(),
    presentation_jti_hash: text('presentation_jti_hash').notNull().unique(),
    payload_hash: text('payload_hash'),
    disclosure_manifest: jsonb('disclosure_manifest')
      .notNull()
      .$type<Array<{ fact_id: string; mode: string }>>(),
    proof_refs: jsonb('proof_refs').notNull().$type<Array<{ id: string; version: number }>>(),
    signing_key_id: text('signing_key_id'),
    signing_algorithm: text('signing_algorithm'),
    key_management_algorithm: text('key_management_algorithm'),
    content_encryption_algorithm: text('content_encryption_algorithm'),
    status: text('status').notNull().default('pending'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    prepared_at: timestamp('prepared_at', { withTimezone: true }),
    delivered_at: timestamp('delivered_at', { withTimezone: true }),
    last_error_code: text('last_error_code'),
    erased_at: timestamp('erased_at', { withTimezone: true }),
    tombstone_hash: text('tombstone_hash'),
    tombstone_claim_id: text('tombstone_claim_id').references(() => passportClaims.claim_id),
  },
  (table) => [
    uniqueIndex('authority_presentations_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('authority_presentations_receiver_nonce_idx').on(
      table.receiver_id,
      table.nonce_hash,
    ),
    uniqueIndex('authority_presentations_signed_request_idx').on(table.signed_request_hash),
    foreignKey({
      columns: [table.authority_use_id, table.operator_id],
      foreignColumns: [authorityUses.id, authorityUses.operator_id],
      name: 'authority_presentations_use_operator_fk',
    }),
    foreignKey({
      columns: [table.binding_id, table.binding_version, table.operator_id],
      foreignColumns: [
        authorityBindings.id,
        authorityBindings.version,
        authorityBindings.operator_id,
      ],
      name: 'authority_presentations_binding_operator_fk',
    }),
    foreignKey({
      columns: [table.receiver_id, table.operator_id],
      foreignColumns: [authorityReceivers.id, authorityReceivers.managed_by_operator_id],
      name: 'authority_presentations_receiver_operator_fk',
    }),
    foreignKey({
      columns: [table.request_signing_key_id, table.receiver_id],
      foreignColumns: [authorityReceiverKeys.id, authorityReceiverKeys.receiver_id],
      name: 'authority_presentations_request_key_receiver_fk',
    }),
    foreignKey({
      columns: [table.response_encryption_key_id, table.receiver_id],
      foreignColumns: [authorityReceiverKeys.id, authorityReceiverKeys.receiver_id],
      name: 'authority_presentations_response_key_receiver_fk',
    }),
    foreignKey({
      columns: [table.tombstone_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_presentations_tombstone_claim_operator_fk',
    }),
    check(
      'authority_presentations_status_check',
      sql`${table.status} in ('pending', 'prepared', 'delivered', 'delivery_failed', 'accepted', 'rejected', 'expired', 'erased')`,
    ),
    check(
      'authority_presentations_request_scrub_check',
      sql`(${table.status} in ('pending', 'prepared', 'delivered') and ${table.request_payload_encrypted} is not null)
        or (${table.status} in ('delivery_failed', 'accepted', 'rejected', 'expired', 'erased')
          and ${table.request_payload_encrypted} is null)`,
    ),
    check(
      'authority_presentations_erasure_check',
      sql`(${table.status} = 'erased' and ${table.erased_at} is not null
          and ${table.tombstone_hash} is not null and ${table.tombstone_claim_id} is not null)
        or (${table.status} <> 'erased' and ${table.erased_at} is null
          and ${table.tombstone_hash} is null and ${table.tombstone_claim_id} is null)`,
    ),
  ],
);

export const receiverTransactionReceipts = pgTable(
  'receiver_transaction_receipts',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    authority_use_id: text('authority_use_id').notNull().unique(),
    presentation_id: text('presentation_id'),
    receiver_id: text('receiver_id').notNull(),
    receiver_profile_version_id: text('receiver_profile_version_id')
      .notNull()
      .references(() => authorityProfileVersions.id),
    receiver_key_id: text('receiver_key_id').notNull(),
    receipt_jti_hash: text('receipt_jti_hash').notNull().unique(),
    native_format: text('native_format').notNull(),
    native_receipt_encrypted: text('native_receipt_encrypted'),
    receipt_hash: text('receipt_hash').notNull(),
    request_hash: text('request_hash').notNull(),
    result_hash: text('result_hash'),
    outcome: text('outcome').notNull(),
    external_transaction_ref_hash: text('external_transaction_ref_hash'),
    verified_at: timestamp('verified_at', { withTimezone: true }).notNull(),
    received_at: timestamp('received_at', { withTimezone: true }).notNull().defaultNow(),
    claim_id: text('claim_id')
      .unique()
      .references(() => passportClaims.claim_id),
    erased_at: timestamp('erased_at', { withTimezone: true }),
    tombstone_hash: text('tombstone_hash'),
    tombstone_claim_id: text('tombstone_claim_id').references(() => passportClaims.claim_id),
  },
  (table) => [
    uniqueIndex('receiver_transaction_receipts_id_operator_idx').on(table.id, table.operator_id),
    index('receiver_transaction_receipts_receiver_received_idx').on(
      table.receiver_id,
      table.received_at,
    ),
    foreignKey({
      columns: [table.authority_use_id, table.operator_id],
      foreignColumns: [authorityUses.id, authorityUses.operator_id],
      name: 'receiver_transaction_receipts_use_operator_fk',
    }),
    foreignKey({
      columns: [table.presentation_id, table.operator_id],
      foreignColumns: [authorityPresentations.id, authorityPresentations.operator_id],
      name: 'receiver_transaction_receipts_presentation_operator_fk',
    }),
    foreignKey({
      columns: [table.receiver_id, table.operator_id],
      foreignColumns: [authorityReceivers.id, authorityReceivers.managed_by_operator_id],
      name: 'receiver_transaction_receipts_receiver_operator_fk',
    }),
    foreignKey({
      columns: [table.receiver_key_id, table.receiver_id],
      foreignColumns: [authorityReceiverKeys.id, authorityReceiverKeys.receiver_id],
      name: 'receiver_transaction_receipts_key_receiver_fk',
    }),
    foreignKey({
      columns: [table.claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'receiver_transaction_receipts_claim_operator_fk',
    }),
    foreignKey({
      columns: [table.tombstone_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'receiver_transaction_receipts_tombstone_claim_operator_fk',
    }),
    check(
      'receiver_transaction_receipts_outcome_check',
      sql`${table.outcome} in ('accepted', 'rejected', 'failed')`,
    ),
    check(
      'receiver_transaction_receipts_erasure_check',
      sql`(${table.erased_at} is not null and ${table.native_receipt_encrypted} is null
          and ${table.tombstone_hash} is not null and ${table.tombstone_claim_id} is not null)
        or (${table.erased_at} is null and ${table.tombstone_hash} is null
          and ${table.tombstone_claim_id} is null)`,
    ),
  ],
);

export const passportAuthorityBindings = pgTable(
  'passport_authority_bindings',
  {
    passport_jti: text('passport_jti').notNull(),
    operator_id: text('operator_id').notNull(),
    binding_id: text('binding_id').notNull(),
    binding_version: integer('binding_version').notNull(),
    binding_claim_id: text('binding_claim_id')
      .notNull()
      .references(() => passportClaims.claim_id),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.passport_jti, table.binding_id, table.binding_version] }),
    index('passport_authority_bindings_operator_idx').on(table.operator_id),
    index('passport_authority_bindings_binding_idx').on(
      table.operator_id,
      table.binding_id,
      table.binding_version,
    ),
    foreignKey({
      columns: [table.passport_jti, table.operator_id],
      foreignColumns: [passports.jti, passports.operator_id],
      name: 'passport_authority_bindings_passport_operator_fk',
    }).onDelete('cascade'),
    foreignKey({
      columns: [table.binding_id, table.binding_version, table.operator_id],
      foreignColumns: [
        authorityBindings.id,
        authorityBindings.version,
        authorityBindings.operator_id,
      ],
      name: 'passport_authority_bindings_binding_operator_fk',
    }),
    foreignKey({
      columns: [table.binding_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'passport_authority_bindings_claim_operator_fk',
    }),
  ],
);

export const authorityIdempotencyKeys = pgTable(
  'authority_idempotency_keys',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    route_key: text('route_key').notNull(),
    idempotency_key_hash: text('idempotency_key_hash').notNull(),
    request_hash: text('request_hash').notNull(),
    state: text('state').notNull().default('started'),
    resource_type: text('resource_type'),
    resource_id: text('resource_id'),
    response_status: integer('response_status'),
    response_body: jsonb('response_body').$type<Record<string, unknown>>(),
    response_readable_until: timestamp('response_readable_until', { withTimezone: true }),
    response_tombstone_hash: text('response_tombstone_hash'),
    workflow_phase: text('workflow_phase'),
    workflow_payload_encrypted: text('workflow_payload_encrypted'),
    lease_token_hash: text('lease_token_hash'),
    lease_expires_at: timestamp('lease_expires_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (table) => [
    uniqueIndex('authority_idempotency_keys_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('authority_idempotency_keys_operator_route_key_idx').on(
      table.operator_id,
      table.route_key,
      table.idempotency_key_hash,
    ),
    index('authority_idempotency_keys_operator_state_created_idx').on(
      table.operator_id,
      table.state,
      table.created_at,
    ),
    index('authority_idempotency_keys_operator_workflow_lease_idx').on(
      table.operator_id,
      table.workflow_phase,
      table.lease_expires_at,
    ),
    index('authority_idempotency_keys_expires_idx').on(table.expires_at),
    check(
      'authority_idempotency_keys_state_check',
      sql`${table.state} in ('started', 'completed')`,
    ),
    check(
      'authority_idempotency_keys_response_status_check',
      sql`${table.response_status} is null or ${table.response_status} between 100 and 599`,
    ),
    check(
      'authority_idempotency_keys_workflow_phase_check',
      sql`${table.workflow_phase} is null or ${table.workflow_phase} in ('reserved', 'initiating', 'ready', 'callback_verifying', 'callback_verified', 'completed', 'failed', 'erased')`,
    ),
    check(
      'authority_idempotency_keys_lease_pair_check',
      sql`(${table.workflow_phase} in ('initiating', 'callback_verifying')
          and ${table.lease_token_hash} is not null and ${table.lease_expires_at} is not null)
        or ((${table.workflow_phase} is null or ${table.workflow_phase} not in ('initiating', 'callback_verifying'))
          and ${table.lease_token_hash} is null and ${table.lease_expires_at} is null)`,
    ),
    check(
      'authority_idempotency_keys_workflow_state_check',
      sql`${table.workflow_phase} is null
        or (${table.workflow_phase} is not null
          and ((${table.state} = 'started' and ${table.workflow_phase} in ('reserved', 'initiating', 'ready', 'callback_verifying', 'callback_verified'))
            or (${table.state} = 'completed' and ${table.workflow_phase} in ('completed', 'failed')))
          and ${table.workflow_payload_encrypted} is not null)
        or (${table.state} = 'completed' and ${table.workflow_phase} = 'erased'
          and ${table.workflow_payload_encrypted} is null)`,
    ),
    check(
      'authority_idempotency_keys_completion_check',
      sql`(${table.state} = 'started' and ${table.response_status} is null and ${table.response_body} is null)
        or (${table.state} = 'completed' and ${table.response_status} is not null
          and (${table.response_body} is not null or ${table.response_tombstone_hash} is not null))`,
    ),
  ],
);
