// Proxy operations and their attempts, evidence and accounting.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  bigint,
  index,
  uniqueIndex,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { authorityUses } from './authority-uses.js';
import { intentApprovals } from './intents.js';
import { operators } from './operators.js';
import { passports } from './passports.js';
import { services, serviceConnections } from './services.js';

// Durable idempotency and replay ledger for non-GET proxy execution. The row
// is a permanent tombstone: retention jobs scrub encrypted payloads but never
// delete the operation identity used to reject a later replay.
export const proxyOperations = pgTable(
  'proxy_operations',
  {
    id: text('id').primaryKey(), // pop_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    operation_key_hash: text('operation_key_hash').notNull(),
    request_hash: text('request_hash').notNull(),
    effect_correlation_hash: text('effect_correlation_hash').notNull(),
    tombstone_hash: text('tombstone_hash').notNull(),

    // Exact prepared bytes are KMS-enveloped. Only non-secret routing identity
    // and content hashes remain visible to PostgreSQL operators.
    prepared_request_version: integer('prepared_request_version').notNull().default(1),
    prepared_request_encrypted: text('prepared_request_encrypted'),
    prepared_request_key_ref: text('prepared_request_key_ref'),
    prepared_request_readable_until: timestamp('prepared_request_readable_until', {
      withTimezone: true,
    }).notNull(),

    agent_id: text('agent_id').notNull(),
    passport_jti: text('passport_jti').notNull(),
    authority_use_id: text('authority_use_id'),
    approval_id: text('approval_id'),
    service_connection_id: text('service_connection_id').notNull(),
    service_id: text('service_id')
      .notNull()
      .references(() => services.id),
    credential_version: integer('credential_version').notNull(),
    provider: text('provider').notNull(),
    method: text('method').notNull(),
    destination_config_hash: text('destination_config_hash').notNull(),
    // Hash of the encrypted originating service scope, exact normalized
    // resource, and signed authority_refs. authority_use_id remains separate
    // provenance and is never treated as a Passport claim.
    scope_commitment_hash: text('scope_commitment_hash').notNull(),
    scope_descriptor_version: integer('scope_descriptor_version').notNull().default(1),
    scope_descriptor_encrypted: text('scope_descriptor_encrypted'),
    scope_descriptor_key_ref: text('scope_descriptor_key_ref'),
    destination_origin: text('destination_origin').notNull(),
    pathname_hash: text('pathname_hash').notNull(),
    query_hash: text('query_hash').notNull(),
    header_names: jsonb('header_names').notNull().$type<string[]>(),
    headers_hash: text('headers_hash').notNull(),
    body_hash: text('body_hash'),
    body_bytes: bigint('body_bytes', { mode: 'number' }).notNull().default(0),
    adapter_kind: text('adapter_kind').notNull().default('generic'),
    native_idempotency_key_hash: text('native_idempotency_key_hash'),
    provider_account_hash: text('provider_account_hash'),
    retry_deadline: timestamp('retry_deadline', { withTimezone: true }),
    reconciliation_state: text('reconciliation_state').notNull().default('not_required'),
    reconciliation_resource_hash: text('reconciliation_resource_hash'),
    reconciliation_evidence_hash: text('reconciliation_evidence_hash'),
    reconciliation_provider_status: text('reconciliation_provider_status'),
    reconciliation_checked_at: timestamp('reconciliation_checked_at', { withTimezone: true }),
    contradictory_evidence_hash: text('contradictory_evidence_hash'),
    late_evidence_at: timestamp('late_evidence_at', { withTimezone: true }),

    delivery_state: text('delivery_state').notNull().default('admitted'),
    replay_state: text('replay_state').notNull().default('none'),
    accounting_state: text('accounting_state').notNull().default('reserved'),

    admission_owner_hash: text('admission_owner_hash').notNull(),
    admission_fence: integer('admission_fence').notNull().default(1),
    admission_lease_expires_at: timestamp('admission_lease_expires_at', {
      withTimezone: true,
    }).notNull(),
    dispatch_owner_hash: text('dispatch_owner_hash'),
    dispatch_fence: integer('dispatch_fence').notNull().default(0),
    dispatch_lease_expires_at: timestamp('dispatch_lease_expires_at', { withTimezone: true }),
    dispatch_started_at: timestamp('dispatch_started_at', { withTimezone: true }),
    transport_attempts: integer('transport_attempts').notNull().default(0),

    response_status: integer('response_status'),
    response_hash: text('response_hash'),
    response_envelope_version: integer('response_envelope_version'),
    response_encrypted: text('response_encrypted'),
    response_key_ref: text('response_key_ref'),
    response_ciphertext_bytes: bigint('response_ciphertext_bytes', { mode: 'number' }),
    response_readable_until: timestamp('response_readable_until', { withTimezone: true }),
    response_received_at: timestamp('response_received_at', { withTimezone: true }),
    outcome_unknown_at: timestamp('outcome_unknown_at', { withTimezone: true }),
    // An outcome_unknown write nothing settled for PROXY_OPERATION_UNRESOLVED_AFTER_DAYS: it stays unknown, is never
    // sent again, and its agent and owner have been told.
    unresolved_at: timestamp('unresolved_at', { withTimezone: true }),

    // Resumable bookkeeping after a screened provider response is durable.
    // This lease never grants provider-dispatch authority.
    post_response_work_state: text('post_response_work_state').notNull().default('none'),
    post_response_context_version: integer('post_response_context_version'),
    post_response_context_encrypted: text('post_response_context_encrypted'),
    post_response_context_key_ref: text('post_response_context_key_ref'),
    post_response_owner_hash: text('post_response_owner_hash'),
    post_response_lease_expires_at: timestamp('post_response_lease_expires_at', {
      withTimezone: true,
    }),
    post_response_next_attempt_at: timestamp('post_response_next_attempt_at', {
      withTimezone: true,
    }),
    post_response_attempts: integer('post_response_attempts').notNull().default(0),
    post_response_credential_at: timestamp('post_response_credential_at', { withTimezone: true }),
    post_response_audit_at: timestamp('post_response_audit_at', { withTimezone: true }),
    post_response_claims_at: timestamp('post_response_claims_at', { withTimezone: true }),
    post_response_intent_claim_id: text('post_response_intent_claim_id'),
    post_response_outcome_claim_id: text('post_response_outcome_claim_id'),
    post_response_security_at: timestamp('post_response_security_at', { withTimezone: true }),
    post_response_analytics_at: timestamp('post_response_analytics_at', { withTimezone: true }),
    post_response_authority_at: timestamp('post_response_authority_at', { withTimezone: true }),
    post_response_completed_at: timestamp('post_response_completed_at', { withTimezone: true }),

    capacity_reserved_bytes: bigint('capacity_reserved_bytes', { mode: 'number' })
      .notNull()
      .default(0),
    capacity_used_bytes: bigint('capacity_used_bytes', { mode: 'number' }).notNull().default(0),
    capacity_released_at: timestamp('capacity_released_at', { withTimezone: true }),

    accounting_period: text('accounting_period').notNull(), // YYYY-MM, fixed at admission
    accounting_units: integer('accounting_units').notNull().default(1),
    accounting_cents: bigint('accounting_cents', { mode: 'number' }).notNull().default(0),
    accounting_obligation_id: text('accounting_obligation_id').notNull(),
    wallet_transaction_id: text('wallet_transaction_id'),
    accounting_reserved_at: timestamp('accounting_reserved_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    accounting_committed_at: timestamp('accounting_committed_at', { withTimezone: true }),
    accounting_released_at: timestamp('accounting_released_at', { withTimezone: true }),

    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    erased_at: timestamp('erased_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('proxy_operations_id_operator_idx').on(table.id, table.operator_id),
    uniqueIndex('proxy_operations_operator_key_idx').on(
      table.operator_id,
      table.operation_key_hash,
    ),
    uniqueIndex('proxy_operations_accounting_obligation_idx').on(
      table.operator_id,
      table.accounting_obligation_id,
    ),
    uniqueIndex('proxy_operations_authority_use_idx')
      .on(table.authority_use_id)
      .where(sql`${table.authority_use_id} is not null`),
    index('proxy_operations_operator_delivery_idx').on(
      table.operator_id,
      table.delivery_state,
      table.created_at,
    ),
    index('proxy_operations_effect_correlation_idx').on(
      table.operator_id,
      table.effect_correlation_hash,
      table.delivery_state,
    ),
    index('proxy_operations_operator_capacity_idx').on(table.operator_id, table.replay_state),
    index('proxy_operations_replay_expiry_idx').on(table.response_readable_until),
    // The sweep that marks writes unresolved once their outcome has been unknown too long.
    index('proxy_operations_unresolved_due_idx')
      .on(table.outcome_unknown_at)
      .where(sql`${table.delivery_state} = 'outcome_unknown' and ${table.unresolved_at} is null`),
    index('proxy_operations_post_response_work_idx').on(
      table.post_response_work_state,
      table.post_response_next_attempt_at,
      table.post_response_lease_expires_at,
    ),
    foreignKey({
      columns: [table.agent_id, table.operator_id],
      foreignColumns: [agents.id, agents.operator_id],
      name: 'proxy_operations_agent_operator_fk',
    }),
    foreignKey({
      columns: [table.passport_jti, table.operator_id],
      foreignColumns: [passports.jti, passports.operator_id],
      name: 'proxy_operations_passport_operator_fk',
    }),
    foreignKey({
      columns: [table.authority_use_id, table.operator_id],
      foreignColumns: [authorityUses.id, authorityUses.operator_id],
      name: 'proxy_operations_authority_use_operator_fk',
    }),
    foreignKey({
      columns: [table.approval_id, table.operator_id],
      foreignColumns: [intentApprovals.id, intentApprovals.operator_id],
      name: 'proxy_operations_approval_operator_fk',
    }),
    foreignKey({
      columns: [table.service_connection_id, table.operator_id],
      foreignColumns: [serviceConnections.id, serviceConnections.operator_id],
      name: 'proxy_operations_connection_operator_fk',
    }),
    check(
      'proxy_operations_method_check',
      sql`${table.method} in ('POST', 'PUT', 'PATCH', 'DELETE')`,
    ),
    check('proxy_operations_adapter_check', sql`${table.adapter_kind} in ('generic', 'stripe')`),
    check(
      'proxy_operations_adapter_binding_check',
      sql`(${table.adapter_kind} = 'generic' and ${table.native_idempotency_key_hash} is null
          and ${table.provider_account_hash} is null and ${table.retry_deadline} is null
          and ${table.reconciliation_state} = 'not_required')
        or (${table.adapter_kind} = 'stripe' and ${table.native_idempotency_key_hash} is not null
          and ${table.provider_account_hash} is not null and ${table.retry_deadline} is not null
          and ${table.retry_deadline} <= ${table.created_at} + interval '23 hours'
          and ${table.reconciliation_state} in ('pending', 'confirmed', 'not_found', 'contradictory', 'expired'))`,
    ),
    check(
      'proxy_operations_delivery_state_check',
      sql`${table.delivery_state} in ('admitted', 'dispatching', 'response_received', 'outcome_unknown')`,
    ),
    check(
      'proxy_operations_replay_state_check',
      sql`${table.replay_state} in ('none', 'screening', 'available', 'expired', 'erased')`,
    ),
    check(
      'proxy_operations_accounting_state_check',
      sql`${table.accounting_state} in ('reserved', 'committed', 'released')`,
    ),
    check(
      'proxy_operations_owner_hash_check',
      sql`${table.admission_owner_hash} ~ '^[0-9a-f]{64}$'
        and (${table.dispatch_owner_hash} is null or ${table.dispatch_owner_hash} ~ '^[0-9a-f]{64}$')`,
    ),
    check(
      'proxy_operations_effect_correlation_hash_check',
      sql`${table.effect_correlation_hash} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'proxy_operations_reconciliation_evidence_check',
      sql`(${table.reconciliation_state} in ('pending', 'not_required')
          and ${table.reconciliation_evidence_hash} is null
          and ${table.reconciliation_provider_status} is null)
        or (${table.reconciliation_state} = 'confirmed'
          and ${table.reconciliation_evidence_hash} ~ '^sha256:[0-9a-f]{64}$'
          and ${table.reconciliation_provider_status} in ('pending', 'requires_action', 'succeeded', 'failed', 'canceled'))
        or (${table.reconciliation_state} in ('not_found', 'contradictory', 'expired')
          and ${table.reconciliation_evidence_hash} ~ '^sha256:[0-9a-f]{64}$'
          and ${table.reconciliation_provider_status} is null)`,
    ),
    check(
      'proxy_operations_fence_check',
      sql`${table.admission_fence} > 0 and ${table.dispatch_fence} >= 0
        and ${table.transport_attempts} between 0 and 3`,
    ),
    check('proxy_operations_credential_version_check', sql`${table.credential_version} > 0`),
    check(
      'proxy_operations_capacity_check',
      sql`${table.body_bytes} >= 0 and ${table.capacity_reserved_bytes} >= 0 and ${table.capacity_used_bytes} >= 0
        and ${table.capacity_used_bytes} <= ${table.capacity_reserved_bytes}`,
    ),
    check(
      'proxy_operations_accounting_amount_check',
      sql`${table.accounting_units} = 1 and ${table.accounting_cents} >= 0
        and ${table.accounting_period} ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'`,
    ),
    check(
      'proxy_operations_dispatch_check',
      sql`(${table.delivery_state} = 'admitted' and ${table.dispatch_owner_hash} is null
          and ${table.dispatch_fence} = 0 and ${table.dispatch_started_at} is null)
        or (${table.delivery_state} <> 'admitted' and ${table.dispatch_owner_hash} is not null
          and ${table.dispatch_fence} > 0 and ${table.dispatch_started_at} is not null)`,
    ),
    check(
      'proxy_operations_response_check',
      sql`(${table.replay_state} = 'available'
          and ${table.delivery_state} = 'response_received'
          and ${table.response_status} between 100 and 599
          and ${table.response_hash} is not null
          and ${table.response_envelope_version} = 1
          and ${table.response_encrypted} is not null
          and ${table.response_key_ref} is not null
          and ${table.response_ciphertext_bytes} is not null
          and ${table.response_readable_until} is not null
          and ${table.response_received_at} is not null)
        or (${table.replay_state} <> 'available' and ${table.response_encrypted} is null
          and ${table.response_key_ref} is null and ${table.response_ciphertext_bytes} is null)`,
    ),
    check(
      'proxy_operations_erasure_check',
      sql`(${table.replay_state} in ('expired', 'erased')
          and ${table.prepared_request_encrypted} is null
          and ${table.prepared_request_key_ref} is null
          and ${table.scope_descriptor_encrypted} is null
          and ${table.scope_descriptor_key_ref} is null
          and ${table.capacity_used_bytes} = 0
          and ${table.capacity_released_at} is not null)
        or ${table.replay_state} not in ('expired', 'erased')`,
    ),
    check(
      'proxy_operations_accounting_timestamps_check',
      sql`(${table.accounting_state} = 'reserved' and ${table.accounting_committed_at} is null
          and ${table.accounting_released_at} is null)
        or (${table.accounting_state} = 'committed' and ${table.accounting_committed_at} is not null
          and ${table.accounting_released_at} is null)
        or (${table.accounting_state} = 'released' and ${table.accounting_committed_at} is null
          and ${table.accounting_released_at} is not null)`,
    ),
    check(
      'proxy_operations_post_response_work_check',
      sql`(${table.post_response_work_state} = 'none'
          and ${table.post_response_context_encrypted} is null
          and ${table.post_response_context_key_ref} is null)
        or (${table.post_response_work_state} in ('pending', 'processing', 'waiting_provider')
          and ${table.post_response_context_version} = 1
          and ${table.post_response_context_encrypted} is not null
          and ${table.post_response_context_key_ref} is not null
          and ${table.post_response_completed_at} is null)
        or (${table.post_response_work_state} = 'completed'
          and ${table.post_response_context_encrypted} is null
          and ${table.post_response_context_key_ref} is null
          and ${table.post_response_completed_at} is not null)
        or (${table.post_response_work_state} = 'expired'
          and ${table.post_response_context_encrypted} is null
          and ${table.post_response_context_key_ref} is null
          and ${table.post_response_completed_at} is null)`,
    ),
    check(
      'proxy_operations_post_response_lease_check',
      sql`(${table.post_response_work_state} = 'processing'
          and ${table.post_response_owner_hash} ~ '^[0-9a-f]{64}$'
          and ${table.post_response_lease_expires_at} is not null)
        or (${table.post_response_work_state} <> 'processing'
          and ${table.post_response_owner_hash} is null
          and ${table.post_response_lease_expires_at} is null)`,
    ),
    check(
      'proxy_operations_post_response_attempts_check',
      sql`${table.post_response_attempts} >= 0`,
    ),
    check(
      'proxy_operations_post_response_schedule_check',
      sql`(${table.post_response_work_state} = 'pending'
          and ${table.post_response_next_attempt_at} is not null)
        or (${table.post_response_work_state} <> 'pending'
          and ${table.post_response_next_attempt_at} is null)`,
    ),
  ],
);

// One row per actual transport attempt. Attempt numbers are permanent evidence
// and are constrained to the adapter's signed retry budget.
export const proxyOperationAttempts = pgTable(
  'proxy_operation_attempts',
  {
    id: text('id').primaryKey(), // poa_*
    operator_id: text('operator_id').notNull(),
    operation_id: text('operation_id').notNull(),
    attempt_number: integer('attempt_number').notNull(),
    dispatch_owner_hash: text('dispatch_owner_hash').notNull(),
    dispatch_fence: integer('dispatch_fence').notNull(),
    lease_expires_at: timestamp('lease_expires_at', { withTimezone: true }).notNull(),
    request_evidence_hash: text('request_evidence_hash').notNull(),
    transport_evidence_hash: text('transport_evidence_hash'),
    provider_request_id_hash: text('provider_request_id_hash'),
    outcome: text('outcome').notNull().default('pending'),
    response_status: integer('response_status'),
    started_at: timestamp('started_at', { withTimezone: true }).notNull().defaultNow(),
    completed_at: timestamp('completed_at', { withTimezone: true }),
    late_evidence_at: timestamp('late_evidence_at', { withTimezone: true }),
    contradictory_evidence_hash: text('contradictory_evidence_hash'),
  },
  (table) => [
    uniqueIndex('proxy_operation_attempts_operation_number_idx').on(
      table.operation_id,
      table.attempt_number,
    ),
    index('proxy_operation_attempts_operator_started_idx').on(table.operator_id, table.started_at),
    foreignKey({
      columns: [table.operation_id, table.operator_id],
      foreignColumns: [proxyOperations.id, proxyOperations.operator_id],
      name: 'proxy_operation_attempts_operation_operator_fk',
    }).onDelete('cascade'),
    check(
      'proxy_operation_attempts_number_check',
      sql`${table.attempt_number} between 1 and 3 and ${table.dispatch_fence} > 0`,
    ),
    check(
      'proxy_operation_attempts_owner_hash_check',
      sql`${table.dispatch_owner_hash} ~ '^[0-9a-f]{64}$'`,
    ),
    check(
      'proxy_operation_attempts_outcome_check',
      sql`${table.outcome} in ('pending', 'response_received', 'outcome_unknown', 'reconciled', 'contradictory')`,
    ),
    check(
      'proxy_operation_attempts_completion_check',
      sql`(${table.outcome} = 'pending' and ${table.completed_at} is null)
        or (${table.outcome} <> 'pending' and ${table.completed_at} is not null)`,
    ),
  ],
);

export const proxyOperationEvidence = pgTable(
  'proxy_operation_evidence',
  {
    id: text('id').primaryKey(), // poe_*
    operator_id: text('operator_id').notNull(),
    operation_id: text('operation_id').notNull(),
    kind: text('kind').notNull(),
    evidence_hash: text('evidence_hash').notNull(),
    reconciliation_state: text('reconciliation_state'),
    resource_hash: text('resource_hash'),
    observed_at: timestamp('observed_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('proxy_operation_evidence_operation_observed_idx').on(
      table.operation_id,
      table.observed_at,
    ),
    foreignKey({
      columns: [table.operation_id, table.operator_id],
      foreignColumns: [proxyOperations.id, proxyOperations.operator_id],
      name: 'proxy_operation_evidence_operation_operator_fk',
    }).onDelete('cascade'),
    check(
      'proxy_operation_evidence_kind_check',
      sql`${table.kind} in ('reconciliation', 'late', 'contradictory')`,
    ),
  ],
);

// Human acknowledgement for a deliberate replacement of an operation whose
// provider outcome is still unknown. The browser chooses the public handles
// and exact request commitment; dispatch consumes this row once, in the same
// transaction that claims the replacement operation. Raw handles and session
// tokens are never persisted.
export const proxyOperationReplacementAcknowledgements = pgTable(
  'proxy_operation_replacement_acknowledgements',
  {
    id: text('id').primaryKey(), // pra_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    original_operation_id: text('original_operation_id').notNull(),
    replacement_operation_key_hash: text('replacement_operation_key_hash').notNull(),
    replacement_request_hash: text('replacement_request_hash').notNull(),
    warning_version: integer('warning_version').notNull(),
    warning_text: text('warning_text').notNull(),
    warning_hash: text('warning_hash').notNull(),
    human_author_kind: text('human_author_kind').notNull(),
    human_author_id: text('human_author_id').notNull(),
    dashboard_session_family_id: text('dashboard_session_family_id').notNull(),
    dashboard_session_token_hash: text('dashboard_session_token_hash').notNull(),
    acknowledged_at: timestamp('acknowledged_at', { withTimezone: true }).notNull().defaultNow(),
    consumed_at: timestamp('consumed_at', { withTimezone: true }),
    consumed_by_operation_id: text('consumed_by_operation_id'),
  },
  (table) => [
    uniqueIndex('proxy_operation_replacement_original_idx').on(
      table.operator_id,
      table.original_operation_id,
    ),
    uniqueIndex('proxy_operation_replacement_handle_idx').on(
      table.operator_id,
      table.replacement_operation_key_hash,
    ),
    foreignKey({
      columns: [table.original_operation_id, table.operator_id],
      foreignColumns: [proxyOperations.id, proxyOperations.operator_id],
      name: 'proxy_operation_replacement_original_operator_fk',
    }).onDelete('cascade'),
    foreignKey({
      columns: [table.consumed_by_operation_id, table.operator_id],
      foreignColumns: [proxyOperations.id, proxyOperations.operator_id],
      name: 'proxy_operation_replacement_consumed_operator_fk',
    }).onDelete('cascade'),
    check(
      'proxy_operation_replacement_hashes_check',
      sql`${table.replacement_operation_key_hash} ~ '^[0-9a-f]{64}$'
        and ${table.replacement_request_hash} ~ '^sha256:[0-9a-f]{64}$'
        and ${table.warning_hash} ~ '^sha256:[0-9a-f]{64}$'
        and ${table.dashboard_session_token_hash} ~ '^[0-9a-f]{64}$'`,
    ),
    check(
      'proxy_operation_replacement_author_check',
      sql`${table.human_author_kind} in ('operator_owner', 'team_member')`,
    ),
    check(
      'proxy_operation_replacement_consumption_check',
      sql`(${table.consumed_at} is null and ${table.consumed_by_operation_id} is null)
        or (${table.consumed_at} is not null and ${table.consumed_by_operation_id} is not null)`,
    ),
  ],
);

// PostgreSQL-authoritative logical action meter. One receipt is written for
// every evaluated non-GET request, including denials. Exact retries, status
// reads and replay reads reuse the unique receipt and cannot increment usage.
export const proxyAccountingReceipts = pgTable(
  'proxy_accounting_receipts',
  {
    id: text('id').primaryKey(), // par_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    accounting_period: text('accounting_period').notNull(),
    operation_key_hash: text('operation_key_hash').notNull(),
    evaluation_hash: text('evaluation_hash').notNull(),
    verdict: text('verdict').notNull(),
    period_sequence: integer('period_sequence').notNull(),
    allowance_units: integer('allowance_units').notNull().default(1),
    // Integer units of 0.0001 cent. This exactly represents the current
    // fractional action overage without floating-point or early rounding.
    overage_units_10000th_cent: bigint('overage_units_10000th_cent', { mode: 'number' })
      .notNull()
      .default(0),
    wallet_obligation_id: text('wallet_obligation_id').notNull(),
    wallet_transaction_id: text('wallet_transaction_id'),
    wallet_state: text('wallet_state').notNull().default('none'),
    evaluated_at: timestamp('evaluated_at', { withTimezone: true }).notNull().defaultNow(),
    wallet_committed_at: timestamp('wallet_committed_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('proxy_accounting_receipts_logical_action_idx').on(
      table.operator_id,
      table.accounting_period,
      table.operation_key_hash,
    ),
    uniqueIndex('proxy_accounting_receipts_period_sequence_idx').on(
      table.operator_id,
      table.accounting_period,
      table.period_sequence,
    ),
    uniqueIndex('proxy_accounting_receipts_obligation_idx').on(
      table.operator_id,
      table.wallet_obligation_id,
    ),
    index('proxy_accounting_receipts_operator_period_idx').on(
      table.operator_id,
      table.accounting_period,
    ),
    check(
      'proxy_accounting_receipts_values_check',
      sql`${table.accounting_period} ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'
        and ${table.period_sequence} > 0 and ${table.allowance_units} = 1
        and ${table.overage_units_10000th_cent} >= 0`,
    ),
    check(
      'proxy_accounting_receipts_verdict_check',
      sql`${table.verdict} in ('admitted', 'denied')`,
    ),
    check(
      'proxy_accounting_receipts_wallet_check',
      sql`(${table.overage_units_10000th_cent} = 0 and ${table.wallet_state} = 'none'
          and ${table.wallet_transaction_id} is null and ${table.wallet_committed_at} is null)
        or (${table.overage_units_10000th_cent} > 0 and ${table.wallet_state} = 'pending'
          and ${table.wallet_transaction_id} is null and ${table.wallet_committed_at} is null)
        or (${table.overage_units_10000th_cent} > 0 and ${table.wallet_state} = 'committed'
          and ${table.wallet_transaction_id} is not null and ${table.wallet_committed_at} is not null)`,
    ),
  ],
);
