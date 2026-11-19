// Authority proofs and bindings.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  boolean,
  index,
  uniqueIndex,
  primaryKey,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import {
  authorityPrincipals,
  authorityReceivers,
  authorityProfileVersions,
} from './authority-registry.js';
import { identityClaims } from './identity.js';
import { operators } from './operators.js';
import { passportClaims } from './signed-records.js';

export const authorityProofs = pgTable(
  'authority_proofs',
  {
    id: text('id').notNull(),
    version: integer('version').notNull(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    subject_principal_id: text('subject_principal_id').notNull(),
    represented_principal_id: text('represented_principal_id'),
    profile_version_id: text('profile_version_id')
      .notNull()
      .references(() => authorityProfileVersions.id),
    proof_kind: text('proof_kind').notNull(),
    source_kind: text('source_kind').notNull(),
    legacy_identity_claim_id: text('legacy_identity_claim_id').references(() => identityClaims.id),
    issuer_identifier: text('issuer_identifier').notNull(),
    issuer_key_thumbprint: text('issuer_key_thumbprint'),
    original_relying_party_identifier: text('original_relying_party_identifier'),
    schema_uri: text('schema_uri').notNull(),
    schema_version: text('schema_version').notNull(),
    native_format: text('native_format').notNull(),
    native_evidence_encrypted: text('native_evidence_encrypted'),
    normalized_facts_encrypted: text('normalized_facts_encrypted'),
    native_evidence_hash: text('native_evidence_hash').notNull(),
    normalized_facts_hash: text('normalized_facts_hash'),
    verification_method: text('verification_method').notNull(),
    verifier_identifier: text('verifier_identifier').notNull(),
    verifier_version: text('verifier_version').notNull(),
    assurance_uri: text('assurance_uri'),
    verified_at: timestamp('verified_at', { withTimezone: true }).notNull(),
    valid_from: timestamp('valid_from', { withTimezone: true }).notNull(),
    expires_at: timestamp('expires_at', { withTimezone: true }),
    last_status_result: text('last_status_result'),
    last_status_checked_at: timestamp('last_status_checked_at', { withTimezone: true }),
    status_fresh_until: timestamp('status_fresh_until', { withTimezone: true }),
    status: text('status').notNull().default('pending'),
    supersedes_version: integer('supersedes_version'),
    claim_id: text('claim_id')
      .unique()
      .references(() => passportClaims.claim_id),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'),
    erased_at: timestamp('erased_at', { withTimezone: true }),
    tombstone_hash: text('tombstone_hash'),
    tombstone_claim_id: text('tombstone_claim_id').references(() => passportClaims.claim_id),
  },
  (table) => [
    primaryKey({ columns: [table.id, table.version] }),
    uniqueIndex('authority_proofs_id_version_operator_idx').on(
      table.id,
      table.version,
      table.operator_id,
    ),
    index('authority_proofs_subject_kind_status_idx').on(
      table.operator_id,
      table.subject_principal_id,
      table.proof_kind,
      table.status,
    ),
    index('authority_proofs_represented_kind_idx').on(
      table.operator_id,
      table.represented_principal_id,
      table.proof_kind,
    ),
    index('authority_proofs_active_expiry_idx')
      .on(table.operator_id, table.expires_at)
      .where(sql`${table.status} = 'active'`),
    index('authority_proofs_legacy_identity_idx').on(
      table.operator_id,
      table.legacy_identity_claim_id,
    ),
    foreignKey({
      columns: [table.subject_principal_id, table.operator_id],
      foreignColumns: [authorityPrincipals.id, authorityPrincipals.operator_id],
      name: 'authority_proofs_subject_operator_fk',
    }),
    foreignKey({
      columns: [table.represented_principal_id, table.operator_id],
      foreignColumns: [authorityPrincipals.id, authorityPrincipals.operator_id],
      name: 'authority_proofs_represented_operator_fk',
    }),
    foreignKey({
      columns: [table.legacy_identity_claim_id, table.operator_id],
      foreignColumns: [identityClaims.id, identityClaims.operator_id],
      name: 'authority_proofs_legacy_identity_operator_fk',
    }),
    foreignKey({
      columns: [table.claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_proofs_claim_operator_fk',
    }),
    foreignKey({
      columns: [table.tombstone_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_proofs_tombstone_claim_operator_fk',
    }),
    check('authority_proofs_version_check', sql`${table.version} > 0`),
    check(
      'authority_proofs_kind_check',
      sql`${table.proof_kind} in ('identity', 'capacity', 'mandate', 'consent', 'signature', 'domain', 'workload')`,
    ),
    check(
      'authority_proofs_source_check',
      sql`${table.source_kind} in ('legacy_identity_claim', 'external_native', 'stack_derived')`,
    ),
    check(
      'authority_proofs_status_check',
      sql`${table.status} in ('pending', 'active', 'suspended', 'revoked', 'replaced', 'erased')`,
    ),
    check(
      'authority_proofs_status_result_check',
      sql`${table.last_status_result} is null or ${table.last_status_result} in ('valid', 'revoked', 'unknown')`,
    ),
    check(
      'authority_proofs_source_storage_check',
      sql`(${table.source_kind} = 'legacy_identity_claim' and ${table.legacy_identity_claim_id} is not null
          and ${table.native_evidence_encrypted} is null and ${table.normalized_facts_encrypted} is null
          and ${table.normalized_facts_hash} is null)
        or (${table.source_kind} <> 'legacy_identity_claim' and ${table.legacy_identity_claim_id} is null
          and (${table.native_evidence_encrypted} is not null or ${table.status} = 'erased'))`,
    ),
    check(
      'authority_proofs_erasure_check',
      sql`(${table.status} = 'erased' and ${table.native_evidence_encrypted} is null
          and ${table.normalized_facts_encrypted} is null and ${table.erased_at} is not null
          and ${table.tombstone_hash} is not null and ${table.tombstone_claim_id} is not null)
        or (${table.status} <> 'erased' and ${table.erased_at} is null
          and ${table.tombstone_hash} is null and ${table.tombstone_claim_id} is null)`,
    ),
  ],
);

export const authorityProofDependencies = pgTable(
  'authority_proof_dependencies',
  {
    derived_proof_id: text('derived_proof_id').notNull(),
    derived_proof_version: integer('derived_proof_version').notNull(),
    operator_id: text('operator_id').notNull(),
    source_proof_id: text('source_proof_id').notNull(),
    source_proof_version: integer('source_proof_version').notNull(),
    relation: text('relation').notNull(),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({
      columns: [
        table.derived_proof_id,
        table.derived_proof_version,
        table.source_proof_id,
        table.source_proof_version,
        table.relation,
      ],
    }),
    foreignKey({
      columns: [table.derived_proof_id, table.derived_proof_version, table.operator_id],
      foreignColumns: [authorityProofs.id, authorityProofs.version, authorityProofs.operator_id],
      name: 'authority_proof_dependencies_derived_operator_fk',
    }),
    foreignKey({
      columns: [table.source_proof_id, table.source_proof_version, table.operator_id],
      foreignColumns: [authorityProofs.id, authorityProofs.version, authorityProofs.operator_id],
      name: 'authority_proof_dependencies_source_operator_fk',
    }),
    check(
      'authority_proof_dependencies_relation_check',
      sql`${table.relation} in ('verified_from', 'translated_from', 'composed_from')`,
    ),
  ],
);

export const authorityBindings = pgTable(
  'authority_bindings',
  {
    id: text('id').notNull(),
    version: integer('version').notNull(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    principal_id: text('principal_id').notNull(),
    agent_id: text('agent_id').notNull(),
    agent_key_thumbprint: text('agent_key_thumbprint').notNull(),
    receiver_id: text('receiver_id').notNull(),
    receiver_profile_version_id: text('receiver_profile_version_id')
      .notNull()
      .references(() => authorityProfileVersions.id),
    domain_profile_version_id: text('domain_profile_version_id').references(
      () => authorityProfileVersions.id,
    ),
    mission_ids: text('mission_ids').array().notNull().default([]),
    lineage_root_id: text('lineage_root_id').notNull(),
    lineage_root_version: integer('lineage_root_version').notNull(),
    parent_binding_id: text('parent_binding_id'),
    parent_binding_version: integer('parent_binding_version'),
    delegation_depth: integer('delegation_depth').notNull().default(0),
    purpose_code: text('purpose_code').notNull(),
    purpose_statement_encrypted: text('purpose_statement_encrypted'),
    purpose_hash: text('purpose_hash').notNull(),
    scope_encrypted: text('scope_encrypted'),
    scope_hash: text('scope_hash').notNull(),
    approval_policy_encrypted: text('approval_policy_encrypted'),
    approval_policy_hash: text('approval_policy_hash').notNull(),
    disclosure_policy_encrypted: text('disclosure_policy_encrypted'),
    disclosure_policy_hash: text('disclosure_policy_hash').notNull(),
    delegation_policy: jsonb('delegation_policy').notNull().$type<Record<string, unknown>>(),
    delegation_policy_hash: text('delegation_policy_hash').notNull(),
    proof_set_hash: text('proof_set_hash').notNull(),
    valid_from: timestamp('valid_from', { withTimezone: true }).notNull(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    status: text('status').notNull().default('draft'),
    claim_id: text('claim_id')
      .unique()
      .references(() => passportClaims.claim_id),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    activated_at: timestamp('activated_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'),
    supersedes_version: integer('supersedes_version'),
    erased_at: timestamp('erased_at', { withTimezone: true }),
    tombstone_hash: text('tombstone_hash'),
    tombstone_claim_id: text('tombstone_claim_id').references(() => passportClaims.claim_id),
  },
  (table) => [
    primaryKey({ columns: [table.id, table.version] }),
    uniqueIndex('authority_bindings_id_version_operator_idx').on(
      table.id,
      table.version,
      table.operator_id,
    ),
    index('authority_bindings_principal_status_idx').on(
      table.operator_id,
      table.principal_id,
      table.status,
    ),
    index('authority_bindings_agent_status_idx').on(
      table.operator_id,
      table.agent_id,
      table.status,
    ),
    index('authority_bindings_receiver_status_idx').on(table.receiver_id, table.status),
    index('authority_bindings_missions_idx').using('gin', table.mission_ids),
    index('authority_bindings_parent_idx').on(
      table.operator_id,
      table.parent_binding_id,
      table.parent_binding_version,
    ),
    index('authority_bindings_lineage_idx').on(
      table.operator_id,
      table.lineage_root_id,
      table.lineage_root_version,
      table.delegation_depth,
    ),
    check(
      'authority_bindings_purpose_code_check',
      sql`${table.purpose_code} ~ '^[a-z][a-z0-9]*([._:-][a-z0-9]+)*$' and ${table.purpose_code} !~ '[0-9]{6,}' and length(${table.purpose_code}) <= 128`,
    ),
    foreignKey({
      columns: [table.principal_id, table.operator_id],
      foreignColumns: [authorityPrincipals.id, authorityPrincipals.operator_id],
      name: 'authority_bindings_principal_operator_fk',
    }),
    foreignKey({
      columns: [table.agent_id, table.operator_id],
      foreignColumns: [agents.id, agents.operator_id],
      name: 'authority_bindings_agent_operator_fk',
    }),
    foreignKey({
      columns: [table.receiver_id, table.operator_id],
      foreignColumns: [authorityReceivers.id, authorityReceivers.managed_by_operator_id],
      name: 'authority_bindings_receiver_operator_fk',
    }),
    foreignKey({
      columns: [table.parent_binding_id, table.parent_binding_version, table.operator_id],
      foreignColumns: [table.id, table.version, table.operator_id],
      name: 'authority_bindings_parent_operator_fk',
    }),
    foreignKey({
      columns: [table.lineage_root_id, table.lineage_root_version, table.operator_id],
      foreignColumns: [table.id, table.version, table.operator_id],
      name: 'authority_bindings_root_operator_fk',
    }),
    foreignKey({
      columns: [table.claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_bindings_claim_operator_fk',
    }),
    foreignKey({
      columns: [table.tombstone_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_bindings_tombstone_claim_operator_fk',
    }),
    check('authority_bindings_version_check', sql`${table.version} > 0`),
    check('authority_bindings_depth_check', sql`${table.delegation_depth} between 0 and 4`),
    check(
      'authority_bindings_status_check',
      sql`${table.status} in ('draft', 'pending_approval', 'active', 'suspended', 'revoked', 'replaced', 'erased')`,
    ),
    check(
      'authority_bindings_erasure_check',
      sql`(${table.status} = 'erased' and ${table.purpose_statement_encrypted} is null
          and ${table.scope_encrypted} is null and ${table.approval_policy_encrypted} is null
          and ${table.disclosure_policy_encrypted} is null and ${table.erased_at} is not null
          and ${table.tombstone_hash} is not null and ${table.tombstone_claim_id} is not null)
        or (${table.status} <> 'erased' and ${table.scope_encrypted} is not null
          and ${table.approval_policy_encrypted} is not null and ${table.disclosure_policy_encrypted} is not null
          and ${table.erased_at} is null and ${table.tombstone_hash} is null
          and ${table.tombstone_claim_id} is null)`,
    ),
    check('authority_bindings_validity_check', sql`${table.expires_at} > ${table.valid_from}`),
    check(
      'authority_bindings_parent_check',
      sql`(${table.delegation_depth} = 0 and ${table.parent_binding_id} is null and ${table.parent_binding_version} is null)
        or (${table.delegation_depth} > 0 and ${table.parent_binding_id} is not null and ${table.parent_binding_version} is not null)`,
    ),
  ],
);

export const authorityBindingProofs = pgTable(
  'authority_binding_proofs',
  {
    binding_id: text('binding_id').notNull(),
    binding_version: integer('binding_version').notNull(),
    proof_id: text('proof_id').notNull(),
    proof_version: integer('proof_version').notNull(),
    operator_id: text('operator_id').notNull(),
    role: text('role').notNull(),
    authoriser_principal_id: text('authoriser_principal_id'),
    group_key: text('group_key').notNull(),
    weight: integer('weight').notNull().default(1),
    required: boolean('required').notNull().default(true),
    ordinal: integer('ordinal').notNull().default(0),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({
      columns: [
        table.binding_id,
        table.binding_version,
        table.proof_id,
        table.proof_version,
        table.role,
      ],
    }),
    index('authority_binding_proofs_proof_idx').on(
      table.operator_id,
      table.proof_id,
      table.proof_version,
    ),
    foreignKey({
      columns: [table.binding_id, table.binding_version, table.operator_id],
      foreignColumns: [
        authorityBindings.id,
        authorityBindings.version,
        authorityBindings.operator_id,
      ],
      name: 'authority_binding_proofs_binding_operator_fk',
    }),
    foreignKey({
      columns: [table.proof_id, table.proof_version, table.operator_id],
      foreignColumns: [authorityProofs.id, authorityProofs.version, authorityProofs.operator_id],
      name: 'authority_binding_proofs_proof_operator_fk',
    }),
    foreignKey({
      columns: [table.authoriser_principal_id, table.operator_id],
      foreignColumns: [authorityPrincipals.id, authorityPrincipals.operator_id],
      name: 'authority_binding_proofs_authoriser_operator_fk',
    }),
    check(
      'authority_binding_proofs_role_check',
      sql`${table.role} in ('principal_identity', 'authoriser_identity', 'authoriser_capacity', 'mandate', 'consent', 'domain')`,
    ),
    check(
      'authority_binding_proofs_weight_check',
      sql`${table.weight} > 0 and ${table.ordinal} >= 0`,
    ),
  ],
);
