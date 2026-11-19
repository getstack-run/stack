// Authority principals, receivers, profile versions and receiver keys.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  index,
  uniqueIndex,
  check,
  foreignKey,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';
import { serviceConnections } from './services.js';
import { passportClaims } from './signed-records.js';

// ─── Authority binding and proof rails (migration 0056) ─────────────

export const authorityPrincipals = pgTable(
  'authority_principals',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(),
    label_encrypted: text('label_encrypted'),
    status: text('status').notNull().default('active'),
    superseded_by_id: text('superseded_by_id'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'),
    erased_at: timestamp('erased_at', { withTimezone: true }),
    tombstone_hash: text('tombstone_hash'),
    tombstone_claim_id: text('tombstone_claim_id').references(() => passportClaims.claim_id),
  },
  (table) => [
    uniqueIndex('authority_principals_id_operator_idx').on(table.id, table.operator_id),
    index('authority_principals_operator_status_idx').on(table.operator_id, table.status),
    index('authority_principals_operator_kind_idx').on(table.operator_id, table.kind),
    uniqueIndex('authority_principals_superseded_unique_idx')
      .on(table.operator_id, table.superseded_by_id)
      .where(sql`${table.superseded_by_id} is not null`),
    foreignKey({
      columns: [table.superseded_by_id, table.operator_id],
      foreignColumns: [table.id, table.operator_id],
      name: 'authority_principals_superseded_operator_fk',
    }),
    check('authority_principals_kind_check', sql`${table.kind} in ('person', 'organisation')`),
    check(
      'authority_principals_status_check',
      sql`${table.status} in ('active', 'revoked', 'erased')`,
    ),
    foreignKey({
      columns: [table.tombstone_claim_id, table.operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_principals_tombstone_claim_operator_fk',
    }),
    check(
      'authority_principals_erasure_check',
      sql`(${table.status} = 'erased' and ${table.label_encrypted} is null
          and ${table.erased_at} is not null and ${table.tombstone_hash} is not null
          and ${table.tombstone_claim_id} is not null)
        or (${table.status} <> 'erased' and ${table.erased_at} is null
          and ${table.tombstone_hash} is null and ${table.tombstone_claim_id} is null)`,
    ),
  ],
);

export const authorityReceivers = pgTable(
  'authority_receivers',
  {
    id: text('id').primaryKey(),
    managed_by_operator_id: text('managed_by_operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    mode: text('mode').notNull(),
    canonical_identifier: text('canonical_identifier').notNull(),
    display_name: text('display_name').notNull(),
    proxy_service_connection_id: text('proxy_service_connection_id'),
    current_profile_version_id: text('current_profile_version_id'),
    status: text('status').notNull().default('pending'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    verified_at: timestamp('verified_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'),
  },
  (table) => [
    uniqueIndex('authority_receivers_id_operator_idx').on(table.id, table.managed_by_operator_id),
    index('authority_receivers_manager_status_idx').on(table.managed_by_operator_id, table.status),
    uniqueIndex('authority_receivers_native_identifier_idx')
      .on(table.canonical_identifier)
      .where(sql`${table.mode} = 'native'`),
    uniqueIndex('authority_receivers_proxy_identifier_idx')
      .on(table.managed_by_operator_id, table.canonical_identifier)
      .where(sql`${table.mode} = 'proxy_bridge'`),
    uniqueIndex('authority_receivers_internal_identifier_idx')
      .on(table.managed_by_operator_id, table.canonical_identifier)
      .where(sql`${table.mode} = 'internal'`),
    foreignKey({
      columns: [table.proxy_service_connection_id, table.managed_by_operator_id],
      foreignColumns: [serviceConnections.id, serviceConnections.operator_id],
      name: 'authority_receivers_proxy_connection_operator_fk',
    }),
    check(
      'authority_receivers_mode_check',
      sql`${table.mode} in ('native', 'proxy_bridge', 'internal')`,
    ),
    check(
      'authority_receivers_status_check',
      sql`${table.status} in ('pending', 'active', 'suspended', 'revoked')`,
    ),
    check(
      'authority_receivers_proxy_connection_check',
      sql`(${table.mode} in ('native', 'internal') and ${table.proxy_service_connection_id} is null)
        or (${table.mode} = 'proxy_bridge' and ${table.proxy_service_connection_id} is not null)`,
    ),
  ],
);

export const authorityProfileVersions = pgTable(
  'authority_profile_versions',
  {
    id: text('id').primaryKey(),
    owner_operator_id: text('owner_operator_id').references(() => operators.id, {
      onDelete: 'cascade',
    }),
    profile_kind: text('profile_kind').notNull(),
    profile_key: text('profile_key').notNull(),
    version: integer('version').notNull(),
    receiver_id: text('receiver_id').references(() => authorityReceivers.id, {
      onDelete: 'cascade',
    }),
    schema_uri: text('schema_uri').notNull(),
    schema_version: text('schema_version').notNull(),
    adapter_key: text('adapter_key').notNull(),
    adapter_version: integer('adapter_version').notNull(),
    config_json: jsonb('config_json').notNull().$type<Record<string, unknown>>(),
    content_hash: text('content_hash').notNull(),
    claim_id: text('claim_id').references(() => passportClaims.claim_id),
    status: text('status').notNull().default('draft'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    activated_at: timestamp('activated_at', { withTimezone: true }),
    retired_at: timestamp('retired_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('authority_profile_versions_id_owner_idx').on(table.id, table.owner_operator_id),
    uniqueIndex('authority_profile_versions_operator_logical_idx')
      .on(table.owner_operator_id, table.profile_kind, table.profile_key, table.version)
      .where(sql`${table.owner_operator_id} is not null`),
    uniqueIndex('authority_profile_versions_catalog_logical_idx')
      .on(table.profile_kind, table.profile_key, table.version)
      .where(sql`${table.owner_operator_id} is null`),
    uniqueIndex('authority_profile_versions_operator_content_idx')
      .on(table.owner_operator_id, table.profile_kind, table.content_hash)
      .where(sql`${table.owner_operator_id} is not null`),
    uniqueIndex('authority_profile_versions_catalog_content_idx')
      .on(table.profile_kind, table.content_hash)
      .where(sql`${table.owner_operator_id} is null`),
    index('authority_profile_versions_receiver_version_idx').on(table.receiver_id, table.version),
    index('authority_profile_versions_owner_status_idx').on(table.owner_operator_id, table.status),
    foreignKey({
      columns: [table.receiver_id, table.owner_operator_id],
      foreignColumns: [authorityReceivers.id, authorityReceivers.managed_by_operator_id],
      name: 'authority_profile_versions_receiver_owner_fk',
    }),
    foreignKey({
      columns: [table.claim_id, table.owner_operator_id],
      foreignColumns: [passportClaims.claim_id, passportClaims.operator_id],
      name: 'authority_profile_versions_claim_owner_fk',
    }),
    check(
      'authority_profile_versions_kind_check',
      sql`${table.profile_kind} in ('proof', 'domain', 'receiver')`,
    ),
    check(
      'authority_profile_versions_version_check',
      sql`${table.version} > 0 and ${table.adapter_version} > 0`,
    ),
    check(
      'authority_profile_versions_status_check',
      sql`${table.status} in ('draft', 'active', 'retired', 'revoked')`,
    ),
    check(
      'authority_profile_versions_receiver_check',
      sql`(${table.profile_kind} = 'receiver' and ${table.receiver_id} is not null and ${table.owner_operator_id} is not null)
        or (${table.profile_kind} <> 'receiver' and ${table.receiver_id} is null)`,
    ),
  ],
);

export const authorityReceiverKeys = pgTable(
  'authority_receiver_keys',
  {
    id: text('id').primaryKey(),
    receiver_id: text('receiver_id')
      .notNull()
      .references(() => authorityReceivers.id, { onDelete: 'cascade' }),
    key_id: text('key_id').notNull(),
    use: text('use').notNull(),
    algorithm: text('algorithm').notNull(),
    public_jwk: jsonb('public_jwk').notNull().$type<Record<string, unknown>>(),
    thumbprint: text('thumbprint').notNull(),
    status: text('status').notNull().default('active'),
    valid_from: timestamp('valid_from', { withTimezone: true }).notNull(),
    valid_until: timestamp('valid_until', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('authority_receiver_keys_id_receiver_idx').on(table.id, table.receiver_id),
    uniqueIndex('authority_receiver_keys_receiver_key_use_idx').on(
      table.receiver_id,
      table.key_id,
      table.use,
    ),
    uniqueIndex('authority_receiver_keys_receiver_thumbprint_use_idx').on(
      table.receiver_id,
      table.thumbprint,
      table.use,
    ),
    index('authority_receiver_keys_receiver_use_status_idx').on(
      table.receiver_id,
      table.use,
      table.status,
    ),
    check(
      'authority_receiver_keys_use_check',
      sql`${table.use} in ('request_signing', 'response_encryption', 'receipt_signing', 'transport_mtls')`,
    ),
    check(
      'authority_receiver_keys_status_check',
      sql`${table.status} in ('active', 'retired', 'revoked')`,
    ),
    check(
      'authority_receiver_keys_validity_check',
      sql`${table.valid_until} is null or ${table.valid_until} > ${table.valid_from}`,
    ),
  ],
);
