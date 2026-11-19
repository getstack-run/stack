// Service catalog, operator connections and per-agent service grants.

import {
  pgTable,
  text,
  timestamp,
  integer,
  jsonb,
  boolean,
  index,
  uniqueIndex,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { agents } from './agents.js';
import { operators, teamMembers } from './operators.js';

// ─── Services (catalog of available integrations) ────────────────────

export const services = pgTable(
  'services',
  {
    id: text('id').primaryKey(),
    // NULL is a STACK-maintained catalog row. A non-NULL owner makes the
    // definition private to that operator; custom OAuth URLs and scopes must
    // never be mutable global state shared by unrelated tenants.
    operator_id: text('operator_id').references(() => operators.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull(), // slack | github | custom_internal_crm | ...
    name: text('name').notNull(),
    description: text('description').notNull(),
    oauth_auth_url: text('oauth_auth_url').notNull(),
    oauth_token_url: text('oauth_token_url').notNull(),
    scopes_available: jsonb('scopes_available').notNull().$type<string[]>(),
    available: boolean('available').notNull().default(true),
  },
  (table) => [
    uniqueIndex('services_catalog_provider_unique')
      .on(table.provider)
      .where(sql`${table.operator_id} is null`),
    uniqueIndex('services_custom_operator_provider_unique')
      .on(table.operator_id, table.provider)
      .where(sql`${table.operator_id} is not null`),
    check(
      'services_owner_shape_check',
      sql`(
        ${table.operator_id} is null
        and left(${table.provider}, 7) <> 'custom_'
      ) or (
        ${table.operator_id} is not null
        and left(${table.provider}, 7) = 'custom_'
        and ${table.available} = false
      )`,
    ),
  ],
);

// ─── Service Connections (operator's connected services) ─────────────

export const serviceConnections = pgTable(
  'service_connections',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    service_id: text('service_id')
      .notNull()
      .references(() => services.id),
    provider: text('provider').notNull(),
        // The customer's name for this connection; unique among a principal's active connections of the provider.
    name: text('name').notNull().default('default'),
    scopes: jsonb('scopes').notNull().$type<string[]>(),
    credential_ref: text('credential_ref').notNull(), // KMS key reference for encrypted credential
    credential_encrypted: text('credential_encrypted').notNull(), // KMS-encrypted OAuth token
    // Monotonic semantic credential version. Increment when the credential
    // material changes (connect/refresh/replace), but not when the same
    // plaintext is merely re-enveloped during a CMEK migration.
    credential_version: integer('credential_version').notNull().default(1),
    // Only the server-owned OAuth callback may create an app binding.
    oauth_managed: boolean('oauth_managed').notNull().default(false),
    connected_by: text('connected_by'), // member ID or null (= operator) — informational
    member_id: text('member_id').references(() => teamMembers.id), // null = shared, set = personal
    status: text('status').notNull().default('active'), // active | expired | revoked
    proxy_enabled: boolean('proxy_enabled').notNull().default(true),
    // Credential-to-destination binding. The hosts this connection's
    // credential may be sent to. NULL means "not declared" and the proxy
    // DENIES — it is not a wildcard. Seeded at connect time from
    // PROVIDER_API_HOSTS where the repo has a grounded value; the operator
    // declares it for per-tenant and unknown providers.
    allowed_hosts: jsonb('allowed_hosts').$type<string[]>(),
    // The service's MCP endpoint, when it speaks MCP over HTTP (`stack_service_tools`, `stack_service_call_tool`). https and
    // on one of allowed_hosts, checked when the connection is made and by the proxy on every call. NULL: the service is
    // not known to speak MCP, or STACK knows its endpoint (SERVICE_MCP_ENDPOINTS).
    mcp_url: text('mcp_url'),
    verification_status: text('verification_status').default('unknown'), // healthy | unhealthy | unknown
    verified_at: timestamp('verified_at', { withTimezone: true }),
    connected_at: timestamp('connected_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }),
    // resource provenance for partner grants (see agents table).
    created_via_grant_id: text('created_via_grant_id'),
  },
  (table) => [
    index('scon_operator_idx').on(table.operator_id),
    index('scon_member_idx').on(table.member_id),
    uniqueIndex('scon_id_operator_idx').on(table.id, table.operator_id),
    check('scon_credential_version_check', sql`${table.credential_version} > 0`),
    // Several active connections of one provider may coexist for a principal (shared, or one member) when their names
    // differ; the name is compared without case.
    uniqueIndex('scon_active_principal_name_idx')
      .on(table.operator_id, table.provider, sql`coalesce(${table.member_id}, '')`, sql`lower(${table.name})`)
      .where(sql`${table.status} = 'active'`),
    check('service_connections_status_check', sql`${table.status} IN ('active', 'expired', 'revoked')`),
    check('service_connections_verification_status_check', sql`${table.verification_status} IN ('healthy', 'unhealthy', 'unknown')`),
  ],
);

// ─── Service Configurations (shared vs per-member mode) ─────────────

export const serviceConfigurations = pgTable(
  'service_configurations',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    service_id: text('service_id')
      .notNull()
      .references(() => services.id),
    provider: text('provider').notNull(),
    mode: text('mode').notNull(), // shared | per_member
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex('svcfg_operator_provider_idx').on(table.operator_id, table.provider)],
);

// ─── Agent Service Grants ────────────────────────────────────────────

export const agentServiceGrants = pgTable(
  'agent_service_grants',
  {
    id: text('id').primaryKey(),
    agent_id: text('agent_id')
      .notNull()
      .references(() => agents.id),
    service_connection_id: text('service_connection_id')
      .notNull()
      .references(() => serviceConnections.id),
    scopes: jsonb('scopes').notNull().$type<string[]>(),
    // Parameter-level scope constraints. Baseline ceiling the operator
    // set when granting. Issued passports may tighten (never loosen).
    // NULL = service-level scope only (legacy path).
    constraints: jsonb('constraints').$type<import('../../schemas/passport.js').Constraint[]>(),
    // Data-flow baseline — the CEILING of cross-service movements this agent
    // may declare on this service. Names the services whose content may flow
    // INTO it (enforced by the scope wall). Issued passports may declare a
    // SUBSET of this (never a flow it lacks) — the mirror of `constraints`,
    // which is a floor. NULL = no baseline ceiling (declare per-passport).
    allow_data_from: jsonb('allow_data_from').$type<string[]>(),
    // The named intents the grant was made with, kept verbatim. `constraints`
    // holds their EXPANSION and is what enforcement reads; this is the
    // human-readable record of the same decision. Reconstructing names from
    // constraints was rejected: a reverse match over the catalog can mislabel
    // hand-written constraints, and this surface must never guess.
    // NULL = granted without named intents (or before this column existed).
    intent_refs:
      jsonb('intent_refs').$type<Array<{ name: string; params: Record<string, unknown> }>>(),
    granted_at: timestamp('granted_at', { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    index('grant_agent_idx').on(table.agent_id),
    uniqueIndex('grant_agent_scon_idx').on(table.agent_id, table.service_connection_id),
  ],
);
