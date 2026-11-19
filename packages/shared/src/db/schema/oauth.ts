// OAuth clients, codes and tokens issued by STACK.

import { pgTable, text, timestamp, integer, jsonb, index, check } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators, teamMembers } from './operators.js';

// ─── OAuth 2.1 ───────────────────────
//
// Four tables backing the OAuth 2.1 server in apps/api/src/routes/oauth.ts.
// Tokens are stored by sha256 hash only (never raw). Refresh tokens implement
// rotation-on-use with reuse-detection: any presentation of an already-replaced
// refresh hash revokes the entire token_family_id (RFC 6819 §5.2.2.3 / OAuth 2.1
// §6.1). Detail: the agent auth design § Implementation ADR.

export const oauthClients = pgTable(
  'oauth_clients',
  {
    id: text('id').primaryKey(), // client_id
    client_secret_hash: text('client_secret_hash'), // sha256(secret); NULL for public PKCE clients
    client_type: text('client_type').notNull(), // 'public' | 'confidential'
    client_name: text('client_name').notNull(),
    redirect_uris: jsonb('redirect_uris').notNull().$type<string[]>(),
    grant_types: jsonb('grant_types').notNull().$type<string[]>(),
    response_types: jsonb('response_types').notNull().$type<string[]>(),
    token_endpoint_auth_method: text('token_endpoint_auth_method').notNull(), // 'none' | 'client_secret_post' | 'client_secret_basic'
    scope: text('scope'), // space-separated default
    software_id: text('software_id'),
    software_version: text('software_version'),
    metadata_url: text('metadata_url'), // for Client ID Metadata Document clients
    operator_id: text('operator_id').references(() => operators.id), // NULL for self-registered DCR clients
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index('oclient_operator_idx').on(table.operator_id)],
);

export const oauthAuthorizationCodes = pgTable(
  'oauth_authorization_codes',
  {
    code_hash: text('code_hash').primaryKey(), // sha256(code)
    client_id: text('client_id')
      .notNull()
      .references(() => oauthClients.id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    member_id: text('member_id').references(() => teamMembers.id),
    redirect_uri: text('redirect_uri').notNull(),
    scope: text('scope').notNull(),
    resource: text('resource').notNull(), // 'stack:api' | 'stack:mcp' (RFC 8707)
    code_challenge: text('code_challenge').notNull(),
    code_challenge_method: text('code_challenge_method').notNull().default('S256'),
    nonce: text('nonce'),
    issued_at: timestamp('issued_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    consumed_at: timestamp('consumed_at', { withTimezone: true }),
  },
  (table) => [index('oac_client_expires_idx').on(table.client_id, table.expires_at)],
);

export const oauthRefreshTokens = pgTable(
  'oauth_refresh_tokens',
  {
    token_hash: text('token_hash').primaryKey(), // sha256(refresh_token)
    token_family_id: text('token_family_id').notNull(), // groups all refreshes from one /authorize grant
    client_id: text('client_id')
      .notNull()
      .references(() => oauthClients.id),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    member_id: text('member_id').references(() => teamMembers.id),
    scope: text('scope').notNull(),
    resource: text('resource').notNull(),
    issued_at: timestamp('issued_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    replaced_by_hash: text('replaced_by_hash'), // set when this token has been rotated
    // KMS-encrypted raw successor. This exists only so a retry of the same
    // single-use token can receive the exact successor during the bounded
    // rotation window. Plaintext refresh tokens never enter PostgreSQL.
    replacement_token_encrypted: text('replacement_token_encrypted'),
    replacement_retry_expires_at: timestamp('replacement_retry_expires_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_reason: text('revoked_reason'), // 'replaced' | 'reuse_detected' | 'logout' | 'admin' | 'operator_revoked'
    last_used_at: timestamp('last_used_at', { withTimezone: true }),
    last_used_ip: text('last_used_ip'),
    last_used_ua: text('last_used_ua'),
  },
  (table) => [
    index('ort_operator_expires_idx').on(table.operator_id, table.expires_at),
    index('ort_family_idx').on(table.token_family_id),
    index('ort_expires_idx').on(table.expires_at),
    index('ort_replaced_by_idx')
      .on(table.replaced_by_hash)
      .where(sql`${table.replaced_by_hash} is not null`),
    index('ort_retry_expiry_idx')
      .on(table.replacement_retry_expires_at)
      .where(
        sql`${table.replacement_token_encrypted} is not null and ${table.replacement_retry_expires_at} is not null`,
      ),
  ],
);

export const oauthDeviceCodes = pgTable(
  'oauth_device_codes',
  {
    device_code_hash: text('device_code_hash').primaryKey(), // sha256(device_code)
    user_code: text('user_code').notNull().unique(), // 8 chars, A-Z2-9 (no I/O/0/1), shown to human
    client_id: text('client_id')
      .notNull()
      .references(() => oauthClients.id),
    scope: text('scope').notNull(),
    resource: text('resource').notNull(),
    status: text('status').notNull().default('pending'), // 'pending' | 'approved' | 'denied' | 'expired'
    operator_id: text('operator_id').references(() => operators.id), // set on approval
    member_id: text('member_id').references(() => teamMembers.id),
    issued_at: timestamp('issued_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    interval_seconds: integer('interval_seconds').notNull().default(5),
    last_polled_at: timestamp('last_polled_at', { withTimezone: true }),
    approved_at: timestamp('approved_at', { withTimezone: true }),
    denied_at: timestamp('denied_at', { withTimezone: true }),
  },
  (table) => [
    index('odc_expires_idx').on(table.expires_at),
    check('oauth_device_codes_status_check', sql`${table.status} IN ('pending', 'approved', 'denied', 'expired')`),
  ],
);
