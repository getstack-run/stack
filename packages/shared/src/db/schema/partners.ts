// Partner grants.

import { pgTable, text, timestamp, jsonb, boolean, index, check } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { operators } from './operators.js';

// ─── Partner grants ("Connect with STACK") ─────────────────
//
// One row = one live (partner, user) edge: the partner holds an opaque
// sk_grant_* token (sha256 at rest) that authenticates it AS ACTING FOR
// the user's operator, bounded three ways: scopes (route map), allowed
// providers, and resource provenance (created_via_grant_id columns).
//
// Ownership semantics: the user_operator is a NORMAL user-owned operator
// (real email, parent_operator_id NULL). This supersedes the earlier
// child-tenant ownership; the partner manages
// by default, the user owns underneath, and "branching out" is just
// logging in (operators.claimed_at).
//
// State machine: pending_consent → active → revoked, plus terminal
// declined and expired (consent window lapsed). ANY other/unknown state
// fails closed at resolveGrantByToken.
//
// Two partial-unique invariants live in the SQL migration (0024), not
// here (repo precedent: 0021 partner indexes):
//   - one live grant per (partner_operator_id, user_operator_id)
//   - live idempotency on (partner_operator_id, external_customer_id)
export const partnerGrants = pgTable(
  'partner_grants',
  {
    id: text('id').primaryKey(), // pgr_*
    partner_operator_id: text('partner_operator_id')
      .notNull()
      .references(() => operators.id),
    user_operator_id: text('user_operator_id')
      .notNull()
      .references(() => operators.id),
    // Partner's own identifier for this customer (e.g. their inbox id) —
    // same mapping role as operators.external_customer_id plays for tenants.
    external_customer_id: text('external_customer_id'),
    token_hash: text('token_hash').notNull().unique(), // sha256(sk_grant_*)
    scopes: jsonb('scopes').notNull().$type<string[]>(), // ⊆ PARTNER_GRANT_SCOPES, fixed at creation
    allowed_providers: jsonb('allowed_providers').notNull().$type<string[]>(), // ⊆ operators.partner_providers at creation
    status: text('status').notNull().default('pending_consent'), // pending_consent | active | revoked | declined | expired
    // true = the create-on-email branch (account did not exist; Express
    // model, no consent, Art.-14 notice email is a HARD delivery gate).
    // false = existing account; explicit consent required before active.
    user_provisioned: boolean('user_provisioned').notNull(),
    consent_token_hash: text('consent_token_hash'), // sha256, single-use (nulled on decision)
    consent_expires_at: timestamp('consent_expires_at', { withTimezone: true }),
    consented_at: timestamp('consented_at', { withTimezone: true }),
    optout_token_hash: text('optout_token_hash'), // sha256; valid only while operator unclaimed
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    revoked_by: text('revoked_by'), // user | partner | staff
    revoke_reason: text('revoke_reason'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    last_used_at: timestamp('last_used_at', { withTimezone: true }),
  },
  (table) => [
    index('partner_grants_partner_idx').on(table.partner_operator_id),
    index('partner_grants_user_idx').on(table.user_operator_id),
    check('partner_grants_status_check', sql`${table.status} IN ('pending_consent', 'active', 'declined', 'expired', 'revoked')`),
  ],
);
