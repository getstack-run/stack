// Operators, their team and the account lifecycle jobs.

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
import type { LimitOverrides } from '../../schemas/partner-limits.js';

// ─── Operators ───────────────────────────────────────────────────────

export const operators = pgTable('operators', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  // Rotated on an owner mailbox transfer; members have their own identity.
  owner_session_revision: text('owner_session_revision').notNull().default('0'),
  // CHECK-constrained to the five tiers as of migration 0029. It was untyped
  // text with no constraint for the first two years, which meant an
  // unrecognised value failed differently in every consumer instead of at the
  // write. Adding a tier = migration + OperatorTier enum + this comment.
  tier: text('tier').notNull().default('free'), // free | developer | pro | business | enterprise
  is_admin: boolean('is_admin').notNull().default(false),
  // (auth refactor): platform-staff authority — gates routes under
  // /v1/admin/* via the requirePlatformStaff middleware. Distinct from
  // is_admin (operator-account-admin, scoped to one operator). The
  // the platform owner + op_stack_system are platform-staff; every other
  // operator is operator-scoped only. See migration 0028.
  is_platform_staff: boolean('is_platform_staff').notNull().default(false),
  // partner-tenancy. is_partner=true operators can create +
  // manage isolated child operators on behalf of their customers. The
  // partner has its own API key + audit chain; each child has its own
  // KMS-scoped audit chain, signing key, isolation. Per-child reads
  // require the partner own the child (parent_operator_id = partner.id).
  // Audit content of a child is NEVER visible to the partner — only
  // aggregate counters.
  is_partner: boolean('is_partner').notNull().default(false),
  parent_operator_id: text('parent_operator_id'), // FK to operators(id) — self-referential, set when this is a child of a partner
  // external_customer_id lets the partner stamp their own
  // identifier on the child (e.g. their inbox id or customer id)
  // so they can map STACK tenant → their own customer record without
  // calling STACK. Indexed for partner-side lookup.
  external_customer_id: text('external_customer_id'),
  // "Connect with STACK" account/partner model.
  // partner_providers: staff-set list of providers a partner's grants may
  //   bind to (only meaningful on is_partner=true rows). A grant's
  //   allowed_providers defaults to this list; the proxy/connect/webhook/
  //   passport paths refuse targets outside it.
  // provisioned_via_grant_id: set when this operator was created by a
  //   partner's connect(email) call (the create-on-email branch). The
  //   account is USER-OWNED (real email, parent_operator_id stays NULL —
  //   the semantic break child tenants); this column is
  //   provenance only.
  // claimed_at: first direct login by the human (magic link). Stamped by
  //   the dashboard auth flow; NULL = partner-provisioned and not yet
  //   claimed. Opt-out deletion is only allowed while unclaimed.
  partner_providers: jsonb('partner_providers').$type<string[]>(),
  provisioned_via_grant_id: text('provisioned_via_grant_id'),
  claimed_at: timestamp('claimed_at', { withTimezone: true }),
  api_key_hash: text('api_key_hash').notNull().unique(),
  stripe_customer_id: text('stripe_customer_id').unique(),
  stripe_subscription_id: text('stripe_subscription_id'),
  // Seats bought on top of the tier allocation, synced from the Stripe
  // subscription item quantity. member-service reads
  // the tier's team members + purchased_seats as the cap.
  purchased_seats: integer('purchased_seats').notNull().default(0),
  // Negotiated retention in days, overriding the tier's retention window.
  // Null = use the tier default.
  audit_retention_days_override: integer('audit_retention_days_override'),
  // Per-deal limit overrides (LimitOverrides in @stack/shared), staff-set on a
  // billing account. NULL = tier defaults. Tenants never carry overrides
  // (CHECK in migration 0092): an account's plan is its own, and a partner's hard cap pools its accounts.
  limit_overrides: jsonb('limit_overrides').$type<LimitOverrides>(),
  billing_period_start: timestamp('billing_period_start', { withTimezone: true }),
  billing_period_end: timestamp('billing_period_end', { withTimezone: true }),
  identity_claim_ttl: text('identity_claim_ttl').notNull().default('1y'), // 30d | 90d | 180d | 1y
  identity_claim_inheritance: text('identity_claim_inheritance').notNull().default('auto'), // auto | opt_in
  identity_auto_revoke: boolean('identity_auto_revoke').notNull().default(false),
  // Operator lifecycle: status drives auth deny. soft_deleted retains the row after an admin action. deleted is reserved
  // for the durable account-erasure saga.
  status: text('status').notNull().default('active'), // active | suspended | soft_deleted | deleted
  comped: boolean('comped').notNull().default(false),
  suspended_at: timestamp('suspended_at', { withTimezone: true }),
  suspended_reason: text('suspended_reason'),
  suspended_by: text('suspended_by'),
  deleted_at: timestamp('deleted_at', { withTimezone: true }),
  // Set when the owner passes identity verification. Gates opening agent
  // accounts.
  identity_verified_at: timestamp('identity_verified_at', { withTimezone: true }),
  // Set when a top-up is disputed or a refund leaves a debt: every agent
  // account of the operator is frozen until it is cleared.
  spend_frozen_at: timestamp('spend_frozen_at', { withTimezone: true }),
  spend_frozen_reason: text('spend_frozen_reason'),
  // The platform subscription that agent accounts need (a Stripe card
  // subscription with a trial), written only from Stripe's subscription
  // events. the platform subscription statuses in @stack/shared; trialing, active
  // and past_due keep paid features on. The trial is given once.
  platform_status: text('platform_status').notNull().default('none'),
  platform_subscription_id: text('platform_subscription_id'),
  platform_trial_started_at: timestamp('platform_trial_started_at', { withTimezone: true }),
  // The day the running trial ends, as Stripe states it (`trial_end`); null when none runs (migration 0201).
  platform_trial_ends_at: timestamp('platform_trial_ends_at', { withTimezone: true }),
  // STACK's hosted controls (the classifier and withholding on agent-account
  // traffic, per-agent budgets), a second card subscription: off | trialing |
  // active | lapsed, written from the controls subscription's Stripe events.
  // The trial is given the first time controls are switched on. Read only
  // through the billing account's controls decision.
  controls_status: text('controls_status').notNull().default('off'),
  controls_subscription_id: text('controls_subscription_id'),
  controls_trial_started_at: timestamp('controls_trial_started_at', { withTimezone: true }),
  controls_trial_ends_at: timestamp('controls_trial_ends_at', { withTimezone: true }),
  // deferral 1 (Signed Primitive epic): Customer-Managed Encryption
  // Keys. ARN of the customer's AWS KMS CMK; status drives the encryption
  // resolver in KmsService. See migration 0034 + the customer-managed keys design.
  // op_stack_system carve-out: cmek_key_arn must always remain NULL there.
  cmek_key_arn: text('cmek_key_arn'),
  cmek_status: text('cmek_status').notNull().default('none'), // none | migrating | active | revoking | revoked
  cmek_activated_at: timestamp('cmek_activated_at', { withTimezone: true }),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
},
  (table) => [
    check('operators_status_check', sql`${table.status} IN ('active', 'suspended', 'soft_deleted', 'deleted')`),
    check('operators_cmek_status_check', sql`${table.cmek_status} IN ('none', 'migrating', 'active', 'revoking', 'revoked')`),
    check(
      'operators_platform_status_check',
      sql`${table.platform_status} IN ('none', 'incomplete', 'trialing', 'active', 'past_due', 'lapsed', 'canceled')`,
    ),
    check('operators_controls_status_check', sql`${table.controls_status} IN ('off', 'trialing', 'active', 'lapsed')`),
    uniqueIndex('operators_platform_subscription_unique')
      .on(table.platform_subscription_id)
      .where(sql`${table.platform_subscription_id} IS NOT NULL`),
    uniqueIndex('operators_controls_subscription_unique')
      .on(table.controls_subscription_id)
      .where(sql`${table.controls_subscription_id} IS NOT NULL`),
  ],
);

// Dashboard magic-link challenges. The dashboard remains the only writer.
// The shared definition lets account erasure use the same typed table.
export const magicLinkTokens = pgTable(
  'magic_link_tokens',
  {
    id: text('id').primaryKey(),
    email: text('email').notNull(),
    token_hash: text('token_hash').notNull().unique(),
    code_hash: text('code_hash'),
    browser_binding_hash: text('browser_binding_hash'),
    intent: text('intent').notNull(),
    operator_id: text('operator_id').references(() => operators.id, { onDelete: 'cascade' }),
    // Set for a team-member sign-in challenge. The member row is checked
    // again at redemption so revocation or role changes take effect before
    // a session is minted.
    member_id: text('member_id'),
    used: boolean('used').notNull().default(false),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (table) => [
    index('mlt_email_idx').on(table.email),
    index('mlt_member_idx').on(table.member_id),
    index('mlt_expires_idx').on(table.expires_at),
  ],
);

// ─── CMEK Migration Progress ─────────────────────────────────────────
//
// Per-table per-operator progress rows for the CMEK migration worker.
// Powers the dashboard progress UI and serves as the resumption point
// when the worker restarts mid-migration. See migration 0034.

export const cmekMigrations = pgTable(
  'cmek_migrations',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    direction: text('direction').notNull(), // 'enable' | 'disable'
    table_name: text('table_name').notNull(),
    rows_total: integer('rows_total').notNull().default(0),
    rows_done: integer('rows_done').notNull().default(0),
    status: text('status').notNull().default('pending'), // pending | running | completed | failed
    error: text('error'),
    started_at: timestamp('started_at', { withTimezone: true }),
    completed_at: timestamp('completed_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('cmek_migrations_op_direction_table_idx').on(
      table.operator_id,
      table.direction,
      table.table_name,
    ),
    index('cmek_migrations_status_idx').on(table.status),
    check('cmek_migrations_status_check', sql`${table.status} IN ('pending', 'running', 'completed', 'failed')`),
  ],
);

// ─── Team Members ───────────────────────────────────────────────────

export const teamMembers = pgTable(
  'team_members',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    email: text('email').notNull(),
    name: text('name').notNull(),
    role: text('role').notNull().default('standard'), // readonly | standard | admin
    api_key_hash: text('api_key_hash').unique(),
    key_prefix: text('key_prefix'),
    allowed_connections: jsonb('allowed_connections').$type<string[]>(),
    // Invitation secrets are stored only as SHA-256 hashes. The raw token is
    // carried in the email URL fragment and submitted once by the browser.
    invite_token_hash: text('invite_token_hash'),
    invite_expires_at: timestamp('invite_expires_at', { withTimezone: true }),
    status: text('status').notNull().default('invited'), // invited | active | revoked
    last_used_at: timestamp('last_used_at', { withTimezone: true }),
    invited_at: timestamp('invited_at', { withTimezone: true }).notNull().defaultNow(),
    joined_at: timestamp('joined_at', { withTimezone: true }),
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    // Single sign-on binds a member to the identity provider's own name for the person (the
    // `iss` and `sub` of the ID token) on their first sign-in; after that the subject, not the
    // e-mail claim, is who signs in. Both are null until the person has signed in that way.
    sso_issuer: text('sso_issuer'),
    sso_subject: text('sso_subject'),
  },
  (table) => [
    index('member_operator_idx').on(table.operator_id),
    uniqueIndex('member_operator_email_idx').on(table.operator_id, table.email),
    uniqueIndex('member_invite_token_hash_idx').on(table.invite_token_hash),
    uniqueIndex('member_sso_subject_idx')
      .on(table.operator_id, table.sso_issuer, table.sso_subject)
      .where(sql`${table.sso_subject} IS NOT NULL`),
    check('team_members_status_check', sql`${table.status} IN ('invited', 'active', 'revoked')`),
    // A subject is always bound with its issuer, so the unique index above can never see a null issuer.
    check('team_members_sso_binding_check', sql`(${table.sso_issuer} IS NULL) = (${table.sso_subject} IS NULL)`),
  ],
);

// ─── Operator OAuth Apps (BYOOA) ────────────────────────────────────

export const operatorOauthApps = pgTable(
  'operator_oauth_apps',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    provider: text('provider').notNull(), // e.g. "slack", "github"
    client_id: text('client_id').notNull(),
    client_secret_encrypted: text('client_secret_encrypted').notNull(), // KMS envelope
    scopes: text('scopes'), // optional override scopes (comma-separated or space-separated)
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('oapp_operator_provider_idx').on(table.operator_id, table.provider),
    index('oapp_operator_idx').on(table.operator_id),
  ],
);

// ─── Connect links ──────────────────────────────────────────────────
//
// A chat assistant cannot be handed a provider credential, so it asks STACK
// for a connect link instead. The link opens a STACK page where the person
// either starts the provider's own consent screen or pastes a key. Only the
// sha256 of the link token is stored. A link is bound to the operator (and
// member) that created it, expires after a fixed time to live and yields
// at most one connection.
export const connectLinks = pgTable(
  'connect_links',
  {
    id: text('id').primaryKey(), // cnl_*
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    /** Member whose session created the link; only that member may use it. */
    member_id: text('member_id'),
    token_hash: text('token_hash').notNull(),
    service_id: text('service_id').notNull(),
    provider: text('provider').notNull(),
    /** oauth = the provider's consent screen; key = a STACK form for an API key. */
    method: text('method').notNull(),
    scopes: jsonb('scopes').$type<string[]>().notNull().default([]),
    /**
     * A link for a key the customer's own API takes (method key, provider custom_<name>): what the chat said when it
     * asked for the link. Not a secret. The hosts are the only place the credential entered on the page may later be
     * sent. Null for a catalog service.
     */
    custom_service: jsonb('custom_service').$type<{
      name: string;
      description?: string;
      allowed_hosts: string[];
      template?: string;
    } | null>(),
    /** What the connection this link makes is called (a `ConnectionName`); null names none. Not a secret. */
    connection_name: text('connection_name'),
    status: text('status').notNull().default('pending'), // pending | connected | expired
    connection_id: text('connection_id'),
    /** operator_key | member_session | oauth: the credential class that asked. */
    created_via: text('created_via').notNull(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    opened_at: timestamp('opened_at', { withTimezone: true }),
    completed_at: timestamp('completed_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('connect_links_token_hash_uidx').on(table.token_hash),
    index('connect_links_operator_status_idx').on(table.operator_id, table.status),
    check('connect_links_method_check', sql`${table.method} in ('oauth', 'key')`),
    check(
      'connect_links_status_check',
      sql`(${table.status} in ('pending', 'expired') and ${table.connection_id} is null)
        or (${table.status} = 'connected' and ${table.connection_id} is not null and ${table.completed_at} is not null)`,
    ),
    check('connect_links_token_hash_check', sql`${table.token_hash} ~ '^[0-9a-f]{64}$'`),
  ],
);

/** Durable saga state for GDPR account erasure. */
export const operatorErasureJobs = pgTable(
  'operator_erasure_jobs',
  {
    // Migration 0045 installs this FK as NOT VALID. The operator row remains
    // until final erasure, then cascades the completed job automatically.
    operator_id: text('operator_id')
      .primaryKey()
      .references(() => operators.id, { onDelete: 'cascade' }),
    status: text('status').notNull().default('pending'),
    claim_id: text('claim_id'),
    attempt_count: integer('attempt_count').notNull().default(0),
    next_attempt_at: timestamp('next_attempt_at', { withTimezone: true }).notNull().defaultNow(),
    last_error_code: text('last_error_code'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('operator_erasure_jobs_due_idx').on(table.next_attempt_at),
    check('operator_erasure_jobs_status_check', sql`${table.status} in ('pending', 'processing')`),
    check(
      'operator_erasure_jobs_error_code_check',
      sql`${table.last_error_code} is null or ${table.last_error_code} in ('archive_store_not_durable', 'archive_list_failed', 'archive_delete_failed', 'archive_verify_failed', 'database_delete_failed', 'memory_erase_failed')`,
    ),
    check('operator_erasure_jobs_attempt_count_check', sql`${table.attempt_count} >= 0`),
  ],
);

/**
 * The accounts that were erased: the operator's id and the time, written in the transaction that deletes the
 * operator, and never changed or removed (a trigger refuses). A restore from a snapshot older than an erasure brings
 * the account back; this list is what says it must not be there, so `OperatorErasureService.reapplyErasures` can
 * delete it again. No foreign key: the operator is gone by then. The id is all it holds.
 */
export const erasedOperators = pgTable('erased_operators', {
  operator_id: text('operator_id').primaryKey(),
  erased_at: timestamp('erased_at', { withTimezone: true }).notNull().defaultNow(),
});

export const operatorEmailChanges = pgTable(
  'operator_email_changes',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    new_email: text('new_email').notNull(),
    /** The address at request time — the trail says what it moved FROM. */
    old_email: text('old_email').notNull(),
    confirm_token_hash: text('confirm_token_hash').notNull(),
    cancel_token_hash: text('cancel_token_hash').notNull(),
    requested_by_member_id: text('requested_by_member_id'),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    delivery_ready_at: timestamp('delivery_ready_at', { withTimezone: true }),
    confirmed_at: timestamp('confirmed_at', { withTimezone: true }),
    cancelled_at: timestamp('cancelled_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('operator_email_changes_operator_idx').on(table.operator_id),
    uniqueIndex('operator_email_changes_confirm_idx').on(table.confirm_token_hash),
    uniqueIndex('operator_email_changes_cancel_idx').on(table.cancel_token_hash),
  ],
);

/** Durable retry state for the old-address completion notice. */
export const operatorEmailDeliveryJobs = pgTable(
  'operator_email_delivery_jobs',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    email_change_id: text('email_change_id')
      .notNull()
      .references(() => operatorEmailChanges.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull().default('completion_notice'),
    status: text('status').notNull().default('pending'),
    claim_id: text('claim_id'),
    attempt_count: integer('attempt_count').notNull().default(0),
    next_attempt_at: timestamp('next_attempt_at', { withTimezone: true }).notNull().defaultNow(),
    last_error_code: text('last_error_code'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('operator_email_delivery_jobs_change_kind_idx').on(
      table.email_change_id,
      table.kind,
    ),
    index('operator_email_delivery_jobs_due_idx').on(table.next_attempt_at),
    check('operator_email_delivery_jobs_kind_check', sql`${table.kind} = 'completion_notice'`),
    check(
      'operator_email_delivery_jobs_status_check',
      sql`${table.status} in ('pending', 'processing')`,
    ),
    check(
      'operator_email_delivery_jobs_error_code_check',
      sql`${table.last_error_code} is null or ${table.last_error_code} = 'delivery_failed'`,
    ),
    check('operator_email_delivery_jobs_attempt_count_check', sql`${table.attempt_count} >= 0`),
  ],
);
