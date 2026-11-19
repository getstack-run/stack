// Identity verification, identity claims and workload-identity trust.

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
import { operators } from './operators.js';
import { services } from './services.js';

// ─── Identity Verification Sessions ─────────────────────────────────

export const identityVerificationSessions = pgTable(
  'identity_verification_sessions',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    provider_key: text('provider_key').notNull(),
    session_ref: text('session_ref').notNull(), // provider's session/order reference
    // pending | completed | failed | expired (a session nobody finished by expires_at; the decision-ends sweep marks it)
    status: text('status').notNull().default('pending'),
    requested_claims: jsonb('requested_claims').notNull().$type<string[]>(),
    provider_data: text('provider_data'), // KMS-encrypted provider-specific state
    // Who started the session: the account owner, a member, or an authority
    // ceremony for another principal. Only an owner session verifies the
    // operator. Null on sessions started before the column existed.
    initiated_by: text('initiated_by'),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    completed_at: timestamp('completed_at', { withTimezone: true }),
  },
  (table) => [
    index('ivsess_operator_idx').on(table.operator_id),
    index('ivsess_session_ref_idx').on(table.session_ref),
    index('ivsess_status_idx').on(table.status),
    index('ivsess_pending_expires_idx').on(table.expires_at).where(sql`${table.status} = 'pending'`),
    check('identity_verification_sessions_status_check', sql`${table.status} IN ('pending', 'completed', 'failed', 'expired')`),
    check(
      'identity_verification_sessions_initiated_by_check',
      sql`${table.initiated_by} IS NULL OR ${table.initiated_by} IN ('owner', 'member', 'authority')`,
    ),
  ],
);

// ─── Identity Providers (pluggable registry) ────────────────────────

export const identityProviders = pgTable('identity_providers', {
  id: text('id').primaryKey(),
  name: text('name').notNull(), // e.g. "Stripe Identity"
  provider_key: text('provider_key').notNull().unique(), // e.g. "stripe_identity"
  supported_layers: jsonb('supported_layers').notNull().$type<string[]>(), // ["humanity", "identity", "delegation"]
  claim_types: jsonb('claim_types').notNull().$type<string[]>(), // e.g. ["verified_human", "verified_identity"]
  assurance_level: text('assurance_level').notNull(), // low | substantial | high
  verification_endpoint: text('verification_endpoint'),
  jwks_uri: text('jwks_uri'),
  active: boolean('active').notNull().default(true),
  created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// ─── Operator Identity Claims ────────────────────────────────────────

export const identityClaims = pgTable(
  'identity_claims',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    provider_id: text('provider_id')
      .notNull()
      .references(() => identityProviders.id),
    provider_key: text('provider_key').notNull(),
    layer: text('layer').notNull(), // humanity | identity | delegation
    claim_type: text('claim_type').notNull(),
    assurance_level: text('assurance_level').notNull(), // low | substantial | high
    verified_at: timestamp('verified_at', { withTimezone: true }).notNull(),
    expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
    assertion_encrypted: text('assertion_encrypted').notNull(), // KMS-encrypted provider assertion
    payload_encrypted: text('payload_encrypted'), // KMS-encrypted claim payload (PII for Layer 2)
    delegated_scopes: jsonb('delegated_scopes').$type<string[]>(), // Layer 3 only
    revoked_at: timestamp('revoked_at', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    // FK back-reference to the paired
    // identity_claim envelope in passport_claims (operator-scoped).
    // PII NEVER enters the envelope; the legacy row remains the
    // encrypted-PII source-of-truth.
    claim_id: text('claim_id'),
  },
  (table) => [
    uniqueIndex('identity_claims_id_operator_idx').on(table.id, table.operator_id),
    index('claim_operator_idx').on(table.operator_id),
    index('claim_provider_idx').on(table.provider_key),
    index('claim_layer_idx').on(table.layer),
    index('claim_expires_idx').on(table.expires_at),
    index('idc_claim_idx').on(table.claim_id),
  ],
);

// ─── SPIFFE Trust Domains ─────────────
// Per-operator config for SPIFFE/SPIRE issuers. One row per
// (operator_id, trust_domain). The `spiffe_id_mapping_policy_json`
// holds an exact-match map of SPIFFE ID → { agent_id }; regex/glob
// can be added without migration. `jwks_cached_*` is the last-known-good
// JWKS we serve via the SVID validator's fail-open path when upstream
// goes down — Redis is the primary cache, this is the durability tier.

export const spiffeTrustDomains = pgTable(
  'spiffe_trust_domains',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    trust_domain: text('trust_domain').notNull(),
    display_name: text('display_name'),
    jwks_uri: text('jwks_uri').notNull(),
    audience: text('audience'), // required JWT-SVID `aud`; NULL = accept any
    jwks_cache_ttl_seconds: integer('jwks_cache_ttl_seconds').notNull().default(300),
    jwks_cached_jwks_json: jsonb('jwks_cached_jwks_json').$type<unknown>(),
    jwks_cached_at: timestamp('jwks_cached_at', { withTimezone: true }),
    spiffe_id_mapping_policy_json: jsonb('spiffe_id_mapping_policy_json')
      .notNull()
      .$type<Record<string, { agent_id: string }>>(),
    rate_limit_per_second: integer('rate_limit_per_second'), // operator override; NULL = default
    active: boolean('active').notNull().default(true),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('spiffe_td_op_trust_unique').on(table.operator_id, table.trust_domain),
    index('spiffe_td_operator_idx').on(table.operator_id),
    index('spiffe_td_active_idx').on(table.active),
  ],
);

// ─── OIDC IdP Configs (chunk E of Signed Primitive) ────────
// Per-operator OIDC identity-provider configuration. v1 enforces one
// IdP per operator (unique index). Client secret KMS-enveloped at rest
// under EncryptionContext={operator_id, provider=oidc}.

export const oidcIdpConfigs = pgTable(
  'oidc_idp_configs',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    display_name: text('display_name'),
    issuer_uri: text('issuer_uri').notNull(),
    client_id: text('client_id').notNull(),
    client_secret_encrypted: text('client_secret_encrypted').notNull(),
    audience: text('audience'),
    redirect_uri: text('redirect_uri').notNull(),
    scopes_json: jsonb('scopes_json')
      .notNull()
      .$type<string[]>()
      .default(['openid', 'email', 'profile']),
    claim_mapping_policy_json: jsonb('claim_mapping_policy_json').$type<Record<string, unknown>>(),
    discovery_cached_json: jsonb('discovery_cached_json').$type<Record<string, unknown>>(),
    jwks_cached_jwks_json: jsonb('jwks_cached_jwks_json').$type<unknown>(),
    jwks_cached_at: timestamp('jwks_cached_at', { withTimezone: true }),
    jwks_cache_ttl_seconds: integer('jwks_cache_ttl_seconds').notNull().default(300),
    /** Origins a verification handoff may return the browser to. NULL or
     *  empty = the dashboard origin only. Without this the caller-supplied
     *  return_url made the public callback an open redirect. */
    allowed_return_origins: jsonb('allowed_return_origins').$type<string[]>(),
    /** SSO login: the slug in /login/sso/<slug>. Names the operator BEFORE
     *  any token is exchanged, so nobody can walk into an account by
     *  asserting its email domain. NULL = SSO login never set up. */
    sso_slug: text('sso_slug'),
    /** Off until the admin has run a test login. A typo in issuer or secret
     *  with this already on locks an org out of its own account. */
    sso_login_enabled: boolean('sso_login_enabled').notNull().default(false),
    /** Role given to a member auto-provisioned on first SSO login. */
    default_member_role: text('default_member_role').notNull().default('standard'),
    active: boolean('active').notNull().default(true),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('oidc_idp_op_unique').on(table.operator_id),
    index('oidc_idp_issuer_idx').on(table.issuer_uri),
    index('oidc_idp_active_idx').on(table.active),
    // Global: the slug resolves to exactly one operator, or /login/sso/<slug>
    // is ambiguous about whose account it signs you into.
    uniqueIndex('oidc_idp_sso_slug_unique').on(table.sso_slug),
  ],
);

// ─── SSO verified domains ──────────────────────────────────
// An e-mail domain an account has proved it controls with a DNS TXT record
// (spec/sso-login/SPEC.md section 9.5). An address at a verified domain counts as
// verified for the account's single sign-on when the provider's ID token does not say.
// A domain is VERIFIED for at most one account at a time (the partial unique index);
// claims that were never proved can be held by any number of accounts, and grant nothing.
//
//   last_confirmed_at  the last time the record was SEEN. A verified domain counts at
//                      sign-in only while this is recent (SSO_DOMAIN_TRUST_SECONDS); past
//                      that the sign-in looks the record up again.
//   missing_since      when a lookup first found the record gone (an answer, not an
//                      error); a domain missing for SSO_DOMAIN_LAPSE_SECONDS lapses.
//   token              published in DNS, so it names the claim and is not a secret.

export const ssoVerifiedDomains = pgTable(
  'sso_verified_domains',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    domain: text('domain').notNull(),
    token: text('token').notNull(),
    status: text('status').notNull().default('pending'),
    verified_at: timestamp('verified_at', { withTimezone: true }),
    last_checked_at: timestamp('last_checked_at', { withTimezone: true }),
    last_confirmed_at: timestamp('last_confirmed_at', { withTimezone: true }),
    last_check: text('last_check'),
    missing_since: timestamp('missing_since', { withTimezone: true }),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('sso_domain_operator_domain_unique').on(table.operator_id, table.domain),
    uniqueIndex('sso_domain_verified_unique').on(table.domain).where(sql`${table.status} = 'verified'`),
    index('sso_domain_recheck_idx').on(table.status, table.last_checked_at),
    check('sso_domain_status_check', sql`${table.status} in ('pending', 'verified', 'lapsed')`),
  ],
);

// ─── WIMSE Issuers (workload identity of Signed Primitive) ─
// Per-operator config for WIMSE Workload Identity Token issuers. One
// row per (operator_id, issuer_uri). Mirrors spiffe_trust_domains in
// shape but discriminates the workload by issuer URI + workload ID
// (the WIT `sub` claim) rather than a SPIFFE trust domain.

export const wimseIssuers = pgTable(
  'wimse_issuers',
  {
    id: text('id').primaryKey(),
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id, { onDelete: 'cascade' }),
    issuer_uri: text('issuer_uri').notNull(), // expected WIT `iss`
    display_name: text('display_name'),
    jwks_uri: text('jwks_uri').notNull(),
    audience: text('audience'), // required WIT `aud`; NULL = accept any
    jwks_cache_ttl_seconds: integer('jwks_cache_ttl_seconds').notNull().default(300),
    jwks_cached_jwks_json: jsonb('jwks_cached_jwks_json').$type<unknown>(),
    jwks_cached_at: timestamp('jwks_cached_at', { withTimezone: true }),
    workload_id_mapping_policy_json: jsonb('workload_id_mapping_policy_json')
      .notNull()
      .$type<Record<string, { agent_id: string }>>(),
    rate_limit_per_second: integer('rate_limit_per_second'),
    active: boolean('active').notNull().default(true),
    created_at: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updated_at: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex('wimse_iss_op_issuer_unique').on(table.operator_id, table.issuer_uri),
    index('wimse_iss_operator_idx').on(table.operator_id),
    index('wimse_iss_active_idx').on(table.active),
  ],
);

// ─── Service Identity Requirements ───────────────────────────────────

export const serviceIdentityRequirements = pgTable(
  'service_identity_requirements',
  {
    id: text('id').primaryKey(),
    // Per-operator policy. This row is the requiring OPERATOR's
    // own identity gate on a service they connect — NOT global-catalog
    // state. Enforcement (passport-service.verify) filters by BOTH
    // operator_id and service_id, so one tenant's requirement never
    // gates another tenant's passport. Migration 0022 added this column;
    // pre-0022 rows were truncated (no recorded author, only ever
    // writable through the pre-fix unscoped path).
    operator_id: text('operator_id')
      .notNull()
      .references(() => operators.id),
    service_id: text('service_id')
      .notNull()
      .references(() => services.id),
    layer: text('layer').notNull(), // humanity | identity | delegation
    requires_claim: text('requires_claim').notNull(), // e.g. "verified_human"
    minimum_assurance: text('minimum_assurance').notNull(), // low | substantial | high
    accepted_providers: jsonb('accepted_providers').notNull().$type<string[]>(),
    required_scopes: jsonb('required_scopes').$type<string[]>(), // Layer 3 — which delegated scopes are needed
    requires_pii: boolean('requires_pii').notNull().default(false), // must be true for Layer 2
    lawful_basis: text('lawful_basis'), // GDPR lawful basis when requires_pii = true
  },
  (table) => [
    // Stable upsert key: setting a requirement for the same
    // (operator, service, layer, claim) updates in place instead of
    // accumulating rows (the pre-fix always-fresh-id conflict target
    // never matched, so every POST inserted).
    uniqueIndex('svc_req_op_service_layer_claim_unique').on(
      table.operator_id,
      table.service_id,
      table.layer,
      table.requires_claim,
    ),
    // Enforcement hot-path lookup: findRequirementsByService(op, svc).
    index('svc_req_op_service_idx').on(table.operator_id, table.service_id),
    index('svc_req_layer_idx').on(table.layer),
  ],
);
