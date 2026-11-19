import { deployment, readStaging } from '@stack/shared';

/**
 * The engine's configuration, read once at boot. A deployment that is more than
 * the engine (STACK's own) reads its variables in its own module, which builds
 * on this one; nothing here names a hosted vendor, and no default here names a
 * host of STACK's: an address defaults to where this deployment says it is
 * (`deployment()`), so an install never points at somebody else's server.
 */

function optional(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function enabled(value: string): boolean {
  return value === 'true' || value === '1';
}

/** The host this deployment's own site is served from, for the sender addresses of its mail. */
function siteHost(): string {
  return new URL(deployment().siteUrl).host;
}

export function assertOAuthSecurityConfiguration(config: {
  NODE_ENV: string;
  OAUTH_ENABLED: string;
  OAUTH_SCOPE_ENFORCEMENT: string;
}): void {
  if (
    config.NODE_ENV === 'production' &&
    enabled(config.OAUTH_ENABLED) &&
    !enabled(config.OAUTH_SCOPE_ENFORCEMENT)
  ) {
    throw new Error(
      'OAuth scope enforcement must be enabled whenever OAuth is enabled in production.',
    );
  }
}

/**
 * A staging deployment refuses to boot without an allow-list: with none, sign-in
 * would either be open to everyone or to nobody, and only the first is unsafe,
 * so neither is guessed.
 */
export function assertStagingConfiguration(config: {
  STACK_STAGING: string;
  STAGING_SIGNIN_ALLOWLIST: string;
}): void {
  readStaging(config);
}

export const env = {
  NODE_ENV: optional('NODE_ENV', 'development'),
  PORT: parseInt(optional('API_PORT', '3000'), 10),

  // Database
  // No default: a connection string names a database and its credential, so an install sets its own
  // (createInfrastructure refuses to boot without it).
  DATABASE_URL: optional('DATABASE_URL', ''),

  // Redis
  REDIS_URL: optional('REDIS_URL', 'redis://localhost:6380'),

  // Public tenant selector for Microsoft provider OAuth. Client credentials
  // remain KMS-encrypted in operator_oauth_apps.
  OAUTH_MICROSOFT_TENANT: optional('OAUTH_MICROSOFT_TENANT', 'common'),

  // AWS KMS
  AWS_REGION: optional('AWS_REGION', ''),
  AWS_KMS_KEY_ID: optional('AWS_KMS_KEY_ID', ''),

  // Session signing key (shared with dashboard for JWT verification).
  // Two paths:
  //   SESSION_SIGNING_KEY_WRAPPED — preferred. Base64-encoded KMS-wrapped PEM,
  //     unwrapped once at boot via KmsService.decryptDirect with AAD
  //     {operator_id: STACK_SYSTEM_OPERATOR_ID, purpose: 'passport_signing'}.
  //     Produced by wrapping the signing key with the KMS key.
  //   SESSION_SIGNING_KEY — plaintext PEM fallback. Dev only. In prod, the
  //     boot path hard-fails when SESSION_SIGNING_KEY_WRAPPED is unset and
  //     this is the only path available.
  SESSION_SIGNING_KEY_WRAPPED: optional('SESSION_SIGNING_KEY_WRAPPED', ''),
  SESSION_SIGNING_KEY: optional('SESSION_SIGNING_KEY', ''),
  //   SESSION_SIGNING_KEY_FILE — path of a PEM file (a mounted secret). Accepted
  //     only when STACK_DEPLOYMENT=self_managed; hosted keeps its key KMS-wrapped.
  SESSION_SIGNING_KEY_FILE: optional('SESSION_SIGNING_KEY_FILE', ''),
  // Future deployment keys must use a new kid. The legacy default keeps
  // existing deployments compatible until their next deliberate rotation.
  DEPLOYMENT_SIGNING_KID: optional('DEPLOYMENT_SIGNING_KID', 'stack-passport-v1'),
  // Offline-pinned public keys for historical deployment-signed claims.
  // JSON JWKS only. Verification never follows a URL from claim data.
  TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON: optional(
    'TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON',
    '',
  ),

  // API-key pepper. Server-side secret HMAC'd into every stored
  // api_key_hash so a leaked keys/operators table (or PITR snapshot) yields
  // hashes useless without it. MUST be identical across api / dashboard /
  // worker or keys stop verifying across surfaces. Required in prod:
  // @stack/shared hashApiKey/verifyApiKeyHash hard-fail when NODE_ENV is
  // production and this is unset. Dev may leave it blank (plain SHA-256,
  // with a one-time warning). Generate with `openssl rand -hex 32`.
  API_KEY_PEPPER: optional('API_KEY_PEPPER', ''),

  // System operator: the operator whose vault holds the deployment's own
  // third-party credentials, which the deployment retrieves at boot. An inert
  // id on an install, which has none.
  STACK_SYSTEM_OPERATOR_ID: optional('STACK_SYSTEM_OPERATOR_ID', ''),

  // cold archive. Read-only from the API; the worker writes.
  // Days of audit kept in Postgres; everything older is read back from
  // object storage on demand.
  AUDIT_HOT_WINDOW_DAYS: optional('AUDIT_HOT_WINDOW_DAYS', ''),

  // Email. A provider key is the fallback when the vault holds none; the FROM
  // addresses are split by purpose so notifications@ does not drag down
  // auth-grade deliverability if it ever gets spam-reported, and default to this
  // deployment's own site.
  RESEND_API_KEY: optional('RESEND_API_KEY', ''),
  RESEND_FROM_EMAIL: optional('RESEND_FROM_EMAIL', `STACK <notifications@${siteHost()}>`),
  RESEND_FROM_AUTH: optional('RESEND_FROM_AUTH', `STACK <auth@${siteHost()}>`),
  RESEND_FROM_NOTIFICATIONS: optional('RESEND_FROM_NOTIFICATIONS', `STACK <notifications@${siteHost()}>`),
  RESEND_REPLY_TO: optional('RESEND_REPLY_TO', ''),
  RESEND_LIST_UNSUBSCRIBE: optional('RESEND_LIST_UNSUBSCRIBE', ''),

  // base URL returned in inbound_webhooks.webhook_url at create time. The
  // operator pastes this URL into the provider's webhook config. Defaults to the
  // API address this deployment says it has.
  STACK_API_BASE_URL: optional('STACK_API_BASE_URL', deployment().apiBaseUrl),

  // CORS
  ALLOWED_ORIGINS: optional('ALLOWED_ORIGINS', ''),

  // OAuth 2.1. Off-by-default so the new
  // routes can ship deployed but inactive while the surrounding pieces
  // (dashboard consent UI, CLI flow, SDK keychain) are wired in.
  // /oauth/* and /.well-known/oauth-* return 404 when this is unset.
  // Flip to 'true' once an end-to-end manual dance is verified in prod.
  OAUTH_ENABLED: optional('OAUTH_ENABLED', 'false'),
  // Retained as an explicit production assertion for deployment visibility.
  // Route enforcement itself is unconditional for every OAuth principal, so
  // this flag can never create a runtime bypass.
  OAUTH_SCOPE_ENFORCEMENT: optional('OAUTH_SCOPE_ENFORCEMENT', 'false'),

  // Dashboard URL for OAuth consent + device-approval handoff. A deployment that
  // names its site (self-managed, or a hosted one with STACK_SITE_URL) defaults to
  // its Console; otherwise the local dashboard.
  DASHBOARD_URL: optional(
    'DASHBOARD_URL',
    deployment().selfManaged || deployment().siteConfigured ? deployment().dashboardUrl : 'http://localhost:3100',
  ),

  // A staging deployment: test accounts only. 'true' limits sign-in, account
  // creation, invitations and outbound email to the exact addresses in
  // STAGING_SIGNIN_ALLOWLIST (comma separated, compared lower-cased) and marks
  // every answer noindex. Any value other than 'true' or 'false' refuses the
  // boot, and so does 'true' with an empty allow-list.
  STACK_STAGING: optional('STACK_STAGING', 'false'),
  STAGING_SIGNIN_ALLOWLIST: optional('STAGING_SIGNIN_ALLOWLIST', ''),

  // Shared with the MCP server only. The MCP server signs a chat confirmation
  // of a governance approval with it after the person accepts an MCP
  // elicitation; the API records the approval only when the signature
  // verifies. Unset (or shorter than 32 characters) disables chat approval:
  // the chat then gets the link to the approval page.
  // Read at request time by routes/governance.ts (chatApprovalKey).
  MCP_ELICITATION_ATTESTATION_KEY: optional('MCP_ELICITATION_ATTESTATION_KEY', ''),

  // gate the per-operator claim-signing cutover. When
  // 'false' (default), every claim signs under the deployment key
  // (kid stack-passport-v1) — preserves the pre-3.5 behaviour. When
  // 'true', non-system operators sign claims under their own
  // per-operator kid (operator_id:claim:vN). Reversibility: flipping
  // back to 'false' makes new claims sign under the deployment key
  // again; historical operator-kid claims keep verifying because the
  // operator-JWKS endpoint keeps serving them (one-way door for the
  // resolver, two-way door for the factory).
  PER_OPERATOR_CLAIM_SIGNING_ENABLED: optional('PER_OPERATOR_CLAIM_SIGNING_ENABLED', 'false'),

  // Name servers (addresses, comma separated) that look up the DNS records which prove an e-mail domain for single
  // sign-on. Empty: the machine's own resolver. Read once, by the wiring of the verified-domain service.
  SSO_DNS_SERVERS: optional('SSO_DNS_SERVERS', ''),

  isDev: optional('NODE_ENV', 'development') === 'development',
} as const;

assertOAuthSecurityConfiguration(env);
assertStagingConfiguration(env);
