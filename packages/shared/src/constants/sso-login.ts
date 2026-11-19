// The wire constants of single sign-on through a customer's OpenID Connect provider (spec/sso-login/SPEC.md):
// the paths, the lifetimes of a sign-in attempt, a code and the handoff reference, the tolerance on an ID token's
// clock and the limits on what is fetched from the provider. They are the public specification's, so they live
// here: the specification generator reads its constants table from this file, and the engine imports the same.

/** The cookie that ties a sign-in attempt to the browser that began it. */
export const SSO_STATE_COOKIE = 'stack_sso_state';
/** How long a sign-in attempt (the state, and the cookie) lasts, in seconds. */
export const SSO_STATE_TTL_SECONDS = 10 * 60;
/** How long an authorization code the provider handed back waits to be redeemed, in seconds. */
export const SSO_CODE_TTL_SECONDS = 5 * 60;
/** How long the handoff reference a finished sign-in leaves behind can be redeemed, in seconds. It is single use. */
export const SSO_HANDOFF_TTL_SECONDS = 60;
/** The tolerance on an ID token's `exp` and `nbf`, in seconds, for a provider's clock that is a little off. */
export const SSO_ID_TOKEN_CLOCK_TOLERANCE_SECONDS = 30;
/** The longest one request to the provider (discovery, key set, token endpoint) may take, in seconds. */
export const SSO_FETCH_TIMEOUT_SECONDS = 5;
/** How long a provider's discovery document is kept, in seconds. */
export const SSO_DISCOVERY_TTL_SECONDS = 24 * 60 * 60;
/** The lifetime of a provider's key set in the cache: the default, and the range a connection may choose in, in seconds. */
export const SSO_JWKS_CACHE_DEFAULT_SECONDS = 300;
export const SSO_JWKS_CACHE_MIN_SECONDS = 60;
export const SSO_JWKS_CACHE_MAX_SECONDS = 3600;
/** An ID token signed by a key the cached set lacks forces one refetch of the set; never more than one in this many seconds. */
export const SSO_JWKS_REFETCH_COOLDOWN_SECONDS = 60;

/** The address a person starts signing in at: the slug names the organisation. */
export const SSO_START_PATH = '/v1/identity/sso/{slug}/start';
/** The address every provider sends the browser back to. */
export const SSO_CALLBACK_PATH = '/v1/identity/oidc/callback';
/** Where, on the deployment's dashboard, a finished sign-in sends the browser, with the handoff reference as `ref`. */
export const SSO_HANDOFF_REDIRECT_PATH = '/auth/sso/callback';

// ── Verified domains (spec/sso-login/SPEC.md section 9.5) ──────────────────────────────────────────────────────────
// An account proves it controls an e-mail domain with a DNS TXT record, and the sign-in then counts an address at that
// domain as verified when the provider's ID token does not say.

/** The label of the DNS name an account publishes its proof at: `{label}.{domain}`. */
export const SSO_DOMAIN_RECORD_LABEL = '_stack-sso';
/** The text a proof record begins with; the rest is the account's token for that domain. */
export const SSO_DOMAIN_RECORD_PREFIX = 'stack-sso-verification=';
/** Random bytes in a proof token (so 32 base64url characters). The token is published in DNS, so it is a name, not a secret. */
export const SSO_DOMAIN_TOKEN_BYTES = 24;
/** How long a successful check of the record counts at sign-in, in seconds. Past it the sign-in looks the record up again, and a lookup that fails or finds nothing means the domain does not count. */
export const SSO_DOMAIN_TRUST_SECONDS = 6 * 60 * 60;
/** How often the deployment looks the records of the domains it holds up again, in seconds. */
export const SSO_DOMAIN_RECHECK_SECONDS = 60 * 60;
/** How long a record may be seen missing before the domain stops belonging to the account and must be verified again, in seconds. */
export const SSO_DOMAIN_LAPSE_SECONDS = 7 * 24 * 60 * 60;
/** How long a domain added and never verified is kept, in seconds. */
export const SSO_DOMAIN_PENDING_SECONDS = 14 * 24 * 60 * 60;
/** A domain is looked up at most once in this many seconds on request, so a request is not a way to flood a name server. */
export const SSO_DOMAIN_CHECK_COOLDOWN_SECONDS = 10;
/** The longest one DNS lookup may take, in seconds. */
export const SSO_DOMAIN_LOOKUP_TIMEOUT_SECONDS = 5;
/** Most domains one account may hold, pending or verified. */
export const SSO_DOMAINS_MAX_PER_ACCOUNT = 20;
/** The states of a domain: `pending` (added, never proven), `verified`, and `lapsed` (was proven, the record has been gone for the lapse time). */
export const SSO_DOMAIN_STATUSES = ['pending', 'verified', 'lapsed'] as const;
export type SsoDomainStatus = (typeof SSO_DOMAIN_STATUSES)[number];
/** What one lookup found: the proof record, no such record, or no answer (a failed lookup is never read as either). */
export const SSO_DOMAIN_CHECK_RESULTS = ['confirmed', 'missing', 'unavailable'] as const;
export type SsoDomainCheckResult = (typeof SSO_DOMAIN_CHECK_RESULTS)[number];
