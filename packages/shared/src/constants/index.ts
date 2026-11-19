// Passport
export const PASSPORT_DEFAULT_TTL_SECONDS = 15 * 60; // 15 minutes
export const PASSPORT_MAX_TTL_SECONDS = 60 * 60; // 1 hour hard max
export const PASSPORT_REFRESH_GRACE_SECONDS = 24 * 60 * 60; // 24 hour grace window after expiry
export const PASSPORT_MAX_DELEGATION_DEPTH = 4;
export const PASSPORT_ISSUER = 'getstack.run';

// Drop-off
export const DROPOFF_DEFAULT_TTL_SECONDS = 30 * 60; // 30 minutes
/** An intent approval waits for a decision this long when its submitter names no time, and at most DAY: a longer time is refused, never cut. */
export const INTENT_APPROVAL_DEFAULT_TTL_SECONDS = 900;
export const INTENT_APPROVAL_MAX_TTL_SECONDS = 24 * 60 * 60;

/** A drop-off lasts any number of seconds its sender names, from a minute; the number is held to what a 32-bit integer carries (the type's own bound). */
export const DROPOFF_TTL_INT_MAX = 2_147_483_647;

// API keys
export const API_KEY_PREFIX_LIVE = 'sk_live_';
export const API_KEY_PREFIX_TEST = 'sk_test_';
export const API_KEY_LENGTH = 32;

// Revocation. Conservative ceiling, wired to no enforcement mechanism:
// verify() runs a live revocation check on every call, so STACK-enforced
// paths reject on the NEXT call (measured ~10ms median / ~15ms p99 in a
// propagation benchmark). This
// constant is the recommended max reconcile interval for external
// stack:revoked subscribers, not a propagation delay.
export const REVOCATION_PROPAGATION_SECONDS = 60;

// Synthetic agents — sandbox runner agents and smoke-test pseudo-agents
// whose security_event firings are detector working-as-designed (the
// adversarial scenarios deliberately trip detectors) but they're noise
// in the operator's day-to-day triage view. The `/v1/security-events`
// route filters these out by default; pass `?include_synthetic=true` to
// see them. The events still write to security_events normally — they
// exist for audit/forensics — they just don't surface in the unresolved
// list. Identification has two prongs:
//   - prefix: agt_sandbox_* covers a deployment's own demo agents
//   - exact id: pseudo-agents created by smoke tests that don't have a
//     real agents row (e.g. 'oauth' from an OAuth refresh smoke test).
export const SYNTHETIC_AGENT_PREFIXES = ['agt_sandbox_'] as const;
export const SYNTHETIC_AGENT_IDS = ['oauth'] as const;

export function isSyntheticAgentId(id: string | null | undefined): boolean {
  if (!id) return false;
  if ((SYNTHETIC_AGENT_IDS as readonly string[]).includes(id)) return true;
  return SYNTHETIC_AGENT_PREFIXES.some((p) => id.startsWith(p));
}

// Session JWT (dashboard auth)
export const SESSION_JWT_TTL_SECONDS = 86400; // 24 hours
export const SESSION_JWT_AUDIENCE = 'stack:dashboard';
export const PASSPORT_JWT_AUDIENCE = 'stack:passport';

// OAuth 2.1. See the agent auth design
// § Implementation ADR for full design notes.
// The original issuer. Keep signing this value until the coordinated issuer
// migration is complete. Verification also accepts the RFC 8414 metadata
// issuer so tokens from the aborted early cutover remain usable until expiry.
export const OAUTH_ISSUER = 'getstack.run';
export const OAUTH_METADATA_ISSUER = 'https://api.getstack.run';
// Access-token lifetime, split per audience. Both are 1 hour: a STACK-
// enforced path (proxy, API, MCP) runs a live revocation check on every
// call, so TTL is NOT the revocation window — it only bounds an offline
// signature-only verifier (which STACK has no consumer of today). A short
// TTL forced refresh-rotation ~12×/hour of active use, and each rotation
// irreversibly revokes the prior refresh token; a single dropped/raced
// client-side persist then bricked the whole token family. 1h (matching
// PASSPORT_MAX_TTL_SECONDS) makes rotation rare. See the agent auth design.
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP = 60 * 60;        // 1 hour
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS_API = 60 * 60;        // 1 hour
export const OAUTH_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
// Redis key marking a whole OAuth token family as revoked. Written at
// family-revoke time (mcp-session revoke + refresh reuse-detection) with a
// TTL ≥ the max access-token TTL so the flag always outlives any live access
// token of that family. The auth path checks it to enforce revocation on an
// already-issued (stateless) access token — mirrors the passport
// `revoked:<jti>` model, family-keyed.
export const OAUTH_FAMILY_REVOKED_KEY = (familyId: string): string =>
  `oauth_family_revoked:${familyId}`;
// Rotation-grace: a client that rotated a refresh token but dropped the
// persisted replacement (or a concurrent client that rotated first) may
// re-present the just-replaced token within this window. When the family
// head is still live and the client matches, we hand back the existing
// head idempotently instead of triggering reuse-detection. A late /
// cross-client / family-moved-on replay still revokes the family.
export const OAUTH_REFRESH_ROTATION_GRACE_SECONDS = 60;           // 1 min
export const OAUTH_AUTHORIZATION_CODE_TTL_SECONDS = 10 * 60;      // 10 min, single-use
export const OAUTH_DEVICE_CODE_TTL_SECONDS = 15 * 60;             // 15 min
export const OAUTH_DEVICE_CODE_INTERVAL_SECONDS = 5;              // poll cadence start
export const OAUTH_DEVICE_CODE_MAX_INTERVAL_SECONDS = 60;         // slow_down cap
export const OAUTH_CONSENT_JWT_TTL_SECONDS = 15 * 60;             // 15 min consent handoff: the owner may first have to sign in by magic link, which lasts 15 minutes
export const OAUTH_CONSENT_JWT_AUDIENCE = 'stack:oauth-consent';
export const OAUTH_ACCESS_TOKEN_AUDIENCE_API = 'stack:api';
export const OAUTH_ACCESS_TOKEN_AUDIENCE_MCP = 'stack:mcp';
export const OAUTH_RESOURCE_API = 'https://api.getstack.run';
export const OAUTH_RESOURCE_MCP = 'https://mcp.getstack.run/mcp';
// The connector-directory MCP endpoint (Claude Connectors Directory, ChatGPT
// apps). Same audience as OAUTH_RESOURCE_MCP, but every token carries a signed
// `resource` claim and the MCP transport serves /directory only to tokens bound
// to this exact resource, and /mcp never to them.
export const OAUTH_RESOURCE_MCP_DIRECTORY = 'https://mcp.getstack.run/directory';
/** OAuth scopes used by the API's exact, default-deny route map. */
export const OAUTH_SCOPES = [
  'account:read', 'account:write',
  'team:read', 'team:write',
  'oauth-apps:read', 'oauth-apps:write',
  'cmek:read', 'cmek:write',
  'passports:read', 'passports:write',
  'agents:read', 'agents:write',
  // Agent accounts. read: accounts, their messages, sandbox runs and
  // purchases. write: open (human approval), close, end a browser session.
  // act: what the account does in the world (mail, texts, sandbox runs,
  // browser, card checkout). manage: operator controls that widen or erase
  // without approval (the do-not-contact list, lift an automatic pause, delete
  // a received message).
  'accounts:read', 'accounts:write', 'accounts:act', 'accounts:manage',
  'services:read', 'services:write', 'services:connect',
  'inbound-webhooks:read', 'inbound-webhooks:write',
  'credentials:read', 'credentials:write',
  'proxy:read', 'proxy:write',
  'audit:read',
  'billing:read', 'billing:write',
  'payouts:read', 'payouts:write',
  'identity:read', 'identity:write',
  'authority:read', 'authority:write',
  'governance:read', 'governance:write',
  // Decide a pending governance approval from the chat: reject, or approve
  // with the hosted MCP server's attestation of the person's confirmation.
  // Separate from governance:write, which also approves intents.
  'governance:decide',
  'intents:read', 'intents:write',
  'missions:read', 'missions:write',
  'reviews:read', 'reviews:write',
  'evidence:read', 'evidence:write',
  'dropoffs:read', 'dropoffs:write',
  'skills:read', 'skills:write', 'skills:invoke', 'skills:publish',
  'notifications:read', 'notifications:write',
  'security-events:read', 'security-events:write',
  'llm:read', 'llm:invoke',
  'scan:read', 'scan:write',
  'detectors:read', 'detectors:write',
  'pii:read', 'pii:write',
  'partner:read', 'partner:write',
  'admin',
] as const;
export type OAuthScope = (typeof OAUTH_SCOPES)[number];
/**
 * Scope ceiling for tokens bound to OAUTH_RESOURCE_MCP_DIRECTORY. The
 * authorization server intersects every requested scope with this list.
 * It withholds the scopes behind the tools the directory profile excludes
 * (proxy execution, wallet-charging skill invocation, credential connect and
 * retrieval, intent submission, team administration, identity and authority
 * configuration, marketplace publishing, partner administration, and an agent
 * account's outbound mail, texts, sandbox runs, browser and card checkout)
 * plus account deletion, billing and payout mutation, the do-not-contact list,
 * agent-account pause and message-erasure controls, OAuth-app and CMEK administration,
 * security-event resolution, LLM gateway calls and platform admin. A leaked
 * directory token therefore cannot reach those REST routes either. Every
 * remaining write is additive, a revocation, or gated by a human browser
 * approval when it loosens or expands authority. governance:decide joins the
 * ceiling so a person can confirm an approval in the chat: it approves only
 * with the hosted MCP server's attestation of that confirmation, never the
 * browser-only actions, and rejecting stays open.
 */
export const OAUTH_DIRECTORY_SCOPES = [
  'account:read',
  'team:read',
  'passports:read', 'passports:write',
  'agents:read', 'agents:write',
  'accounts:read', 'accounts:write',
  'services:read', 'services:write',
  'inbound-webhooks:read', 'inbound-webhooks:write',
  'proxy:read',
  'audit:read',
  'billing:read',
  'identity:read',
  'authority:read',
  'governance:read', 'governance:decide',
  'intents:read',
  'missions:read', 'missions:write',
  'reviews:read', 'reviews:write',
  'evidence:read', 'evidence:write',
  'dropoffs:read', 'dropoffs:write',
  'skills:read', 'skills:write',
  'notifications:read', 'notifications:write',
  'security-events:read',
  'llm:read',
  'scan:read', 'scan:write',
  'detectors:read', 'detectors:write',
  'pii:read', 'pii:write',
  'partner:read',
] as const satisfies readonly OAuthScope[];

/**
 * Scopes an MCP client requests by default for /mcp: the protected-resource
 * metadata scopes_supported and the scope in the 401 challenge. It covers
 * every /mcp tool except those whose scope also authorizes a write no human
 * approval gates (team:write, identity:write, authority:write, skills:publish,
 * partner:write, accounts:manage); those stay explicit incremental grants.
 * reviews:write, detectors:write, pii:write, notifications:write,
 * inbound-webhooks:write and accounts:write are included because their
 * writes are additive, revocations, or need a human browser approval
 * (governance step-up) for every Bearer caller.
 *
 * An owner signing in from a chat also gets the owner's own scopes by default,
 * so running the account from the chat needs no second consent:
 * account:write (end a chat session, change identity settings; deleting the
 * account and changing its e-mail are closed to every OAuth token),
 * billing:write (every route behind it is a browser-only approval),
 * governance:write (approve or reject an intent an agent submitted) and
 * security-events:write (mark an event resolved). The routes behind them
 * refuse an agent context and a member who is not an admin. The directory
 * ceiling does not include them. The runtime action scopes
 * (proxy:write, skills:invoke, accounts:act, llm:invoke) are included because acting is
 * what /mcp serves: each action is metered, audited, and refused once the
 * Passport, Mission or agent account is revoked or closed.
 */
export const OAUTH_MCP_DEFAULT_SCOPES = [
  'account:read', 'account:write',
  'team:read',
  'passports:read', 'passports:write',
  'agents:read', 'agents:write',
  'accounts:read', 'accounts:write', 'accounts:act',
  'services:read', 'services:write', 'services:connect',
  'inbound-webhooks:read', 'inbound-webhooks:write',
  'proxy:read', 'proxy:write',
  'audit:read',
  'billing:read', 'billing:write',
  'identity:read',
  'authority:read',
  'governance:read', 'governance:write', 'governance:decide',
  'intents:read', 'intents:write',
  'missions:read', 'missions:write',
  'reviews:read', 'reviews:write',
  'evidence:read', 'evidence:write',
  'dropoffs:read', 'dropoffs:write',
  'skills:read', 'skills:write', 'skills:invoke',
  'notifications:read', 'notifications:write',
  'security-events:read', 'security-events:write',
  'llm:read', 'llm:invoke',
  'scan:read', 'scan:write',
  'detectors:read', 'detectors:write',
  'pii:read', 'pii:write',
  'partner:read',
] as const satisfies readonly OAuthScope[];

/**
 * Scopes a client requests by default for /directory, and the scope the
 * authorization server grants when a directory request names none. Every
 * entry is inside OAUTH_DIRECTORY_SCOPES and covers a directory tool.
 */
export const OAUTH_DIRECTORY_DEFAULT_SCOPES = OAUTH_MCP_DEFAULT_SCOPES.filter(
  (scope) => (OAUTH_DIRECTORY_SCOPES as readonly string[]).includes(scope),
);
export const OAUTH_DEFAULT_SCOPE = 'passports:read agents:read services:read audit:read';

/**
 * RFC 8693 Token Exchange — Part of the Signed Primitive epic.
 *
 * STACK accepts subject_token = STACK passport JWT and returns a refreshed
 * passport. Mirrors the existing passport-service.refresh() flow under the
 * OAuth standard envelope so Keycard, OAuth-Token-Exchange-aware tooling,
 * and the broader OAuth ecosystem can interop at the protocol level.
 *
 * Token-type URIs:
 *   - subject_token_type accepted: TOKEN_TYPE_JWT (RFC 8693 standard) OR
 *     TOKEN_TYPE_STACK_PASSPORT (STACK-specific, explicit semantics).
 *   - issued_token_type returned: TOKEN_TYPE_STACK_PASSPORT. The bytes
 *     ARE a JWT, but STACK-passport semantics (revocation, delegation,
 *     accountability) are not captured by `urn:...jwt` alone.
 */
export const GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';
export const TOKEN_TYPE_STACK_PASSPORT = 'urn:stack:token-type:passport';

/** Reserved domain of the placeholder emails partner-managed accounts carry until their customer claims one. */
export const TENANT_PLACEHOLDER_EMAIL_DOMAIN = '.stack-tenant.local';

/**
 * Partner-managed accounts and their release to the customer.
 *
 * A partner opens an account for its customer under its own reference; nothing of the customer is
 * stored until the partner invites them to see it or the account is released to them. A release
 * mails the customer a claim link; the claim runs the platform checkout and the sanctions check, and
 * only when both pass does the account move to the customer. A claim that is not completed in time
 * leaves the account with the partner.
 */
export const PARTNER_RELEASE_STATUSES = ['pending', 'completed', 'returned', 'cancelled'] as const;
export type PartnerReleaseStatus = (typeof PARTNER_RELEASE_STATUSES)[number];
/** Who asked for the account to be released. */
export const PARTNER_RELEASE_REQUESTERS = ['partner', 'customer'] as const;
export type PartnerReleaseRequester = (typeof PARTNER_RELEASE_REQUESTERS)[number];
/** How long a claim link works. Past it the account stays with the partner. */
export const PARTNER_CLAIM_TTL_SECONDS = 7 * 24 * 3600;
/** A claim link is not mailed again for the same account within this window. */
export const PARTNER_CLAIM_RESEND_SECONDS = 10 * 60;
/** How long the partner can read the outcome of a release after it ended. */
export const PARTNER_RELEASE_RECORD_SECONDS = 90 * 24 * 3600;
/** Releases and invitations a partner may start per hour. Each one mails a stranger on STACK's behalf. */
export const PARTNER_MAIL_RATE_PER_HOUR = 60;
/** What the customer a partner invites may do in the account: read it, change nothing. */
export const PARTNER_INVITE_ROLE = 'readonly';

// per-agent Ed25519 keypair. Each request from the agent
// runtime is a fresh JWT signed by the agent's privkey, audience-bound,
// short-lived to bound replay. Server holds the pubkey in
// agents.pubkey (JWK). See the agent auth design §.
export const AGENT_JWT_ISSUER = 'stack-sdk';
export const AGENT_JWT_AUDIENCE = 'stack:agent';
// What the first-party SDKs MINT. Not a ceiling: the verifier accepts up to
// AGENT_JWT_MAX_TTL_SECONDS below, so a third-party client could legitimately
// present a 120s token. (The old comment here claimed 60 was the hard ceiling
// and that the replay window "is exactly this long" - both wrong. Replay is
// blocked outright by the Redis nonce, which is NX for TTL*2, so a jti is
// single-use rather than replayable within a window.)
export const AGENT_JWT_TTL_SECONDS = 60;
export const AGENT_JWT_MAX_TTL_SECONDS = 120;   // verifier refuses anything longer than this even if signed
/**
 * How far a verifier lets an agent JWT's `exp` and `nbf` drift from its own
 * clock. A token stays acceptable until `exp` plus this, so a jti is
 * remembered for as long (see authenticateAgentJwt).
 */
export const AGENT_JWT_CLOCK_TOLERANCE_SECONDS = 30;
/** Enrollment proof-of-possession challenge — server-issued, 5 min TTL,
 * single-use (consumed by /enroll). */
export const AGENT_ENROLLMENT_CHALLENGE_TTL_SECONDS = 5 * 60;
/** Fleet enrollment challenge (proof of possession of the new worker key), single-use. */
export const FLEET_ENROLLMENT_CHALLENGE_TTL_SECONDS = 120;
/**
 * Enrollment ticket — short-lived signed bearer the dashboard mints when
 * an operator approves an SDK agent enrollment in the browser. The SDK
 * holds it in-memory and uses it as the Bearer for /enrollment-challenge
 * + /enroll on a single bound agent_id. Single-use: burned after /enroll
 * succeeds (Redis jti). Audience-locked so the same JWT cannot be
 * replayed against any other API surface even if exfiltrated.
 *
 * 5 min covers a slow user click + the two-RTT enrollment dance with
 * margin; not so long that an exfiltrated ticket survives a coffee break.
 */
export const ENROLLMENT_TICKET_AUDIENCE = 'stack:enrollment-ticket';
export const ENROLLMENT_TICKET_TTL_SECONDS = 5 * 60;

// Team invites
export const INVITE_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

// Accountability
export const CHECKPOINT_DEFAULT_INTERVAL_SECONDS = 5 * 60; // 5 minutes (standard preset)
export const CHECKPOINT_MIN_INTERVAL_SECONDS = 60; // 1 minute absolute min
export const CHECKPOINT_MAX_INTERVAL_SECONDS = 3600; // 1 hour absolute max
export const CHECKPOINT_PRESETS = {
  frequent: 2 * 60,   // 2 min
  standard: 5 * 60,   // 5 min
  relaxed: 15 * 60,   // 15 min
  marathon: 60 * 60,  // 60 min
} as const;

// Security signals
export const CREDENTIAL_BURST_WINDOW_SECONDS = 60;
export const CREDENTIAL_BURST_THRESHOLD = 10;

// Proxy
/**
 * The longest a signed Passport may be, in characters. A Passport travels in a request header, and STACK's servers
 * take request headers up to `HTTP_MAX_HEADER_BYTES`, so STACK refuses to sign one that would not arrive.
 */
export const PASSPORT_TOKEN_MAX_CHARS = 48_000;
/** The most bytes of request headers STACK's HTTP servers read (Node's `maxHeaderSize`; Node's own default is 16 KB). */
export const HTTP_MAX_HEADER_BYTES = 64 * 1024;
export const PROXY_RESPONSE_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
export const PROXY_REQUEST_TIMEOUT_MS = 30_000; // 30 seconds
/**
 * A proxied write whose outcome is unknown and that nothing settled (no response came back, no reconciliation ended it)
 * becomes `unresolved` after this many days: it is never sent again, and the agent and the owner are told.
 */
export const PROXY_OPERATION_UNRESOLVED_AFTER_DAYS = 7;

// Control socket: action kinds, limits and closed lists
export * from './control-socket.js';

// Policies: the configuration behind hosted controls
export * from './control-policy.js';

// The STACK network: signed-object formats, limits and closed lists
export * from './network.js';

// The catalogue: kinds, bounds and where the file is served
export * from './catalogue.js';

// The OpenRouter passthrough of the model gateway: its host, hold, bounds and headers
export * from './openrouter-gateway.js';
export * from './openrouter-endpoints.js';
export * from './openrouter-worst-case.js';

// The plan the engine runs on: the contract plan's limits
export * from './plan-limits.js';

// Why a connection must be reconnected, and the words for it
export * from './reconnect-reasons.js';

// Credential templates
export { CREDENTIAL_TEMPLATES, type CredentialTemplate, type CredentialField } from './credential-templates.js';

// Known API hosts per provider — seeds credential-to-destination binding
export {
  PROVIDER_API_HOSTS,
  PER_TENANT_HOST_PROVIDERS,
  defaultHostsForProvider,
  isPerTenantHostProvider,
} from './provider-api-hosts.js';

// Providers whose responses carry money and bank identifiers (data-flow rule).
export { FINANCIAL_PROVIDERS, isFinancialProvider } from './financial-providers.js';

/**
 * How long a read stays on a Mission's data trail, counted from when it was
 * recorded. A Mission has no maximum length, and an agent account's standing
 * Mission is extended in place and never replaced, so without a window its
 * trail would grow for as long as the account lives and every source it ever
 * read would taint every later send. Seven days covers "read it Monday, send
 * it on Friday" and a mail thread that takes a week to answer; anything older
 * is no longer what the agent is working from. Reading a source again records
 * it again, so a source the agent keeps using never ages out.
 */
export const DATA_TRAIL_WINDOW_SECONDS = 7 * 24 * 60 * 60;

// Safety detector catalog — display names + descriptions + status for every signal
export {
  DETECTORS,
  DETECTOR_KEYS,
  getDetector,
  getDetectorDisplayName,
  getDetectorDescription,
  listLiveDetectors,
  type DetectorDefinition,
  type DetectorKey,
  type DetectorStatus,
  type DetectorPipeline,
} from './detectors.js';

// PII pattern catalog + scanner. Reusable across LLM
// gateway redaction (immediate use), future audit-log + security-event
// + dropoff redaction (5.2.4+).
export {
  PII_PATTERNS,
  PII_SCORES,
  PII_CONTEXT_BOOST,
  PII_CONTEXT_WINDOW_CHARS,
  PII_DEFAULT_THRESHOLD,
  scanForPii,
  type PiiCategory,
  type PiiPatternDef,
  type PiiMatch,
  type PiiScanOptions,
} from './pii-patterns/index.js';

// per-provider × per-model LLM pricing catalog + cost
// calculation helper. Consumed by LlmUsageService (packages/vault) on
// every successful LLM gateway call.
export {
  LLM_GATEWAY_MARKUP_BPS,
  MICROCENTS_PER_CENT,
  ANTHROPIC_PRICING,
  OPENAI_PRICING,
  PRICING_FALLBACK,
  calculateLlmCost,
  costFromProviderReported,
  costFromHeldCents,
  costFromCatalogueUsdMicros,
  type LlmModelPricing,
  type LlmCostBreakdown,
} from './llm-pricing.js';

// Who an agent is: the wire constants of spec/agent-identity
export * from './agent-identity.js';

// The security-monitoring export: the wire constants of spec/siem-export
export * from './siem-export.js';

// Single sign-on: the wire constants of spec/sso-login
export * from './sso-login.js';

// A pending item an agent waits on, and how it ended (announced through the API's decisionReached registry)
export * from './decisions.js';

// Connected services that speak MCP over HTTP, and where (stack_service_tools, stack_service_call_tool)
export * from './service-mcp.js';
