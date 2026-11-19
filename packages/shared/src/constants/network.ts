// The STACK network: hosted services a self-hosted install (or a hosted
// customer) calls, and the trust between companies they make possible. These
// are the closed lists and the numbers every layer (API, vault, SDKs, CLI,
// the offline verifier and the public specification) agrees on.
//
// Every signed object below is a compact JWS (RFC 7515), EdDSA over Ed25519.
// Each has its own `typ` header and `aud` claim, so a signature made for one
// purpose is never valid for another, and none of them is a passport:
// a passport verifier checks `aud` = `stack:passport` and rejects all of these.

/** Who a signed request from an install is addressed to. */
export const NETWORK_AUDIENCE = 'stack:network';

/** typ of a request an install signs with its own key (the install proof). */
export const NETWORK_INSTALL_PROOF_TYP = 'stack-install+jwt';
/** typ of the proof of possession an install signs when it registers a key. */
export const NETWORK_INSTALL_POP_TYP = 'stack-install-pop+jwt';
/** typ and aud of a countersignature STACK signs over an install's passport. */
export const COUNTERSIGNATURE_TYP = 'stack-countersignature+jwt';
export const COUNTERSIGNATURE_AUDIENCE = 'stack:countersignature';
/** typ and aud of the signed list of revocations. */
export const REVOCATION_LIST_TYP = 'stack-revocation-list+jwt';
export const REVOCATION_LIST_AUDIENCE = 'stack:revocation-list';
/** typ and aud of the "STACK-verified" statement. */
export const VERIFIED_STATEMENT_TYP = 'stack-verified+jwt';
export const VERIFIED_STATEMENT_AUDIENCE = 'stack:verified';
/** typ and aud of the signed detection rule set. */
export const DETECTION_RULES_TYP = 'stack-detection-rules+jwt';
export const DETECTION_RULES_AUDIENCE = 'stack:detection-rules';

/** The mark's name, spelled exactly like this wherever a statement or a client shows it. Its use is set out in TRADEMARKS.md. */
export const STACK_VERIFIED_MARK = 'STACK-verified';

/** What an install proof asks for. The route that receives it checks it is the one it serves. */
export const NETWORK_PROOF_ACTIONS = ['rules', 'classify', 'countersign', 'revoke'] as const;
export type NetworkProofAction = (typeof NETWORK_PROOF_ACTIONS)[number];

/** An install proof is good for this long after it is issued, and once. */
export const NETWORK_PROOF_MAX_LIFETIME_SECONDS = 120;
/** How far an install's clock may differ from STACK's (either way). */
export const NETWORK_PROOF_CLOCK_SKEW_SECONDS = 60;
/** The key-registration challenge, and how long the install has to answer it. */
export const NETWORK_KEY_CHALLENGE_TTL_SECONDS = 300;

/** A countersignature is as short-lived as a passport: default 15 minutes, never above an hour. */
export const COUNTERSIGNATURE_DEFAULT_TTL_SECONDS = 900;
export const COUNTERSIGNATURE_MIN_TTL_SECONDS = 60;
export const COUNTERSIGNATURE_MAX_TTL_SECONDS = 3600;
/** A "STACK-verified" statement is a snapshot: five minutes. */
export const VERIFIED_STATEMENT_TTL_SECONDS = 300;
/** A signed revocation list is a snapshot too: five minutes. */
export const REVOCATION_LIST_TTL_SECONDS = 300;
/** A signed rule set may be used for this long; an install fetches a fresh one well before. */
export const DETECTION_RULES_TTL_SECONDS = 72 * 3600;

/** Counterparty subscriptions deliver the revocation list; these bound them. */
export const NETWORK_MAX_INSTALLS_PER_OPERATOR = 250;
export const NETWORK_MAX_LIVE_KEYS_PER_INSTALL = 3;
export const NETWORK_MAX_SUBSCRIPTIONS_PER_OPERATOR = 100;
/** An old key keeps working this long after a new one is registered (and no longer than a week). */
export const NETWORK_KEY_ROLLOVER_DEFAULT_SECONDS = 24 * 3600;
export const NETWORK_KEY_ROLLOVER_MAX_SECONDS = 7 * 24 * 3600;
export const REVOCATION_LIST_PAGE_DEFAULT = 200;
export const REVOCATION_LIST_PAGE_MAX = 500;
/** Countersignature rows are kept this long after they expire, then removed. */
export const COUNTERSIGNATURE_RETENTION_DAYS = 30;
/** A revoked licence key is listed this long after it would have expired, then removed. */
export const LICENCE_REVOCATION_RETENTION_DAYS = 90;
/**
 * How long the network remembers that a licence key is not revoked. A revocation
 * overwrites it at once on every machine; this only bounds the case where that
 * write could not be made.
 */
export const LICENCE_REVOCATION_CACHE_SECONDS = 30;
/** How long it remembers that one is revoked (the database still decides when the copy lapses). */
export const LICENCE_REVOKED_CACHE_SECONDS = 24 * 3600;

/** Webhook delivery: attempts back off from 1 s to 1 h, and a subscription that has failed this long pauses. */
export const NETWORK_WEBHOOK_TIMEOUT_MS = 5_000;
export const NETWORK_WEBHOOK_RESPONSE_MAX_BYTES = 4_096;
export const NETWORK_WEBHOOK_BACKOFF_BASE_MS = 1_000;
export const NETWORK_WEBHOOK_BACKOFF_MAX_MS = 60 * 60 * 1000;
export const NETWORK_WEBHOOK_GIVE_UP_MS = 72 * 3600 * 1000;
/** Deliveries a runner claims at once. */
export const NETWORK_WEBHOOK_BATCH = 50;

/** What a revocation names. */
export const NETWORK_REVOCATION_KINDS = ['passport', 'agent', 'key', 'install'] as const;
export type NetworkRevocationKind = (typeof NETWORK_REVOCATION_KINDS)[number];

/** Why, as a closed list: the public list never carries free text. */
export const NETWORK_REVOCATION_REASONS = [
  'unspecified',
  'key_compromise',
  'agent_decommissioned',
  'superseded',
  'policy_violation',
  'owner_request',
] as const;
export type NetworkRevocationReason = (typeof NETWORK_REVOCATION_REASONS)[number];

/** Who published it. */
export const NETWORK_REVOCATION_PUBLISHERS = ['install', 'owner', 'stack'] as const;
export type NetworkRevocationPublisher = (typeof NETWORK_REVOCATION_PUBLISHERS)[number];

export const NETWORK_INSTALL_STATUSES = ['active', 'revoked'] as const;
export const NETWORK_KEY_STATUSES = ['active', 'revoked'] as const;
export const NETWORK_SUBSCRIPTION_STATUSES = ['active', 'failing', 'paused'] as const;

/** What the "STACK-verified" statement says. Only `live` earns the mark. */
export const NETWORK_VERIFIED_STATUSES = ['live', 'expired', 'revoked'] as const;
export type NetworkVerifiedStatus = (typeof NETWORK_VERIFIED_STATUSES)[number];

/** The detection rule packs STACK serves, and which way each one reads. */
export const NETWORK_RULE_PACKS = [
  { id: 'prompt_injection', direction: 'input' },
  { id: 'output_injection', direction: 'output' },
] as const;
