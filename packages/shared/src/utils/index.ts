import { nanoid } from 'nanoid';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { ForbiddenError } from '../errors/index.js';

export { assertPublicUrl, isBlockedIp, parsePublicUrl, resolvePublicUrl, UnsafeUrlError } from './url-guard.js';
export type { PublicUrlResolution, UrlGuardOptions } from './url-guard.js';
export { closePublicFetchPools, publicFetch, PublicFetchLimitError, stripHopByHopHeaders } from './public-fetch.js';
export type { PublicFetchOptions } from './public-fetch.js';
export {
  generateWebhookSecret,
  liveWebhookSecrets,
  signStandardWebhook,
  verifyStandardWebhook,
  webhookRotationLive,
  webhookSecretKey,
  WEBHOOK_ID_HEADER,
  WEBHOOK_SECRET_PREFIX,
  WEBHOOK_SECRET_ROTATION_GRACE_MS,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_SIGNATURE_TOLERANCE_SECONDS,
  WEBHOOK_TIMESTAMP_HEADER,
} from './standard-webhooks.js';
export type { SignedWebhookHeaders, WebhookVerification } from './standard-webhooks.js';
// The reader of an outbound Gmail or Outlook message: the proxy's constraints and the scope wall read recipients and text
// from a message whose headers are encoded in the body.
export { deriveRequestEmail, isEncodedEmailRequest, type DerivedEmail } from './derived-email.js';
export { redisBackoffMs, waitForRedis } from './redis-wait.js';
export {
  JOB_FAILED_CODE,
  JOB_NOT_CONFIGURED_CODE,
  jobFailureCode,
  reportJob,
  runPass,
  type JobObserver,
  type JobReport,
  type PassHandle,
  type PassOptions,
} from './job-report.js';
export {
  logRedisErrorsThrottled,
  observeRedisClient,
  REDIS_COMMAND_TIMEOUT_MS,
  REDIS_CONNECT_TIMEOUT_MS,
  REDIS_ERROR_LOG_WINDOW_MS,
  type ObservableRedis,
  type RedisErrorLogOptions,
  type RedisErrorSource,
} from './redis-error-log.js';
export {
  installSafeConsoleTelemetry,
  registerSafeRouteTemplate,
  safeErrorSummary,
  safeRouteTemplate,
  safeSentryRelease,
  sanitizeSentryEvent,
  type SafeErrorSummary,
} from './safe-telemetry.js';
export { deriveMcpForwardedClientKey, MCP_FORWARDED_CLIENT_KEY_PURPOSE, signForwardedClient } from './forwarded-client-key.js';
export {
  hashMcpSessionId,
  isUsableMcpElicitationAttestationKey,
  mcpElicitationAttestationMessage,
  MCP_ELICITATION_ATTESTATION_KEY_MIN_LENGTH,
  MCP_ELICITATION_ATTESTATION_MAX_AGE_SECONDS,
  MCP_ELICITATION_ATTESTATION_VERSION,
  signMcpElicitationAttestation,
  verifyMcpElicitationAttestation,
  type McpElicitationAttestationFields,
} from './mcp-elicitation-attestation.js';

export {
  normalizeRequest,
  resolvePath,
  evaluateConstraint,
  findFailingConstraint,
  constraintsAreSubset,
  compareConstraintSets,
  alternativesOf,
  MAX_SUBSET_COMPARISONS,
  allowDataFromIsSubset,
  allowDataFromGrantWidens,
  resolveAllowDataFromGrant,
  invalidChildScopes,
  defaultConnectionScopes,
  isServiceInScope,
} from './constraints.js';
export type { NormalizedRequest, ConstraintSetVerdict } from './constraints.js';

export { assertDelegationAllowed } from './delegation.js';

export {
  AUDIT_CHAIN_GENESIS,
  AUDIT_HASH_VERSION_CURRENT,
  computeAuditEntryHash,
  type AuditEntryHashInput,
  type AuditHashVersion,
  type AuditClaimBindingStatus,
} from './audit-hash.js';

export { computePassportClaimHash } from './passport-claim-hash.js';

export {
  JSON_SCHEMA_LIMITS,
  JsonSchemaPolicyError,
  assertSafeJsonSchema,
  assertBoundedJsonValue,
} from './json-schema-policy.js';

// direction classification for detector-config writes.
export {
  classifyDetectorConfigDelta,
  DETECTOR_CONFIG_DEFAULTS,
} from './detector-config-delta.js';
export type {
  DetectorConfigDelta,
  DetectorConfigDirection,
  DetectorConfigState,
} from './detector-config-delta.js';

export { canonicalize } from './json-canonicalize.js';

export { computeMerkleRoot } from './merkle.js';

export {
  reconstructTimeline,
  type ReplayedEventKind,
  type ReplayedEvent,
  type ReplayedMission,
  type ReplayedCapUsage,
  type ReplayedTimeline,
  type ReconstructClaimInput,
} from './reconstruct-timeline.js';

export { shannonEntropy } from './shannon-entropy.js';

// entity extraction for the
// undeclared_target detector + entity_observation producers.
export { extractEntities, canonicalMoneyAmount } from './entity-extraction.js';
export type { ExtractedEntity, EntityType, ExtractEntitiesOptions } from './entity-extraction.js';

// Credential-to-destination binding — a stored credential may only be
// injected into a request whose host belongs to its connection.
export { isHostAllowed, hostOfUrl, normalizeAllowedHosts, InvalidAllowedHostError } from './host-binding.js';
export { deriveConnectionHosts } from './derive-connection-hosts.js';

// Closed operations / closed bodies — a field present but undeclared is a denial.
export {
  evaluateScopePolicy,
  enumerateRequestFields,
  isFieldDeclared,
} from './operation-policy.js';
export type { PolicyDenial, DeclaredOperation as DeclaredOperationShape, ScopePolicy as ScopePolicyShape } from './operation-policy.js';

// Data carries its origin — the guestbook rule.
export {
  contentFingerprints,
  collectStrings,
  evaluateDataFlow,
  evaluateSourceMatches,
  matchObservedSources,
  carriedSources,
  indexObserved,
  flowSourceLabel,
  flowServiceKey,
  flowSourceAllowed,
  parseFlowSource,
  FLOW_SERVICE_KEY_MAX_CHARS,
} from './data-flow.js';
export type { ObservedItem, ObservedIndex, SourceMatch, SourceMatchInput, DeclaredFlow, DataFlowInput, DataFlowViolation } from './data-flow.js';

// Provenance that survives a hand-off between agents.
export {
  attributePayload,
  fingerprintPayload,
  inheritedObservations,
  observedKnowsEntity,
  provenanceEntityKey,
  provenanceSources,
  trailEntity,
  trailEntityDigest,
} from './provenance.js';
export type { DropoffProvenance, InheritedObservation, PayloadFingerprint } from './provenance.js';

// ID generation — prefixed for easy identification in logs and debugging
export function generateId(prefix: string, length = 21): string {
  return `${prefix}_${nanoid(length)}`;
}

export const ids = {
  operator: () => generateId('op'),
  agent: () => generateId('agt'),
  service: () => generateId('svc'),
  serviceConnection: () => generateId('scon'),
  passport: () => generateId('pas'),
  dropoff: () => generateId('dof'),
  auditEntry: () => generateId('aud'),
  apiKey: () => generateId('sk_live', 32),
  session: () => generateId('ses'),
  identityProvider: () => generateId('idp'),
  identityClaim: () => generateId('idc'),
  // `serviceRequirement` and `skillRequest` both mint `sreq_*`. Both ids are
  // persisted, so the prefix cannot change. The collision is harmless: the ids
  // live in different tables and neither is looked up without its table.
  serviceRequirement: () => generateId('sreq'),
  member: () => generateId('mem'),
  inviteToken: () => generateId('inv', 32),
  oauthApp: () => generateId('oapp'),
  serviceConfiguration: () => generateId('scfg'),
  skill: () => generateId('skl'),
  skillInvocation: () => generateId('sinv'),
  checkpoint: () => generateId('chk'),
  checkout: () => generateId('cout'),
  review: () => generateId('prev'),
  notificationChannel: () => generateId('nch'),
  notificationDestination: () => generateId('ndst'),
  securityEvent: () => generateId('sevt'),
  skillRating: () => generateId('srat'),
  // Shares the `sreq` prefix with `serviceRequirement`; see the note there.
  skillRequest: () => generateId('sreq'),
  skillRequestMatch: () => generateId('srmatch'),
  verificationCode: () => generateId('vcode'),
  auditArchiveSegment: () => generateId('aseg'),
  // SPIFFE consumer
  spiffeTrustDomain: () => generateId('std'),
  // WIMSE workload identity issuer
  wimseIssuer: () => generateId('wimse'),
  // OIDC IdP federation + enterprise SSO login
  oidcIdpConfig: () => generateId('oidc'),
  /** 32 raw bytes: it is a bearer credential for its 60-second life. */
  ssoHandoff: () => generateId('ssoh', 32),
  /** A verified-domain claim of single sign-on. */
  ssoDomain: () => generateId('ssod'),
  passportClaim: () => generateId('pc'),
  // Mission
  mission: () => generateId('ms'),
  // OAuth
  oauthClient: () => generateId('oclient'),
  oauthAccessTokenJti: () => generateId('oat'),
  oauthCode: () => generateId('ocode', 48),         // raw, returned to client (sha256'd at rest)
  oauthRefreshToken: () => generateId('rt', 48),    // raw, returned to client
  oauthDeviceCode: () => generateId('dvc', 48),     // raw, returned to client
  oauthTokenFamily: () => generateId('rfam'),
  // Intent approval
  intentApproval: () => generateId('ia'),
  // LLM usage — one row per successful /v1/llm/* call
  llmUsage: () => generateId('usg'),
  // Twin run — one row per mission with active twin run
  twinRun: () => generateId('twr'),
  // Evidence pack — one row per export of a pack
  pack: () => generateId('pck'),
  operatorDecision: () => generateId('odec'),
  // Inbound webhook — one row per inbound endpoint
  inboundWebhook: () => generateId('iwh'),
  // Inbound webhook slug — opaque URL-routing key embedded in the public path
  inboundWebhookSlug: () => generateId('s', 32),
  // Governance approval — one row per gated-action step-up request
  governanceApproval: () => generateId('gvr'),
  // Operator email transfer — one row per in-flight change of the address an
  // account signs in with.
  emailChange: () => generateId('oec'),
  // Control socket: one per customer; a decision's id is also the signed
  // message id of its request, so it is long enough to never repeat.
  controlSocket: () => generateId('csk'),
  controlDecision: () => generateId('dec', 24),
  controlEventBatch: () => generateId('evb', 24),
  // Policies and the actions they hold for a person.
  controlPolicy: () => generateId('cpl'),
  controlReview: () => generateId('crv'),
} as const;

// Hashing
export function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256Buffer(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

// API key hashing — HMAC-SHA256 with a server-side pepper so a
// leaked api_keys/operators table (SQLi, a DB backup, the PITR snapshot,
// an insider) yields hashes that are useless without the pepper.
//
// Fail-closed: in production the pepper is REQUIRED. Running unpeppered in
// prod silently defeats the control, so we throw instead of degrading —
// same posture as the SESSION_SIGNING_KEY prod hard-fail. In dev the
// pepper may be unset; we warn once so it's visible but not blocking.
// Read on use, not at import: a mounted secret (API_KEY_PEPPER_FILE) is put in the
// environment after this module loads.
const apiKeyPepper = (): string => process.env.API_KEY_PEPPER || '';
let warnedNoPepper = false;

function requirePepperOrWarn(): string {
  const pepper = apiKeyPepper();
  if (pepper) return pepper;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'API_KEY_PEPPER is not set. Refusing to hash/verify API keys unpeppered in production. ' +
        'Set the API_KEY_PEPPER secret (identical across api/dashboard/worker).',
    );
  }
  if (!warnedNoPepper) {
    warnedNoPepper = true;
    console.warn('[SECURITY] API_KEY_PEPPER is unset:', 'API-key hashes are plain SHA-256 (dev only).');
  }
  return '';
}

/**
 * Hash an API key for STORAGE. Produces the CURRENT scheme: HMAC-SHA256
 * under the pepper when set, plain SHA-256 otherwise (dev). This is what
 * gets written to `api_keys.hash` / `operators.api_key_hash` /
 * `team_members.api_key_hash`.
 */
export function hashApiKey(key: string): string {
  const pepper = requirePepperOrWarn();
  if (pepper) {
    return createHmac('sha256', pepper).update(key).digest('hex');
  }
  return sha256(key);
}

/**
 * Verify a presented API key against a STORED hash, tolerating the
 * dual-verify migration window. Because the pepper was
 * introduced after keys were already stored as plain SHA-256, a stored
 * hash may be under either scheme:
 *
 *   - peppered match  → { matches: true,  needsRehash: false }
 *   - legacy plain match (pepper is set) → { matches: true, needsRehash: true }
 *     Caller SHOULD re-store hashApiKey(presented) to upgrade the row.
 *   - no match        → { matches: false, needsRehash: false }
 *
 * Both comparisons are constant-time. The plain fallback only runs when a
 * pepper is configured (so it strictly widens acceptance during the
 * migration, never weakens the peppered regime); once telemetry shows no
 * legacy hashes remain, the fallback can be removed.
 */
export function verifyApiKeyHash(
  presentedKey: string,
  storedHash: string,
): { matches: boolean; needsRehash: boolean } {
  const pepper = requirePepperOrWarn();

  if (pepper) {
    const peppered = createHmac('sha256', pepper).update(presentedKey).digest('hex');
    if (secureCompare(peppered, storedHash)) {
      return { matches: true, needsRehash: false };
    }
    // Legacy row written before the pepper existed.
    const legacy = sha256(presentedKey);
    if (secureCompare(legacy, storedHash)) {
      return { matches: true, needsRehash: true };
    }
    return { matches: false, needsRehash: false };
  }

  // No pepper (dev): the stored hash is plain SHA-256 too.
  return { matches: secureCompare(sha256(presentedKey), storedHash), needsRehash: false };
}

// Constant-time comparison for API keys
export function secureCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

// Timestamp helpers
export function nowMs(): number {
  return Date.now();
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function secondsFromNow(seconds: number): number {
  return nowSeconds() + seconds;
}

// JSON-safe serialization for audit log payloads
export function hashPayload(payload: unknown): string {
  return sha256(JSON.stringify(payload));
}

// ─── Mission resolver ──────────────────
//
// Pure helper. Producers (proxy http_call, skill invocation,
// checkpoint submission, security event record, intent simulation
// emit) call this to populate the `mission_ref` field on the claim
// they're about to register.
//
// Auto-resolve rules:
//   - explicit non-null → must be in passport's mission_ids, returned as-is
//   - explicit null OR undefined + passport has exactly ONE active
//     mission → return that mission_id
//   - zero bindings → null unless a Mission is required
//   - multiple bindings without an explicit selection → deny
//
// The "explicit not in passport.mission_ids" case throws ForbiddenError
// at the call site — callers cannot tag an action with a mission the
// passport isn't bound to.

export class MissionRefForbidden extends ForbiddenError {
  constructor(missionId: string, passportMissionIds: readonly string[]) {
    super(
      `mission_ref ${missionId} is not bound to this passport. Passport carries: [${passportMissionIds.join(', ') || '(none)'}]`,
    );
    this.name = 'MissionRefForbidden';
  }
}

/**
 * Resolve the mission_ref payload field for a producer-emitted claim.
 *
 * @param passportMissionIds — the mission_ids[] claim from the passport
 *   JWT payload (PassportPayload.mission_ids). Pass undefined or empty
 *   array when the passport carries no mission binding.
 * @param explicit — optional caller-supplied mission_id override.
 *   Producer can take this from inbound parameters (e.g. an
 *   intent_claim payload's mission_ref) to thread an explicit choice
 *   through.
 * @returns the mission_id to stamp on the claim, or null when no
 *   mission attribution applies (zero bound + no explicit).
 * @throws MissionRefForbidden when explicit is supplied but not in
 *   the passport's mission_ids set.
 */
export function resolveMissionRef(
  passportMissionIds: readonly string[] | null | undefined,
  explicit?: string | null,
  options: { required?: boolean } = {},
): string | null {
  const bound = [...new Set(passportMissionIds ?? [])];
  if (explicit) {
    if (!bound.includes(explicit)) {
      throw new MissionRefForbidden(explicit, bound);
    }
    return explicit;
  }
  if (bound.length === 1) return bound[0]!;
  if (bound.length > 1 || options.required) throw new ForbiddenError();
  return null;
}

export * from './fleet-policy.js';
export * from './send-bounds.js';
export * from './refusal-evidence.js';
export * from './control-policy.js';
export * from './mission-recipients.js';
export * from './approval-scope-lines.js';
export * from './intent-approval-preview.js';
export * from './fictional-numbers.js';
export * from './partner-mail-rate.js';
export { SECRET_FILE_SETTINGS, loadSecretFiles } from './secret-files.js';
export * from './network-trust.js';
export * from './sso-domain.js';
export {
  isToolListed,
  MCP_AUDIENCES,
  MCP_SESSION_AUDIENCES,
  type McpAudience,
  type McpSessionAudience,
  type McpToolListing,
  type McpToolSession,
} from './mcp-tool-exposure.js';
