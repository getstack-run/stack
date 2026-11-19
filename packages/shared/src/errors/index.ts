import { StackError } from './base.js';
export { StackError };

// Auth
export class UnauthorizedError extends StackError {
  constructor(message = 'Unauthorized') {
    super(message, 'UNAUTHORIZED', 401);
  }
}

export class ForbiddenError extends StackError {
  constructor(message = 'Forbidden', details?: Record<string, unknown>) {
    super(message, 'FORBIDDEN', 403, details);
  }
}

export class InvalidApiKeyError extends StackError {
  constructor() {
    super('Invalid API key', 'INVALID_API_KEY', 401);
  }
}

// agent JWTs are ONE-TIME tokens (jti burned on first
// presentation). Reuse used to bucket into INVALID_API_KEY, which sent
// integrators auditing vaulted provider keys and inventing consistency
// theories; a whole incident report got filed against a client that
// cached its JWT. Distinct error so the message carries the fix. No
// enumeration risk: the caller already holds the signed token — telling
// them it was already spent reveals nothing they didn't do themselves.
export class AgentJwtReplayedError extends StackError {
  constructor() {
    super(
      'Agent JWT already used - mint a fresh JWT for every request (one JWT = one request; re-sign on retries, never resend the same Authorization header)',
      'AGENT_JWT_REPLAYED',
      401,
    );
  }
}

// A plan allowance (agents, members, service connections) the caller is at.
export class TierLimitExceededError extends StackError {
  constructor(resource: string, limit: number) {
    super(
      `${resource} limit reached (${limit}). Upgrade your plan to continue.`,
      'TIER_LIMIT_EXCEEDED',
      403,
    );
  }
}

// operate-vs-govern step-up. A gated governance action was
// attempted from a Bearer-credential context without an approved
// governance approval. The message carries the retry protocol: the
// human approves at the dashboard URL, the caller retries the SAME
// request with X-Governance-Approval. The approval id is deliberately
// safe to surface in an LLM context: it is worthless without the
// server-side approved state + the same operator's credential + an
// exact payload-hash match.
export class GovernanceApprovalRequiredError extends StackError {
  /** approver 'partner': the caller is a white-label tenant, whose partner's admin decides in the partner's STACK console. */
  constructor(approvalId: string, approvalUrl: string, approver: 'operator' | 'partner' = 'operator') {
    const ask = approver === 'partner'
      ? `Ask your partner to approve request ${approvalId} in their STACK console`
      : `Ask the operator to approve request ${approvalId} at ${approvalUrl}`;
    super(
      `This action loosens a safety control and requires human approval. ${ask}, then retry the same call with header X-Governance-Approval: ${approvalId}`,
      'GOVERNANCE_APPROVAL_REQUIRED',
      403,
      { approval_id: approvalId, approval_url: approvalUrl },
    );
  }
}

/** Where a governance approval a retry named stands, when it cannot be used: still waiting, declined, or out of time. */
export type GovernanceApprovalExit = 'pending' | 'rejected' | 'expired';

const GOVERNANCE_APPROVAL_EXIT_CODES: Readonly<Record<GovernanceApprovalExit, string>> = {
  pending: 'GOVERNANCE_APPROVAL_PENDING',
  rejected: 'GOVERNANCE_APPROVAL_REJECTED',
  expired: 'GOVERNANCE_APPROVAL_EXPIRED',
};

/**
 * A retry named a governance approval that cannot be used yet or any more. Each end has its own code, so a client
 * knows whether to wait (`GOVERNANCE_APPROVAL_PENDING`) or ask again (`_REJECTED`, `_EXPIRED`) without reading the
 * message. Still 403, as every refused governance retry is.
 */
export class GovernanceApprovalStateError extends StackError {
  constructor(approvalId: string, exit: GovernanceApprovalExit, message: string) {
    super(message, GOVERNANCE_APPROVAL_EXIT_CODES[exit], 403, { approval_id: approvalId, status: exit });
    this.name = 'GovernanceApprovalStateError';
  }
}

// a machine whose database/Redis went unreachable was
// converting every auth-path lookup failure into INVALID_API_KEY,
// which reads as "your credential is bad" when the truth is "this
// instance is sick, retry". Infrastructure failures on the auth path
// fail CLOSED but RETRIABLE with this 503 instead. Generic on purpose:
// any dependency outage that should tell the caller "not you, us -
// try again" can reuse it.
/** Seconds a caller is told to wait before retrying a SERVICE_UNAVAILABLE. */
export const SERVICE_UNAVAILABLE_RETRY_AFTER_SECONDS = 5;

/**
 * A backing service STACK depends on (Redis, the database) is unreachable. The
 * call fails closed but is retriable: the answer is 503 with a `Retry-After`
 * header and `details.retry_after_seconds`, so a client can tell this apart
 * from a refused credential.
 */
export class ServiceUnavailableError extends StackError {
  constructor(
    message = 'Service temporarily unavailable, please retry',
    retryAfterSeconds = SERVICE_UNAVAILABLE_RETRY_AFTER_SECONDS,
  ) {
    super(message, 'SERVICE_UNAVAILABLE', 503, { retry_after_seconds: retryAfterSeconds });
  }
}

/**
 * A connection of a service that is called with an OAuth access token holds none: it was connected with fields that carry
 * no token. Retrying can never help, so this is a client error with its own code and no retry hint; the connection has to
 * be made again.
 */
export class ConnectionNoAccessTokenError extends StackError {
  constructor() {
    super(
      'This connection has no usable access token, so the service cannot be called through it. Reconnect the service to fix it.',
      'CONNECTION_NO_ACCESS_TOKEN',
      409,
    );
  }
}

/**
 * True when `err` is the Redis client reporting that it cannot reach the
 * server: ioredis gives up a command after its retry budget
 * (`MaxRetriesPerRequestError`), refuses it while disconnected, or times it
 * out. A Redis reply error (a wrong type, a script error) is a bug, not an
 * outage, and is not matched.
 */
export function isRedisUnavailableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if (err.name === 'MaxRetriesPerRequestError' || err.name === 'ClusterAllFailedError') return true;
  return /^(Connection is closed\.?|Stream isn't writeable and enableOfflineQueue options is false|Command timed out)$/.test(err.message);
}

/**
 * The account a call is billed to is not active: a white-label tenant whose
 * partner is suspended, deleted or no longer a partner. Nothing is charged to
 * anyone and the tenant's own wallet is never used instead.
 */
export class BillingAccountInactiveError extends StackError {
  constructor(message = "This account's billing account is not active") {
    super(message, 'BILLING_ACCOUNT_INACTIVE', 403);
  }
}

/** What an account of a partner is told when its partner's card check is not finished, so no agent account can open yet. */
export const PARTNER_CARD_CHECK_NOT_FINISHED_MESSAGE =
  "The partner's card check is not finished. Agent accounts can be opened once it is.";

export class OperatorSuspendedError extends StackError {
  constructor(reason?: string) {
    super(
      reason ? `Account suspended: ${reason}` : 'Account suspended',
      'OPERATOR_SUSPENDED',
      403,
    );
  }
}

export class OperatorDeletedError extends StackError {
  constructor() {
    super('Account deleted', 'OPERATOR_DELETED', 403);
  }
}

// Passport
export class PassportExpiredError extends StackError {
  constructor() {
    super('Passport has expired', 'PASSPORT_EXPIRED', 401);
  }
}

export class PassportRevokedError extends StackError {
  constructor() {
    super('Passport has been revoked', 'PASSPORT_REVOKED', 401);
  }
}

/** A token presented as a Passport that is not one of this deployment's: unreadable, tampered, another audience or issuer. Not a revocation. */
export class PassportInvalidError extends StackError {
  constructor() {
    super('Passport is not valid', 'PASSPORT_INVALID', 401);
  }
}

export class DelegationDepthExceededError extends StackError {
  constructor() {
    super('Maximum delegation depth exceeded', 'DELEGATION_DEPTH_EXCEEDED', 400);
  }
}

export class ScopeEscalationError extends StackError {
  // #7 — optional detail so the caller can SEE what went wrong: which
  // scopes were rejected and what the parent (connection/service) actually
  // allows. Previously this threw an opaque "Child scope cannot exceed parent"
  // with no way to discover the parent set (there was no read-back either).
  // Backward-compatible: no-arg construction still works; code stays stable
  // ('SCOPE_ESCALATION') per the shared-error-code invariant.
  constructor(detail?: { requested_invalid?: string[]; parent_scopes?: string[] }) {
    const base = 'Child scope cannot exceed parent scope';
    const msg =
      detail && (detail.requested_invalid?.length || detail.parent_scopes)
        ? `${base}. Rejected: [${(detail.requested_invalid ?? []).join(', ')}]. ` +
          `Allowed (parent): [${(detail.parent_scopes ?? []).join(', ')}]` +
          `${(detail.parent_scopes ?? []).includes('*') ? '' : " (use '*' to allow any)"}.`
        : base;
    super(msg, 'SCOPE_ESCALATION', 400, detail);
  }
}

/**
 * A new or revised policy allows a send without naming who receives it.
 * `details.rules` lists each offending rule, the intents involved and the
 * recipient fields left unbound. See findUnboundSendRules.
 */
export class UnboundedSendRuleError extends StackError {
  constructor(message: string, details: Record<string, unknown>) {
    super(message, 'UNBOUNDED_SEND_RULE', 400, details);
  }
}

// Request shape
//
// A request that is malformed in a way a Zod schema cannot express (a body
// the handler can only judge after reading other state, a callback whose
// state is stale). Schema failures never use these: a ZodError reaches the
// error handler on its own and becomes VALIDATION_ERROR.
export class InvalidRequestError extends StackError {
  constructor(message = 'Invalid request', details?: Record<string, unknown>) {
    super(message, 'INVALID_REQUEST', 400, details);
  }
}

export class InvalidJsonError extends StackError {
  constructor(message = 'Request body is not valid JSON') {
    super(message, 'INVALID_JSON', 400);
  }
}

// Raised by webhook receivers whose sender authenticates with a signature
// header. The message names which check failed; it never carries the
// expected or received signature.
export class InvalidWebhookSignatureError extends StackError {
  constructor(message = 'Invalid webhook signature') {
    super(message, 'INVALID_WEBHOOK_SIGNATURE', 400);
  }
}

// The deployment has the route but not the integration behind it (for
// example billing without a payment provider key). 501 because the server
// does not support the operation as configured, which a retry cannot fix.
export class NotConfiguredError extends StackError {
  /** The vault service whose credential is missing (`stripe`, for example): never on the wire, read by the API's error counting. */
  readonly service: string | undefined;

  constructor(feature: string, service?: string) {
    super(`${feature} is not configured`, 'NOT_CONFIGURED', 501);
    this.service = service;
  }
}

// A webhook event was authentic but processing it failed. 500 on purpose:
// the sender's retry machinery is what recovers from a transient failure.
export class WebhookHandlerFailedError extends StackError {
  constructor(eventType: string) {
    super('Webhook handler failed', 'WEBHOOK_HANDLER_FAILED', 500, { event_type: eventType });
  }
}

export class RateLimitedError extends StackError {
  constructor(message = 'Too many requests', details?: Record<string, unknown>) {
    super(message, 'RATE_LIMITED', 429, details);
  }
}

// Resources
export class NotFoundError extends StackError {
  constructor(resource: string, id: string) {
    super(`${resource} not found: ${id}`, 'NOT_FOUND', 404);
  }
}

/**
 * A message cannot be answered under a rule that sends only to who wrote it, because who wrote it could not be verified (a
 * received email whose receiving server did not vouch for its sender). Nothing is pinned and nothing is sent.
 */
export class MessageSenderUnverifiedError extends StackError {
  constructor() {
    super('The sender of this message could not be verified, so it cannot be answered here.', 'MESSAGE_SENDER_NOT_VERIFIED', 422);
  }
}

export class ConflictError extends StackError {
  constructor(message: string) {
    super(message, 'CONFLICT', 409);
  }
}

/**
 * A call named a service that the account holds more than one connection to, and nothing said which. `connections` is
 * the caller's own eligible set only (never another connection of the account), so a refusal reveals nothing the caller
 * could not already use. Nothing was decrypted and nothing was sent.
 */
export class ConnectionAmbiguousError extends StackError {
  constructor(provider: string, connections: ReadonlyArray<{ id: string; name: string }>) {
    super(
      `More than one connection of "${provider}" is available to this caller: pass \`connection\` with one of their names or ids.`,
      'CONNECTION_AMBIGUOUS',
      409,
      { connections: connections.map((c) => ({ id: c.id, name: c.name })) },
    );
  }
}

/**
 * A cap of the Mission paused it: every action under it is refused until its owner raises the limit, lets it continue
 * or closes it. Nothing was revoked, and the action did not run.
 */
export class MissionPausedError extends StackError {
  constructor(missionId: string, cap: string | null) {
    super(
      'This Mission is paused because it reached one of its limits. Its owner can raise the limit, let it continue or close it.',
      'MISSION_PAUSED',
      403,
      { mission_id: missionId, ...(cap ? { cap } : {}) },
    );
    this.name = 'MissionPausedError';
  }
}

/** The owner asked for something only a Mission a cap paused can take (a review), and this one is not paused. */
export class MissionNotPausedError extends StackError {
  constructor(missionId: string) {
    super('This Mission is not paused, so there is nothing to review.', 'MISSION_NOT_PAUSED', 409, { mission_id: missionId });
    this.name = 'MissionNotPausedError';
  }
}

// Drop-off
export class DropoffExpiredError extends StackError {
  constructor(id: string) {
    super(`Drop-off has expired: ${id}`, 'DROPOFF_EXPIRED', 410);
  }
}

export class DropoffAlreadyCollectedError extends StackError {
  /**
   * `collectedBy` names the agent that took it, when it is known: a drop-off that names several agents is taken by
   * the first to collect, and the others are told who that was.
   */
  constructor(id: string, collectedBy?: { agent_id: string; name: string | null }) {
    super(
      collectedBy
        ? `Drop-off already collected: ${id}. Taken by ${collectedBy.name ? `${collectedBy.name} (${collectedBy.agent_id})` : collectedBy.agent_id}`
        : `Drop-off already collected: ${id}`,
      'DROPOFF_ALREADY_COLLECTED',
      409,
      collectedBy ? { dropoff_id: id, collected_by: collectedBy } : undefined,
    );
  }
}

export class SchemaValidationError extends StackError {
  constructor(details: Record<string, unknown>) {
    super('Package does not conform to declared schema', 'SCHEMA_VALIDATION_FAILED', 400, details);
  }
}

// Accountability
export class PassportBlockedError extends StackError {
  constructor(agentId: string) {
    super(
      `Agent ${agentId} is blocked from passport issuance pending review`,
      'PASSPORT_BLOCKED',
      403,
    );
  }
}

export class AccountabilityRequiredError extends StackError {
  constructor(field: string) {
    super(
      `Intent declaration required: missing ${field}`,
      'ACCOUNTABILITY_REQUIRED',
      400,
    );
  }
}

export class CheckpointNotAvailableError extends StackError {
  constructor() {
    super(
      'Checkpoints are not available for standard-mode passports',
      'CHECKPOINT_NOT_AVAILABLE',
      404,
    );
  }
}

export class DelegationAccountabilityError extends StackError {
  constructor(parentMode: string, childMode: string) {
    super(
      `Cannot delegate from ${parentMode} agent to ${childMode} agent. Delegation cannot reduce accountability.`,
      'DELEGATION_ACCOUNTABILITY_VIOLATION',
      400,
    );
  }
}

// Identity
export class IdentityRequirementsError extends StackError {
  constructor(unmetRequirements: string) {
    super(
      `Identity requirements not met: ${unmetRequirements}`,
      'IDENTITY_REQUIREMENTS_NOT_MET',
      403,
      { unmet: unmetRequirements },
    );
  }
}

// A public JWKS was requested for an agent or operator that has no published
// key. 404 for "unknown subject" and "no key" alike, so a verifier cache never
// stores an empty key set and a prober learns nothing about which ids exist.
export class SigningKeyUnavailableError extends StackError {
  constructor(subject: 'agent' | 'operator', id: string) {
    super(`${subject} has no signing key available`, 'SIGNING_KEY_UNAVAILABLE', 404, { [`${subject}_id`]: id });
  }
}

// An operator tried to create a second identity configuration where only one
// may exist (an OIDC identity provider per operator, a SPIFFE trust domain or
// WIMSE issuer per operator and URI). `existing_id` lets the caller go and
// update the row that is already there.
const IDENTITY_CONFIG_EXISTS_CODES = {
  oidc: 'OIDC_CONFIG_EXISTS',
  spiffe: 'TRUST_DOMAIN_EXISTS',
  wimse: 'WIMSE_ISSUER_EXISTS',
} as const;

export class IdentityConfigExistsError extends StackError {
  constructor(kind: keyof typeof IDENTITY_CONFIG_EXISTS_CODES, message: string, existingId: string) {
    super(message, IDENTITY_CONFIG_EXISTS_CODES[kind], 409, { existing_id: existingId });
  }
}

// Mission binding for workload-issued Passports: every Passport minted from a
// workload token is bound to one live Mission the operator opened for it.
export class MissionRequiredError extends StackError {
  constructor(message = 'Body must carry mission_id: the ms_* id of a live Mission for this workload (open one with POST /v1/missions)') {
    super(message, 'MISSION_REQUIRED', 400);
  }
}

// Workload attestation (SPIFFE JWT-SVID and WIMSE WIT presentation). The
// reason is the validator's failure code or one of the route's own checks;
// each maps to one stable wire code and one HTTP status. The set is closed so
// a new reason cannot ship without a code.
export const WORKLOAD_ATTESTATION_REASONS = {
  malformed_jwt: ['WORKLOAD_TOKEN_MALFORMED', 400],
  missing_sub: ['WORKLOAD_SUBJECT_MISSING', 400],
  missing_iss: ['WORKLOAD_ISSUER_MISSING', 400],
  invalid_spiffe_id: ['WORKLOAD_SPIFFE_ID_INVALID', 400],
  trust_domain_mismatch: ['WORKLOAD_TRUST_DOMAIN_MISMATCH', 400],
  issuer_mismatch: ['WORKLOAD_ISSUER_MISMATCH', 400],
  missing_kid: ['WORKLOAD_KEY_ID_MISSING', 400],
  unknown_kid: ['WORKLOAD_KEY_ID_UNKNOWN', 400],
  verify_failed: ['WORKLOAD_VERIFY_FAILED', 400],
  too_close_to_expiry: ['WORKLOAD_TOKEN_TOO_CLOSE_TO_EXPIRY', 400],
  expired: ['WORKLOAD_TOKEN_EXPIRED', 401],
  audience_mismatch: ['WORKLOAD_AUDIENCE_MISMATCH', 401],
  signature_invalid: ['WORKLOAD_SIGNATURE_INVALID', 401],
  not_configured: ['WORKLOAD_ISSUER_NOT_CONFIGURED', 401],
  not_mapped: ['WORKLOAD_IDENTITY_NOT_MAPPED', 403],
  jwks_unavailable: ['WORKLOAD_JWKS_UNAVAILABLE', 503],
  provider_unavailable: ['WORKLOAD_PROVIDER_UNAVAILABLE', 500],
} as const satisfies Record<string, readonly [string, number]>;

export type WorkloadAttestationReason = keyof typeof WORKLOAD_ATTESTATION_REASONS;

export class WorkloadAttestationError extends StackError {
  constructor(readonly reason: WorkloadAttestationReason, message: string) {
    const [code, status] = WORKLOAD_ATTESTATION_REASONS[reason];
    super(message, code, status);
    this.name = 'WorkloadAttestationError';
  }
}

// Single sign-on login (OIDC identity provider redirect flow). Every reason
// has one wire code and one status; the set is closed for the same reason as
// the workload table above.
export const SSO_LOGIN_REASONS = {
  browser_binding_required: ['BROWSER_BINDING_REQUIRED', 400],
  invalid_callback: ['SSO_CALLBACK_INVALID', 400],
  upstream_error: ['SSO_UPSTREAM_ERROR', 400],
  state_invalid: ['SSO_STATE_INVALID', 400],
  state_not_bound: ['SSO_STATE_NOT_BOUND', 400],
  login_failed: ['SSO_LOGIN_FAILED', 400],
  handoff_invalid: ['SSO_HANDOFF_INVALID', 401],
  provider_unavailable: ['SSO_PROVIDER_UNAVAILABLE', 503],
} as const satisfies Record<string, readonly [string, number]>;

export type SsoLoginReason = keyof typeof SSO_LOGIN_REASONS;

export class SsoLoginError extends StackError {
  constructor(readonly reason: SsoLoginReason, message: string) {
    const [code, status] = SSO_LOGIN_REASONS[reason];
    super(message, code, status);
    this.name = 'SsoLoginError';
  }
}

// Verified domains of single sign-on (spec/sso-login/SPEC.md section 9.5): the refusals of the calls that add, check
// and remove them. One wire code and status per reason. `unavailable` is the one answer for a domain another account
// holds and for one this account cannot take, so it never says who holds a name.
export const SSO_DOMAIN_REASONS = {
  invalid: ['SSO_DOMAIN_INVALID', 400],
  unavailable: ['SSO_DOMAIN_UNAVAILABLE', 409],
  limit_reached: ['SSO_DOMAIN_LIMIT_REACHED', 409],
} as const satisfies Record<string, readonly [string, number]>;

export type SsoDomainReason = keyof typeof SSO_DOMAIN_REASONS;

export class SsoDomainError extends StackError {
  constructor(readonly reason: SsoDomainReason, message: string) {
    const [code, status] = SSO_DOMAIN_REASONS[reason];
    super(message, code, status);
    this.name = 'SsoDomainError';
  }
}

// CMEK (Customer-Managed Encryption Keys)
//
// Raised when an AWS KMS API call returns AccessDeniedException — the
// customer has revoked STACK's IAM grant on their CMK. Every operator-
// scoped operation that needs to encrypt or decrypt fail-closes with
// 503 carrying this error code; the operator + customer-side admin
// remediation is to restore the IAM grant in the customer's AWS console.
//
// 503 (not 403) on purpose: the issue is a transient lack of access to
// an upstream service we depend on, not an authorization failure on
// the caller. Clients with retry logic will retry; the retries will
// also fail until the customer restores the grant.
export class CmekRevokedError extends StackError {
  constructor(operatorId: string, keyArn?: string) {
    super(
      'Customer-managed encryption key is unreachable. STACK no longer has KMS access — please restore the IAM grant on the configured CMK in your AWS console.',
      'CMEK_REVOKED',
      503,
      { operator_id: operatorId, ...(keyArn ? { key_arn: keyArn } : {}) },
    );
  }
}

// Raised when CmekService.enable() rejects the toggle-on request because
// the IAM-grant smoke test failed, the ARN is malformed, the operator
// is op_stack_system (dogfood carve-out), or the operator is not on
// the enterprise tier. 400 is the right code for all four — caller can
// surface the detail to the dashboard form.
export class CmekConfigurationError extends StackError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'CMEK_CONFIGURATION_INVALID', 400, details);
  }
}

// The control socket. A customer's decider (hosted, or their own server)
// refused an action, or gave no usable answer. Neither is charged: the action
// is handed back to the caller's allowance.

/**
 * The customer's decider said no. `retry.ref` names a pending approval the
 * retry may cite in `X-Control-Ref`. A refusal by a hosted policy also names
 * which rule refused (`rule`: the policy, its revision, the section and the
 * rule id), never a value the call carried.
 */
export class ControlDeniedError extends StackError {
  constructor(
    readonly decisionId: string,
    readonly reasonCode: string | null,
    reasonMessage: string | null,
    readonly retry: { ref: string; after_seconds?: number } | null,
    readonly rule: Record<string, unknown> | null = null,
  ) {
    super(
      reasonMessage ?? 'Your controls refused this action. Nothing was charged.',
      'CONTROL_DENIED',
      403,
      {
        decision_id: decisionId,
        reason_code: reasonCode,
        ...(retry ? { retry } : {}),
        ...(rule ? { rule } : {}),
      },
    );
    this.name = 'ControlDeniedError';
  }
}

/**
 * A limit of the customer's policy was reached while the action was being paid
 * for: a spend limit counted at the reservation (`window` day, month or
 * mission), or the most one action may cost (`window` action, with
 * `ceilingCents`). Nothing was reserved or charged and the action is handed back.
 */
export class ControlLimitExceededError extends StackError {
  constructor(
    readonly window: string,
    readonly limitUnit: string,
    readonly remaining: number,
    readonly ceilingCents: number | null = null,
    /** The counter that refused: a spend rule's (`spend:<rule id>`), or null for the account's shared window. */
    readonly scope: string | null = null,
    /** The Mission whose money cap refused (scope `mission_spend`), so its cap behaviour can follow. Never in the body. */
    readonly missionId: string | null = null,
  ) {
    super(
      ceilingCents !== null
        ? 'This action costs more than your controls allow for one action. Nothing was charged.'
        : scope === 'mission_spend' || scope?.startsWith('mission_spend@')
          ? "This action would pass the Mission's spend limit. Nothing was charged."
          : 'Your controls set a limit that this action would pass. Nothing was charged.',
      'CONTROL_LIMIT_EXCEEDED',
      403,
      {
        limit: { window, unit: limitUnit, ...(scope !== null ? { scope } : {}) },
        remaining,
        ...(ceilingCents !== null ? { max_per_action_cents: ceilingCents } : {}),
      },
    );
    this.name = 'ControlLimitExceededError';
  }
}

/**
 * The customer's control server gave no usable answer in time (no answer, a
 * bad signature, an error, an open breaker). The action is refused, never
 * charged, and handed back so the agent can retry once the server answers.
 * 403 and not 503, so a provider-compatible client does not retry it blindly.
 */
export class ControlSocketUnavailableError extends StackError {
  constructor(readonly decisionId: string, readonly unavailableCause: string) {
    super(
      'Your control server did not answer in time, so this action was refused. Nothing was charged; retry once it answers, or fix or remove the control server in the console.',
      'CONTROL_SOCKET_UNAVAILABLE',
      403,
      { decision_id: decisionId, cause: unavailableCause },
    );
    this.name = 'ControlSocketUnavailableError';
  }
}

/** STACK's own hosted controls could not decide. Nothing ran and nothing was charged. */
export class ControlUnavailableError extends StackError {
  constructor(readonly decisionId: string) {
    super(
      "STACK's hosted controls could not decide this action just now, so it was refused. Nothing was charged; retry in a moment.",
      'CONTROL_UNAVAILABLE',
      503,
      { decision_id: decisionId },
      { stackSide: true },
    );
    this.name = 'ControlUnavailableError';
  }
}

/**
 * A feature this self-managed install has no licence for: no key, an expired
 * one, or a key that does not cover it. 402 like the platform subscription:
 * the fix is a licence, not a different request.
 */
export class LicenceRequiredError extends StackError {
  constructor(
    featureLabel: string,
    details: { feature: string; licence: 'none' | 'invalid' | 'expired' | 'valid' },
  ) {
    super(
      `This feature needs a STACK licence that includes ${featureLabel}. Set STACK_LICENCE_KEY to a current licence key.`,
      'LICENCE_REQUIRED',
      402,
      details,
    );
    this.name = 'LicenceRequiredError';
  }
}

/** Hosted controls are not on for this customer, so they cannot be chosen. */
export class ControlsNotEnabledError extends StackError {
  constructor() {
    super(
      'Hosted controls are not on for this account. Turn them on in the STACK console, or use your own control server.',
      'CONTROLS_NOT_ENABLED',
      409,
    );
    this.name = 'ControlsNotEnabledError';
  }
}

/**
 * What a customer without controls is refused, by kind: reading the record (the audit record, evidence packs, Mission
 * dossiers and replay, signed records, passport reports, operator-review downloads), the detector settings, control
 * policies and their simulation, control reviews, PII redaction settings, the list of Missions, fleets and pending
 * intent checks, and the caps on an agent wallet.
 */
export const CONTROLS_REQUIRED_FEATURES = [
  'record',
  'detector_settings',
  'policies',
  'reviews',
  'pii_settings',
  'detector_reads',
  'missions',
  'fleets',
  'intent_checks',
  'wallet_caps',
  'budget',
] as const;
export type ControlsRequiredFeature = (typeof CONTROLS_REQUIRED_FEATURES)[number];

const CONTROLS_REQUIRED_MESSAGES: Record<ControlsRequiredFeature, string> = {
  record:
    'Reading the record needs controls. STACK keeps the record either way: switch controls on in billing to read all of it, including everything from before.',
  detector_settings: 'Changing detector settings needs controls. Switch controls on in billing.',
  policies: 'Control policies need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
  reviews: 'Control reviews need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
  pii_settings: 'PII redaction settings need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
  detector_reads: 'Detector settings need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
  missions: 'Listing Missions needs controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
  fleets: 'Fleets need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
  wallet_caps: 'Wallet caps need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page. Without controls the wallet has no cap and its balance is the limit.',
  budget: "An agent account's monthly budget needs controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page. Without controls the account's limit is its prepaid credit.",
  intent_checks: 'Pending intent checks need controls, and controls are off for this account. The owner switches them on in the Console, at the Billing page.',
};

/**
 * The customer has no controls, and this is a controls feature. 402 like the platform subscription: the fix is to switch
 * controls on, not a different request. STACK still writes the record for every account; only reading it is refused.
 */
export class ControlsRequiredError extends StackError {
  constructor(feature: ControlsRequiredFeature) {
    super(CONTROLS_REQUIRED_MESSAGES[feature], 'CONTROLS_REQUIRED', 402, { feature });
    this.name = 'ControlsRequiredError';
  }
}

/** The address was refused (not https, an internal host) or its setup check failed. */
export class ControlSocketAddressError extends StackError {
  constructor(message: string, readonly addressCause: string) {
    super(message, 'CONTROL_SOCKET_ADDRESS_REFUSED', 400, { cause: addressCause });
    this.name = 'ControlSocketAddressError';
  }
}

/**
 * Base of every refusal to spend that an install with a prepaid balance raises
 * (not enough credit, a frozen wallet). The API's error handler
 * maps this one class to 402, so an engine path that meets a hosted refusal
 * answers it without knowing the wallet that raised it.
 *
 * What the caller is told is `refusal`, fixed when the error is raised: the
 * handler answers from it and never from `message` or `details`, which a
 * catch block may have rewritten on the way up, so a refusal carries a balance
 * and nothing else.
 */
export class SpendRefusedError extends StackError {
  readonly refusal: Readonly<{ code: string; message: string; details?: Readonly<Record<string, unknown>> }>;

  constructor(message: string, code: string, details?: Record<string, unknown>) {
    super(message, code, 402, details);
    this.name = 'SpendRefusedError';
    this.refusal = Object.freeze({
      code,
      message,
      ...(details ? { details: Object.freeze({ ...details }) } : {}),
    });
  }
}

/**
 * Base of a spend whose settlement is still pending: the money was authorised
 * but its capture has not been recorded, so the caller is asked to retry rather
 * than refused.
 */
export class SpendSettlementPendingError extends StackError {
  constructor(message: string, code: string, details?: Record<string, unknown>) {
    super(message, code, 503, details);
    this.name = 'SpendSettlementPendingError';
  }
}

/**
 * A cost cap (`X-Max-Cost-Cents`) below a call's worst case, for a deployment that refuses such a call. STACK's own key lowers
 * the hold to the cap instead, and a call on the customer's own provider key ignores the header: the provider bills that call
 * and STACK holds nothing for it. Refused before anything is held or sent.
 */
export class ModelCostCapError extends StackError {
  constructor(reason: 'cost_cap_exceeded', message: string, details: Record<string, unknown> = {}) {
    super(message, 'MODEL_COST_CAP', 422, { reason, ...details });
    this.name = 'ModelCostCapError';
  }
}

/**
 * A call to OpenRouter's API that the gateway does not send on STACK's own key: an endpoint of the OpenRouter ACCOUNT
 * (its keys, credits, files, batches, presets and the rest) or one the gateway does not know. STACK's key is one
 * OpenRouter account shared by every agent account, so these are not an agent account's to use; on the customer's
 * own OpenRouter key every endpoint passes. Refused before anything is counted, held or sent.
 */
export class OpenRouterEndpointRefusedError extends StackError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, 'OPENROUTER_ENDPOINT_REFUSED', 403, details);
    this.name = 'OpenRouterEndpointRefusedError';
  }
}

/**
 * An image asked of a provider that has no image generation endpoint (Anthropic), or of a caller whose model calls
 * cannot make one. Refused before anything is sent or counted; the message says where the image can be made.
 */
export class ImageNotSupportedError extends StackError {
  constructor(provider: string, message: string) {
    super(message, 'IMAGE_NOT_SUPPORTED', 422, { provider });
    this.name = 'ImageNotSupportedError';
  }
}
