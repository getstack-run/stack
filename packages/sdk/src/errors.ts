export class StackError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status: number,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'StackError';
  }
}

export class NotFoundError extends StackError {
  constructor(resource: string, id: string) {
    super(`${resource} ${id} not found`, 'NOT_FOUND', 404);
    this.name = 'NotFoundError';
  }
}

export class ForbiddenError extends StackError {
  constructor(message = 'Forbidden') {
    super(message, 'FORBIDDEN', 403);
    this.name = 'ForbiddenError';
  }
}

/**
 * A passport refresh was refused because the passport's Mission is no
 * longer live. Every passport is bound to one Mission and never outlives
 * it, so retrying cannot succeed: open a new Mission and issue a new
 * passport (or call `missions.start`). `refusal` holds the API error.
 */
export class MissionNotLiveError extends StackError {
  constructor(
    public readonly missionId: string | null,
    public readonly state: 'completed' | 'revoked' | 'expired' | 'not_found' | 'unbound',
    public readonly refusal: StackError,
  ) {
    super(
      missionId
        ? `Cannot refresh the passport: Mission ${missionId} is ${state === 'not_found' ? 'not found' : state}. Open a new Mission and issue a new passport.`
        : 'Cannot refresh the passport: it is not bound to exactly one live Mission. Open a Mission and issue a new passport.',
      'MISSION_NOT_LIVE',
      refusal.status,
      refusal.details,
    );
    this.name = 'MissionNotLiveError';
  }
}

export class ValidationError extends StackError {
  constructor(message: string, details?: unknown) {
    super(message, 'VALIDATION_ERROR', 400, details);
    this.name = 'ValidationError';
  }
}

/** The `details` object of an API error, given either the whole envelope or the details. */
function errorDetails(details: unknown): Record<string, unknown> {
  if (!details || typeof details !== 'object') return {};
  const inner = (details as { error?: { details?: unknown } }).error?.details;
  const source = inner !== undefined ? inner : details;
  return source && typeof source === 'object' ? (source as Record<string, unknown>) : {};
}

const text = (value: unknown): string => (typeof value === 'string' ? value : '');

/**
 * 403 `GOVERNANCE_APPROVAL_REQUIRED`: the call needs a human's approval. Send
 * the person to `approvalUrl`; once approved, retry the same call with the
 * same input and `governanceApprovalId: approvalId`.
 */
export class GovernanceApprovalRequiredError extends StackError {
  readonly approvalId: string;
  readonly approvalUrl: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'GOVERNANCE_APPROVAL_REQUIRED', status, details);
    this.name = 'GovernanceApprovalRequiredError';
    const fields = errorDetails(details);
    this.approvalId = text(fields['approval_id']);
    this.approvalUrl = text(fields['approval_url']);
  }
}

/**
 * 403 `GOVERNANCE_APPROVAL_PENDING`, `GOVERNANCE_APPROVAL_REJECTED` or `GOVERNANCE_APPROVAL_EXPIRED`: a retry named an
 * approval that cannot be used. Pending: wait for the person and retry. Rejected or expired: ask for a new one by making
 * the call again without the approval. `approvalStatus` is `pending`, `rejected` or `expired`.
 */
export class GovernanceApprovalStateError extends StackError {
  readonly approvalId: string;
  readonly approvalStatus: string;
  constructor(message: string, code: string, status: number, details?: unknown) {
    super(message, code, status, details);
    this.name = 'GovernanceApprovalStateError';
    const fields = errorDetails(details);
    this.approvalId = text(fields['approval_id']);
    this.approvalStatus = text(fields['status']);
  }
}

/** 409 `ACCOUNT_PIECE_NOT_READY`: a piece of the agent account is not ready; read the account to follow it. */
export class AccountPieceNotReadyError extends StackError {
  readonly accountId: string;
  readonly piece: string;
  readonly state: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'ACCOUNT_PIECE_NOT_READY', status, details);
    this.name = 'AccountPieceNotReadyError';
    const fields = errorDetails(details);
    this.accountId = text(fields['account_id']);
    this.piece = text(fields['piece']);
    this.state = text(fields['state']);
  }
}

/** 402 `AGENT_BUDGET_EXCEEDED`: the agent has reached its monthly budget. */
export class AgentBudgetExceededError extends StackError {
  readonly accountId: string;
  readonly remainingCents: number;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'AGENT_BUDGET_EXCEEDED', status, details);
    this.name = 'AgentBudgetExceededError';
    const fields = errorDetails(details);
    this.accountId = text(fields['account_id']);
    const remaining = fields['remaining_cents'];
    this.remainingCents = typeof remaining === 'number' ? remaining : 0;
  }
}

/** 403 `RECIPIENT_OPTED_OUT`: the number asked not to be contacted, so it is on the customer's do-not-contact list and texts and calls to it are refused. */
export class RecipientOptedOutError extends StackError {
  readonly accountId: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'RECIPIENT_OPTED_OUT', status, details);
    this.name = 'RecipientOptedOutError';
    this.accountId = text(errorDetails(details)['account_id']);
  }
}

/**
 * 422 `DESTINATION_NOT_AVAILABLE`: texts and calls to this number are not available. `reason` is `no_price` (Twilio has
 * no price for the destination, so STACK cannot charge it at cost) or `refused_by_twilio` (Twilio's own geographic
 * permissions or high-risk number blocking do not allow it from this account's number). Nothing was charged.
 */
export class DestinationNotAvailableError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'DESTINATION_NOT_AVAILABLE', status, details);
    this.name = 'DestinationNotAvailableError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/** 503 `BROWSER_TIME_USED_UP`: the browser time STACK has for this month is spent. Nothing was charged; browsers are available again when the month turns. */
export class BrowserTimeUsedUpError extends StackError {
  readonly provider: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'BROWSER_TIME_USED_UP', status, details);
    this.name = 'BrowserTimeUsedUpError';
    this.provider = text(errorDetails(details)['provider']);
  }
}

/** 503 `BROWSER_SESSION_LENGTH_REFUSED`: the browser plan does not allow a session this long. Nothing was charged; retrying does not help. */
export class BrowserSessionLengthRefusedError extends StackError {
  readonly provider: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'BROWSER_SESSION_LENGTH_REFUSED', status, details);
    this.name = 'BrowserSessionLengthRefusedError';
    this.provider = text(errorDetails(details)['provider']);
  }
}

/** 503 `PROVIDER_CAPACITY_UNAVAILABLE`: a provider declined STACK's own account, or STACK paused its own spend at Twilio. Nothing was charged; retry in a few minutes. */
export class ProviderCapacityUnavailableError extends StackError {
  readonly provider: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'PROVIDER_CAPACITY_UNAVAILABLE', status, details);
    this.name = 'ProviderCapacityUnavailableError';
    this.provider = text(errorDetails(details)['provider']);
  }
}

/**
 * `ACCOUNT_CALL_FAILED`: the call did not go through. When `retryable` (502)
 * the call may have been placed: read the account's calls before retrying.
 * Otherwise (422) the provider refused it.
 */
export class AccountCallFailedError extends StackError {
  readonly reason: string;
  readonly retryable: boolean;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'ACCOUNT_CALL_FAILED', status, details);
    this.name = 'AccountCallFailedError';
    this.reason = text(errorDetails(details)['reason']);
    this.retryable = status === 502;
  }
}


/** 422 `TOOL_PRICE_REFUSED`: a paid tool run refused before it is held (`max_results` out of range, an input too deep). Nothing was held or charged. */
export class ToolPriceRefusedError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'TOOL_PRICE_REFUSED', status, details);
    this.name = 'ToolPriceRefusedError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/** 503 `TOOLS_UNAVAILABLE`: paid tools are unavailable on STACK's side. Nothing was charged; retry later. */
export class ToolsUnavailableError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'TOOLS_UNAVAILABLE', status, details);
    this.name = 'ToolsUnavailableError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/** 503 `MAKING_UNAVAILABLE`: making cannot serve the call on STACK's or a supplier's side. Nothing was ordered or charged; retry later. */
export class MakingUnavailableError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'MAKING_UNAVAILABLE', status, details);
    this.name = 'MakingUnavailableError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/** 400 `TOOL_RUN_REJECTED`: the tool provider refused the request; inspect the endpoint's schema. Nothing was charged. */
export class ToolRunRejectedError extends StackError {
  readonly providerStatus: number | null;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'TOOL_RUN_REJECTED', status, details);
    this.name = 'ToolRunRejectedError';
    const providerStatus = errorDetails(details)['provider_status'];
    this.providerStatus = typeof providerStatus === 'number' ? providerStatus : null;
  }
}

/**
 * 403 `BUDGET_NEEDS_CONTROLS`: a per-agent monthly budget needs controls. Open
 * the account without `monthly_budget_cents` (prepaid credit is its limit), or
 * turn on controls first.
 */
export class BudgetNeedsControlsError extends StackError {
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'BUDGET_NEEDS_CONTROLS', status, details);
    this.name = 'BudgetNeedsControlsError';
  }
}

/**
 * 402 `PLATFORM_SUBSCRIPTION_REQUIRED`: every agent call, an agent account's
 * or not, needs the platform subscription trialing or active (a contract plan
 * never does). `subscriptionStatus` is its status now (none, incomplete,
 * lapsed or canceled). The error's details carry how to start it
 * (`subscribe.api`, `subscribe.cli`, `subscribe.url`).
 */
export class PlatformSubscriptionRequiredError extends StackError {
  readonly subscriptionStatus: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'PLATFORM_SUBSCRIPTION_REQUIRED', status, details);
    this.name = 'PlatformSubscriptionRequiredError';
    this.subscriptionStatus = text(errorDetails(details)['status']);
  }
}

/**
 * 429 `SHARED_MAIL_DAILY_LIMIT`: the customer's agents have reached `limit` recipients
 * today (UTC) on the shared agent domain; every To, Cc and Bcc address counts, not each email. The limit is
 * 20 for a customer's first 14 days and 100 after. It resets at midnight UTC; inboxes
 * on an own verified domain have no STACK daily limit.
 */
export class SharedMailDailyLimitError extends StackError {
  readonly limit: number;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'SHARED_MAIL_DAILY_LIMIT', status, details);
    this.name = 'SharedMailDailyLimitError';
    const limit = errorDetails(details)['limit'];
    this.limit = typeof limit === 'number' ? limit : 0;
  }
}

/**
 * A Telegram send STACK refused before anything left. `reason` says why:
 * `no_bot` (the agent has no bot), `chat_unknown` (the chat never wrote to the
 * bot: a Telegram bot cannot message a chat first), `chat_blocked`,
 * `bot_unavailable` (Telegram no longer accepts the bot's token).
 * Nothing was sent.
 */
export class TelegramSendRefusedError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'TELEGRAM_SEND_REFUSED', status, details);
    this.name = 'TelegramSendRefusedError';
    const reason = errorDetails(details)['reason'];
    this.reason = typeof reason === 'string' ? reason : 'unknown';
  }
}

/**
 * 413 `EMAIL_ATTACHMENTS_TOO_LARGE`: the files attached to an email come to more than the mail provider takes in one
 * message (`limitBytes`, 25 MB). Nothing was sent. Attach fewer or smaller files, or send a share link.
 */
export class EmailAttachmentsTooLargeError extends StackError {
  readonly totalBytes: number;
  readonly limitBytes: number;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'EMAIL_ATTACHMENTS_TOO_LARGE', status, details);
    this.name = 'EmailAttachmentsTooLargeError';
    const fields = errorDetails(details);
    const total = fields['total_bytes'];
    const limit = fields['limit_bytes'];
    this.totalBytes = typeof total === 'number' ? total : 0;
    this.limitBytes = typeof limit === 'number' ? limit : 0;
  }
}

/**
 * 422 `EMAIL_MESSAGE_NOT_ANSWERABLE`: a reply or forward names a message that cannot be answered. `reason` is
 * `not_email`, `withheld`, `not_received` (the account sent it) or `no_sender` (its From names no address).
 * Nothing was sent.
 */
export class EmailMessageNotAnswerableError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'EMAIL_MESSAGE_NOT_ANSWERABLE', status, details);
    this.name = 'EmailMessageNotAnswerableError';
    const reason = errorDetails(details)['reason'];
    this.reason = typeof reason === 'string' ? reason : 'unknown';
  }
}

/** One policy rule that allows a send without naming who receives it (the `rules` of an `UnboundedSendRuleError`). */
export interface UnboundSendRuleFinding {
  ruleId: string;
  connectionId: string;
  provider: string | null;
  /** `unbound_recipient`, `implicit_recipient`, `unpinned_operation` or `unknown_intent`. */
  reason: string;
  /** The send intents involved. */
  intents: string[];
  /** The recipient fields that need an `eq` or `in` constraint. */
  unboundPaths: string[];
}

const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []);

/**
 * 400 `UNBOUNDED_SEND_RULE`: a new or revised policy allows a send without
 * naming who receives it. `rules` lists each offending rule; bind the recipient
 * fields, set the rule's `recipients` to `"per_mission"` so each Mission names
 * them, or set the rule to `review` or `deny`.
 */
export class UnboundedSendRuleError extends StackError {
  readonly rules: UnboundSendRuleFinding[];
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'UNBOUNDED_SEND_RULE', status, details);
    this.name = 'UnboundedSendRuleError';
    const rules = errorDetails(details)['rules'];
    this.rules = (Array.isArray(rules) ? rules : []).map((rule) => {
      const fields = rule && typeof rule === 'object' ? (rule as Record<string, unknown>) : {};
      return {
        ruleId: text(fields['rule_id']),
        connectionId: text(fields['connection_id']),
        provider: typeof fields['provider'] === 'string' ? fields['provider'] : null,
        reason: text(fields['reason']),
        intents: strings(fields['intents']),
        unboundPaths: strings(fields['unbound_paths']),
      };
    });
  }
}

/** Which rule of a policy refused an action. Never a value from the call. */
export interface ControlRefusalRuleDetails {
  policyId: string;
  policyRevision: number;
  /** The part of the policy: `connections`, `actions`, `recipients`, `spend`, `review`, `models`, `browser`, `card`, `wallet`, `sandbox` or `tools`. */
  section: string;
  /** The rule that refused: a connection rule id, or the policy field. */
  rule: string;
  /** The stable reason, for example `recipient_not_allowed`, `recipients_not_pinned` or `review_required`. */
  code: string;
  /** The policy's own side of the comparison (a limit, a list's size), never what the call carried. */
  detail: Record<string, string | number | boolean | null> | null;
}

/**
 * 403 `CONTROL_DENIED`: your controls refused the action. Nothing was charged.
 * `rule` says which rule of a hosted policy refused it (null when your own
 * decision server refused). An action held for a person carries `retry`: once
 * the person approves it, send the same action again with the header
 * `X-Control-Ref: <retry.ref>`.
 */
export class ControlDeniedError extends StackError {
  readonly decisionId: string;
  readonly reasonCode: string | null;
  readonly retry: { ref: string; afterSeconds: number | null } | null;
  readonly rule: ControlRefusalRuleDetails | null;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'CONTROL_DENIED', status, details);
    this.name = 'ControlDeniedError';
    const fields = errorDetails(details);
    this.decisionId = text(fields['decision_id']);
    this.reasonCode = typeof fields['reason_code'] === 'string' ? fields['reason_code'] : null;
    const retry = fields['retry'];
    const retryFields = retry && typeof retry === 'object' ? (retry as Record<string, unknown>) : null;
    this.retry =
      retryFields && typeof retryFields['ref'] === 'string'
        ? { ref: retryFields['ref'], afterSeconds: typeof retryFields['after_seconds'] === 'number' ? retryFields['after_seconds'] : null }
        : null;
    const rule = fields['rule'];
    const ruleFields = rule && typeof rule === 'object' ? (rule as Record<string, unknown>) : null;
    const detail = ruleFields?.['detail'];
    this.rule = ruleFields
      ? {
          policyId: text(ruleFields['policy_id']),
          policyRevision: typeof ruleFields['policy_revision'] === 'number' ? ruleFields['policy_revision'] : 0,
          section: text(ruleFields['section']),
          rule: text(ruleFields['rule']),
          code: text(ruleFields['code']),
          detail: detail && typeof detail === 'object' ? (detail as Record<string, string | number | boolean | null>) : null,
        }
      : null;
  }
}

/**
 * 403 `CONTROL_LIMIT_EXCEEDED`: a limit of your policy was reached while the
 * action was being paid for. Nothing was reserved or charged. `limit` is the
 * window (`day`, `month`, `mission` or `action`) and unit that was hit,
 * `remaining` what is left of it, and `maxPerActionCents` the most one action
 * may cost when that was the limit.
 */
export class ControlLimitExceededError extends StackError {
  /** `scope` names the spend rule's counter that refused (`spend:<rule id>`); absent for the account's shared windows. */
  readonly limit: { window: string; unit: string; scope?: string } | null;
  readonly remaining: number;
  readonly maxPerActionCents: number | null;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'CONTROL_LIMIT_EXCEEDED', status, details);
    this.name = 'ControlLimitExceededError';
    const fields = errorDetails(details);
    const limit = fields['limit'];
    const limitFields = limit && typeof limit === 'object' ? (limit as Record<string, unknown>) : null;
    this.limit = limitFields
      ? { window: text(limitFields['window']), unit: text(limitFields['unit']), ...(typeof limitFields['scope'] === 'string' ? { scope: limitFields['scope'] } : {}) }
      : null;
    this.remaining = typeof fields['remaining'] === 'number' ? fields['remaining'] : 0;
    this.maxPerActionCents = typeof fields['max_per_action_cents'] === 'number' ? fields['max_per_action_cents'] : null;
  }
}

/** 409 `CONTROLS_NOT_ENABLED`: policies need hosted controls, which are not on for this account. Turn them on with `billing.subscribeControls`. */
export class ControlsNotEnabledError extends StackError {
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'CONTROLS_NOT_ENABLED', status, details);
    this.name = 'ControlsNotEnabledError';
  }
}

/**
 * 402 `CONTROLS_REQUIRED`: this is a controls feature and the account has no controls. `feature` is `record` for a
 * read of the record (the audit record, evidence packs and signed records, Mission dossiers and replay, passport
 * reports, operator-review downloads), `detector_settings` for a change of the detector settings, `detector_reads` for
 * reading them, `policies` for control policies and their simulation, `reviews` for control reviews, `pii_settings` for
 * the PII redaction settings, `missions` for listing Missions, `fleets` for fleets, `intent_checks` for
 * pending intent checks `wallet_caps` for an agent wallet's caps and `budget` for an agent account's monthly budget. STACK keeps the record either way: switch controls on with `billing.subscribeControls` to read
 * all of it, including what came before.
 */
export class ControlsRequiredError extends StackError {
  readonly feature: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'CONTROLS_REQUIRED', status, details);
    this.name = 'ControlsRequiredError';
    this.feature = text(errorDetails(details)['feature']);
  }
}

/** One thing the publish scan found: a closed `code` and the file it is in, never page text. */
export interface SiteScanFinding {
  /** For example `brand_impersonation`, `unsafe_link` or `scanner_unavailable`. */
  code: string;
  path: string | null;
}

/**
 * 422 `WEBSITE_PUBLISH_REJECTED`: the publish scan found something the service
 * does not host, so nothing went live. `findings` names each one and the file
 * it is in. Fix them and publish again. A `scanner_unavailable` finding means
 * the scan could not run: publishing is refused rather than accepted unscanned,
 * so retry later.
 */
export class WebsitePublishRejectedError extends StackError {
  readonly findings: SiteScanFinding[];
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'WEBSITE_PUBLISH_REJECTED', status, details);
    this.name = 'WebsitePublishRejectedError';
    const findings = errorDetails(details)['findings'];
    this.findings = (Array.isArray(findings) ? findings : []).map((finding) => {
      const fields = finding && typeof finding === 'object' ? (finding as Record<string, unknown>) : {};
      return { code: text(fields['code']), path: typeof fields['path'] === 'string' ? fields['path'] : null };
    });
  }
}

/** 403 `WEBSITE_LIMIT_EXCEEDED`: the account is at `max` for `limit` (the size of the whole site) for a website. */
export class WebsiteLimitExceededError extends StackError {
  readonly limit: string;
  readonly max: number;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'WEBSITE_LIMIT_EXCEEDED', status, details);
    this.name = 'WebsiteLimitExceededError';
    const fields = errorDetails(details);
    this.limit = text(fields['limit']);
    this.max = typeof fields['max'] === 'number' ? fields['max'] : 0;
  }
}

/** 403 `WEBSITE_SUSPENDED`: the site is `suspended` or `taken_down` (`by` says who), so nothing can be published to it. */
export class WebsiteSuspendedError extends StackError {
  readonly state: string;
  readonly by: string | null;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'WEBSITE_SUSPENDED', status, details);
    this.name = 'WebsiteSuspendedError';
    const fields = errorDetails(details);
    this.state = text(fields['state']);
    this.by = typeof fields['by'] === 'string' ? fields['by'] : null;
  }
}

/** 409 `WEBSITE_HOSTNAME_UNAVAILABLE`: the address is taken, is not a name STACK can serve, or its ownership is not proven yet. `reason` says which. */
export class WebsiteHostnameUnavailableError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'WEBSITE_HOSTNAME_UNAVAILABLE', status, details);
    this.name = 'WebsiteHostnameUnavailableError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/** 409 `PAYMENT_CONNECTION_REQUIRED`: the account has no active Stripe connection. The customer connects their own Stripe first (`payments.startStripe`). */
export class PaymentConnectionRequiredError extends StackError {
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'PAYMENT_CONNECTION_REQUIRED', status, details);
    this.name = 'PaymentConnectionRequiredError';
  }
}

/** `STRIPE_REQUEST_FAILED`: Stripe refused or failed a call made with the customer's key; nothing was created. `kind` is `permission`, `rejected` or `unavailable` (502: try again shortly). */
export class StripeRequestFailedError extends StackError {
  readonly kind: string;
  readonly providerStatus: number | null;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'STRIPE_REQUEST_FAILED', status, details);
    this.name = 'StripeRequestFailedError';
    const fields = errorDetails(details);
    this.kind = text(fields['kind']);
    this.providerStatus = typeof fields['provider_status'] === 'number' ? fields['provider_status'] : null;
  }
}

/**
 * 400 or 422 `POST_REFUSED`: a letter or postcard was refused before anything was held or sent. `reason` says why:
 * `address_undeliverable`, `pdf_unreadable`, `too_many_pages` or `provider_refused` (the print provider's own refusal).
 * Nothing was charged.
 */
export class PostRefusedError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'POST_REFUSED', status, details);
    this.name = 'PostRefusedError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/** 503 `POST_UNAVAILABLE`: post is unavailable on STACK's side (provider not configured, or not answering). Nothing was charged; retry later. */
export class PostUnavailableError extends StackError {
  readonly reason: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'POST_UNAVAILABLE', status, details);
    this.name = 'PostUnavailableError';
    this.reason = text(errorDetails(details)['reason']);
  }
}

/**
 * 409 `POSTAL_ADDRESS_NOT_ACTIVE`: the customer's street address is not live. `addressStatus` is `none`,
 * `pending_identity` (the owner's steps at the supplier are unfinished) or `suspended`.
 */
export class PostalAddressNotActiveError extends StackError {
  readonly addressStatus: string;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'POSTAL_ADDRESS_NOT_ACTIVE', status, details);
    this.name = 'PostalAddressNotActiveError';
    this.addressStatus = text(errorDetails(details)['status']);
  }
}

/**
 * 409 `CONNECTION_AMBIGUOUS`: the service has several connections and the call named none. Nothing was sent upstream.
 * `connections` is the `{ id, name }` list the call could have used; repeat it with `connection` set to one of them.
 */
export class ConnectionAmbiguousError extends StackError {
  readonly connections: Array<{ id: string; name: string }>;
  constructor(message: string, status: number, details?: unknown) {
    super(message, 'CONNECTION_AMBIGUOUS', status, details);
    this.name = 'ConnectionAmbiguousError';
    const rows = errorDetails(details)['connections'];
    this.connections = Array.isArray(rows)
      ? rows
          .filter((row): row is Record<string, unknown> => typeof row === 'object' && row !== null)
          .map((row) => ({ id: text(row['id']), name: text(row['name']) }))
      : [];
  }
}

/** The error for a non-2xx API response: a typed subclass for the codes callers act on, else `StackError`. */
export function apiError(message: string, code: string, status: number, details?: unknown): StackError {
  switch (code) {
    case 'GOVERNANCE_APPROVAL_REQUIRED':
      return new GovernanceApprovalRequiredError(message, status, details);
    case 'GOVERNANCE_APPROVAL_PENDING':
    case 'GOVERNANCE_APPROVAL_REJECTED':
    case 'GOVERNANCE_APPROVAL_EXPIRED':
      return new GovernanceApprovalStateError(message, code, status, details);
    case 'ACCOUNT_PIECE_NOT_READY':
      return new AccountPieceNotReadyError(message, status, details);
    case 'AGENT_BUDGET_EXCEEDED':
      return new AgentBudgetExceededError(message, status, details);
    case 'RECIPIENT_OPTED_OUT':
      return new RecipientOptedOutError(message, status, details);
    case 'PROVIDER_CAPACITY_UNAVAILABLE':
      return new ProviderCapacityUnavailableError(message, status, details);
    case 'BROWSER_TIME_USED_UP':
      return new BrowserTimeUsedUpError(message, status, details);
    case 'BROWSER_SESSION_LENGTH_REFUSED':
      return new BrowserSessionLengthRefusedError(message, status, details);
    case 'ACCOUNT_CALL_FAILED':
      return new AccountCallFailedError(message, status, details);
    case 'DESTINATION_NOT_AVAILABLE':
      return new DestinationNotAvailableError(message, status, details);
    case 'TOOL_PRICE_REFUSED':
      return new ToolPriceRefusedError(message, status, details);
    case 'TOOLS_UNAVAILABLE':
      return new ToolsUnavailableError(message, status, details);
    case 'TOOL_RUN_REJECTED':
      return new ToolRunRejectedError(message, status, details);
    case 'MAKING_UNAVAILABLE':
      return new MakingUnavailableError(message, status, details);
    case 'BUDGET_NEEDS_CONTROLS':
      return new BudgetNeedsControlsError(message, status, details);
    case 'PLATFORM_SUBSCRIPTION_REQUIRED':
      return new PlatformSubscriptionRequiredError(message, status, details);
    case 'SHARED_MAIL_DAILY_LIMIT':
      return new SharedMailDailyLimitError(message, status, details);
    case 'EMAIL_ATTACHMENTS_TOO_LARGE':
      return new EmailAttachmentsTooLargeError(message, status, details);
    case 'EMAIL_MESSAGE_NOT_ANSWERABLE':
      return new EmailMessageNotAnswerableError(message, status, details);
    case 'TELEGRAM_SEND_REFUSED':
      return new TelegramSendRefusedError(message, status, details);
    case 'UNBOUNDED_SEND_RULE':
      return new UnboundedSendRuleError(message, status, details);
    case 'CONTROL_DENIED':
      return new ControlDeniedError(message, status, details);
    case 'CONTROL_LIMIT_EXCEEDED':
      return new ControlLimitExceededError(message, status, details);
    case 'CONTROLS_NOT_ENABLED':
      return new ControlsNotEnabledError(message, status, details);
    case 'CONTROLS_REQUIRED':
      return new ControlsRequiredError(message, status, details);
    case 'WEBSITE_PUBLISH_REJECTED':
      return new WebsitePublishRejectedError(message, status, details);
    case 'WEBSITE_LIMIT_EXCEEDED':
      return new WebsiteLimitExceededError(message, status, details);
    case 'WEBSITE_SUSPENDED':
      return new WebsiteSuspendedError(message, status, details);
    case 'WEBSITE_HOSTNAME_UNAVAILABLE':
      return new WebsiteHostnameUnavailableError(message, status, details);
    case 'PAYMENT_CONNECTION_REQUIRED':
      return new PaymentConnectionRequiredError(message, status, details);
    case 'STRIPE_REQUEST_FAILED':
      return new StripeRequestFailedError(message, status, details);
    case 'POST_REFUSED':
      return new PostRefusedError(message, status, details);
    case 'POST_UNAVAILABLE':
      return new PostUnavailableError(message, status, details);
    case 'POSTAL_ADDRESS_NOT_ACTIVE':
      return new PostalAddressNotActiveError(message, status, details);
    case 'CONNECTION_AMBIGUOUS':
      return new ConnectionAmbiguousError(message, status, details);
    default:
      return new StackError(message, code, status, details);
  }
}
