"""STACK SDK error classes."""

from __future__ import annotations

import re
from typing import Any, Callable


class StackError(Exception):
    """Base error for all STACK API errors."""

    def __init__(
        self, message: str, code: str = "UNKNOWN", status_code: int = 500, details: dict[str, Any] | None = None
    ):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class NotFoundError(StackError):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, "NOT_FOUND", 404)


class UnauthorizedError(StackError):
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, "UNAUTHORIZED", 401)


class ForbiddenError(StackError):
    def __init__(self, message: str = "Forbidden"):
        super().__init__(message, "FORBIDDEN", 403)


class ValidationError(StackError):
    def __init__(self, message: str = "Validation failed", details: dict[str, Any] | None = None):
        super().__init__(message, "VALIDATION_ERROR", 400, details)


class PassportBlockedError(StackError):
    def __init__(self, message: str = "Agent is blocked from passport issuance"):
        super().__init__(message, "PASSPORT_BLOCKED", 403)


class MissionEndedError(StackError):
    """A passport could not be refreshed or issued because its Mission is no
    longer live (completed, revoked, expired or not found).

    Every passport is bound to exactly one Mission and never outlives it.
    Open a new Mission (``stack.missions.open`` or ``stack.missions.start``)
    and issue a new passport for it.

    ``mission_id`` is the Mission named by the API (``None`` when the passport
    carried no Mission). ``mission_state`` is one of ``"completed"``,
    ``"revoked"``, ``"expired"``, ``"not_found"`` or ``"missing"``.
    ``status_code`` keeps the API status (403 or 404).
    """

    def __init__(
        self,
        mission_id: str | None,
        mission_state: str,
        status_code: int = 403,
        api_message: str | None = None,
    ):
        subject = f"Mission {mission_id}" if mission_id else "The passport's Mission"
        state_text = {
            "completed": "is completed",
            "revoked": "is revoked",
            "expired": "has expired",
            "not_found": "was not found",
            "missing": "is missing (the passport is not bound to a Mission)",
        }.get(mission_state, f"is {mission_state}")
        super().__init__(
            f"{subject} {state_text}; a passport cannot outlive its Mission. "
            "Open a new Mission (stack.missions.open or stack.missions.start) "
            "and issue a new passport for it.",
            "MISSION_ENDED",
            status_code,
            {"mission_id": mission_id, "mission_state": mission_state, "api_message": api_message},
        )
        self.mission_id = mission_id
        self.mission_state = mission_state


class GovernanceApprovalRequiredError(ForbiddenError):
    """The call loosens a safety control and waits for a human approval.

    Ask the operator to approve at ``approval_url``, then retry the same call
    with ``governance_approval_id=approval_id``. A ``ForbiddenError`` (403), so
    existing ``except ForbiddenError`` handlers keep catching it.
    """

    def __init__(self, message: str = "Human approval required", details: dict[str, Any] | None = None):
        StackError.__init__(self, message, "GOVERNANCE_APPROVAL_REQUIRED", 403, details)
        self.approval_id: str | None = _detail_str(self.details, "approval_id")
        self.approval_url: str | None = _detail_str(self.details, "approval_url")


class GovernanceApprovalStateError(ForbiddenError):
    """A retry named a governance approval that cannot be used (403).

    ``code`` is ``GOVERNANCE_APPROVAL_PENDING`` (wait for the person, then retry),
    ``GOVERNANCE_APPROVAL_REJECTED`` or ``GOVERNANCE_APPROVAL_EXPIRED`` (make the call
    again without the approval to ask for a new one). ``approval_status`` is
    ``pending``, ``rejected`` or ``expired``. A ``ForbiddenError``, so existing
    ``except ForbiddenError`` handlers keep catching it.
    """

    def __init__(self, message: str, code: str, details: dict[str, Any] | None = None):
        StackError.__init__(self, message, code, 403, details)
        self.approval_id: str | None = _detail_str(self.details, "approval_id")
        self.approval_status: str | None = _detail_str(self.details, "status")


def _governance_state(code: str) -> Callable[[str, dict[str, Any]], StackError]:
    return lambda message, details: GovernanceApprovalStateError(message, code, details)


class AgentBudgetExceededError(StackError):
    """The agent account has reached its monthly budget (402).

    ``remaining_cents`` is what was left when the call was refused.
    """

    def __init__(self, message: str = "Agent budget exceeded", details: dict[str, Any] | None = None):
        super().__init__(message, "AGENT_BUDGET_EXCEEDED", 402, details)
        self.account_id: str | None = _detail_str(self.details, "account_id")
        self.remaining_cents: int | None = _detail_int(self.details, "remaining_cents")


class AccountPieceNotReadyError(StackError):
    """A piece of the agent account (inbox, phone, browser and so on) is not ready (409).

    ``state`` is the piece's current state, such as ``"pending"`` or ``"paused"``.
    Read the account to see when it is ready.
    """

    def __init__(self, message: str = "Account piece not ready", details: dict[str, Any] | None = None):
        super().__init__(message, "ACCOUNT_PIECE_NOT_READY", 409, details)
        self.account_id: str | None = _detail_str(self.details, "account_id")
        self.piece: str | None = _detail_str(self.details, "piece")
        self.state: str | None = _detail_str(self.details, "state")


class BrowserTimeUsedUpError(StackError):
    """This month's browser time is spent (503). Nothing was charged; browsers return when the month turns."""

    def __init__(self, message: str = "Browser time for this month is used up", details: dict[str, Any] | None = None):
        super().__init__(message, "BROWSER_TIME_USED_UP", 503, details)
        self.provider: str | None = _detail_str(self.details, "provider")


class BrowserSessionLengthRefusedError(StackError):
    """The browser plan does not allow a session this long (503). Nothing was charged; retrying does not help."""

    def __init__(self, message: str = "Browser session length not allowed", details: dict[str, Any] | None = None):
        super().__init__(message, "BROWSER_SESSION_LENGTH_REFUSED", 503, details)
        self.provider: str | None = _detail_str(self.details, "provider")


class ProviderCapacityUnavailableError(StackError):
    """A provider declined STACK's own account, or STACK paused its own spend at Twilio (503).

    Nothing was charged; retry in a few minutes.
    """

    def __init__(self, message: str = "Provider capacity unavailable", details: dict[str, Any] | None = None):
        super().__init__(message, "PROVIDER_CAPACITY_UNAVAILABLE", 503, details)
        self.provider: str | None = _detail_str(self.details, "provider")


class AccountCallFailedError(StackError):
    """The call provider refused or failed the call (502 or 422).

    ``retryable`` is true for a 502: the call may have been placed, so read the account's calls
    before retrying. A 422 is a refusal; ``reason`` names it.
    """

    def __init__(self, message: str = "Account call failed", details: dict[str, Any] | None = None):
        super().__init__(message, "ACCOUNT_CALL_FAILED", 502, details)
        self.reason: str | None = _detail_str(self.details, "reason")

    @property
    def retryable(self) -> bool:
        return self.status_code == 502


class RecipientOptedOutError(ForbiddenError):
    """The number asked not to be contacted, so texts and calls to it are refused (403).

    It texted STOP (or another opt-out word), or the customer or an agent added it. The owner reads the
    do-not-contact list with ``stack.accounts.opt_outs.list`` and takes a number off with ``remove``.
    A ``ForbiddenError``, so existing ``except ForbiddenError`` handlers keep catching it.
    """

    def __init__(self, message: str = "Recipient opted out", details: dict[str, Any] | None = None):
        StackError.__init__(self, message, "RECIPIENT_OPTED_OUT", 403, details)
        self.account_id: str | None = _detail_str(self.details, "account_id")


class DestinationNotAvailableError(StackError):
    """Texts and calls to this number are not available (422). Nothing was charged.

    ``reason`` is ``"no_price"`` (Twilio has no price for the destination, so STACK cannot charge it at cost) or
    ``"refused_by_twilio"`` (Twilio's own geographic permissions or high-risk number blocking do not allow it from
    the account's number).
    """

    def __init__(self, message: str = "Destination not available", details: dict[str, Any] | None = None):
        super().__init__(message, "DESTINATION_NOT_AVAILABLE", 422, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class ToolPriceRefusedError(StackError):
    """A paid tool run refused before it is held (422): max_results out of range, an input too deep.

    Nothing was held or charged.

    ``provider`` and ``endpoint`` name the endpoint; ``reason`` says what is missing.
    """

    def __init__(self, message: str = "Tool price refused", details: dict[str, Any] | None = None):
        super().__init__(message, "TOOL_PRICE_REFUSED", 422, details)
        self.reason: str | None = _detail_str(self.details, "reason")
        self.provider: str | None = _detail_str(self.details, "provider")
        self.endpoint: str | None = _detail_str(self.details, "endpoint")


class ToolsUnavailableError(StackError):
    """Paid tools are unavailable on STACK's side (503). Nothing was charged; retry later."""

    def __init__(self, message: str = "Tools unavailable", details: dict[str, Any] | None = None):
        super().__init__(message, "TOOLS_UNAVAILABLE", 503, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class ConnectionAmbiguousError(StackError):
    """The service has several connections and the call named none (409). Nothing was sent upstream.

    ``connections`` is the ``[{"id", "name"}]`` the call could have used; repeat it with ``connection`` set to one
    of those ids or names.
    """

    def __init__(
        self, message: str = "Several connections match; pass connection", details: dict[str, Any] | None = None
    ):
        super().__init__(message, "CONNECTION_AMBIGUOUS", 409, details)
        rows = self.details.get("connections")
        self.connections: list[dict[str, Any]] = (
            [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        )


class ModelCostCapError(StackError):
    """A model call was refused for its ``max_cost_cents`` (422).

    STACK's key never refuses a cap: it lowers the hold, and a call on your own provider key ignores it. A deployment
    that does refuse a cap below the call's worst case says ``cost_cap_exceeded`` in ``reason``. Nothing was held or
    charged.
    """

    def __init__(self, message: str = "Model cost cap", details: dict[str, Any] | None = None):
        super().__init__(message, "MODEL_COST_CAP", 422, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class CatalogueUnavailableError(StackError):
    """The catalogue is not available (503). Retry later.

    ``reason`` is ``not_built`` (STACK has not built it yet) or ``store_unavailable``.
    """

    def __init__(self, message: str = "Catalogue unavailable", details: dict[str, Any] | None = None):
        super().__init__(message, "CATALOGUE_UNAVAILABLE", 503, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class MakingUnavailableError(StackError):
    """Making is unavailable on STACK's or a supplier's side (503). Nothing was ordered or charged; retry later."""

    def __init__(self, message: str = "Making unavailable", details: dict[str, Any] | None = None):
        super().__init__(message, "MAKING_UNAVAILABLE", 503, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class ToolRunRejectedError(StackError):
    """The tool provider refused the run request itself (400): check the input against the endpoint's schema.

    ``provider_status`` is the provider's HTTP status. Nothing was charged.
    """

    def __init__(self, message: str = "Tool run rejected", details: dict[str, Any] | None = None):
        super().__init__(message, "TOOL_RUN_REJECTED", 400, details)
        self.provider_status: int | None = _detail_int(self.details, "provider_status")


class PostRefusedError(StackError):
    """A letter or postcard was refused before anything was held or sent (400 or 422).

    ``reason`` says why: ``address_undeliverable``, ``pdf_unreadable``, ``too_many_pages`` or
    ``provider_refused`` (the print provider's own refusal). Nothing was charged.
    """

    def __init__(self, message: str = "Post refused", details: dict[str, Any] | None = None):
        super().__init__(message, "POST_REFUSED", 403, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class PostUnavailableError(StackError):
    """Post is unavailable on STACK's side (503): the letter provider is not configured or not answering.

    Nothing was charged; retry later.
    """

    def __init__(self, message: str = "Post unavailable", details: dict[str, Any] | None = None):
        super().__init__(message, "POST_UNAVAILABLE", 503, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class PostalAddressNotActiveError(StackError):
    """The customer's street address is not live (409).

    ``address_status`` is ``none``, ``pending_identity`` (the owner's steps at the supplier are unfinished)
    or ``suspended``.
    """

    def __init__(self, message: str = "Street address not active", details: dict[str, Any] | None = None):
        super().__init__(message, "POSTAL_ADDRESS_NOT_ACTIVE", 409, details)
        self.address_status: str | None = _detail_str(self.details, "status")


class BudgetNeedsControlsError(ForbiddenError):
    """A per-agent monthly budget needs controls (403).

    Open the account without ``monthly_budget_cents`` (prepaid credit is its limit), or turn on controls
    first. A ``ForbiddenError``, so existing ``except ForbiddenError`` handlers keep catching it.
    """

    def __init__(self, message: str = "Budget needs controls", details: dict[str, Any] | None = None):
        StackError.__init__(self, message, "BUDGET_NEEDS_CONTROLS", 403, details)


class PlatformSubscriptionRequiredError(StackError):
    """Every agent call needs the platform subscription trialing or active (402).

    An agent account's or not; a contract plan never needs it. ``subscription_status`` is
    its status now: none, incomplete, lapsed or canceled. The message says how to start the plan.
    """

    def __init__(self, message: str = "Platform subscription required", details: dict[str, Any] | None = None):
        super().__init__(message, "PLATFORM_SUBSCRIPTION_REQUIRED", 402, details)
        self.subscription_status: str | None = _detail_str(self.details, "status")


class ControlsRequiredError(StackError):
    """This is a controls feature and the account has no controls (402).

    ``feature`` is ``record`` for a read of the record (the audit record, evidence packs and signed records,
    Mission dossiers and replay, passport reports, operator-review downloads), ``detector_settings`` for a
    change of the detector settings, ``detector_reads`` for reading them, ``policies`` for control policies and
    their simulation, ``reviews`` for control reviews, ``pii_settings`` for the PII redaction settings,
    ``missions`` for listing Missions, ``fleets`` for fleets, ``intent_checks`` for pending intent
    checks ``wallet_caps`` for an agent wallet's caps and ``budget`` for an agent account's monthly budget. STACK keeps
    the record either way: switch controls on with ``billing.subscribe_controls`` to read all
    of it, including what came before.
    """

    def __init__(self, message: str = "Controls required", details: dict[str, Any] | None = None):
        super().__init__(message, "CONTROLS_REQUIRED", 402, details)
        self.feature: str | None = _detail_str(self.details, "feature")


class SharedMailDailyLimitError(StackError):
    """The customer's agents have reached ``limit`` recipients today (UTC) on the shared agent domain (429).

    Every To, Cc and Bcc address counts, not each email; the limit is 20 for a customer's first 14 days and 100 after.
    It resets at midnight UTC; inboxes on an own verified domain have no STACK daily limit.
    """

    def __init__(self, message: str = "Shared mail daily limit", details: dict[str, Any] | None = None):
        super().__init__(message, "SHARED_MAIL_DAILY_LIMIT", 429, details)
        self.limit: int | None = _detail_int(self.details, "limit")


class TelegramSendRefusedError(StackError):
    """A Telegram send STACK refused before anything left (403). Nothing was sent.

    ``reason``: ``no_bot`` (the agent has no bot), ``chat_unknown`` (the chat never wrote to the bot: a
    Telegram bot cannot message a chat first), ``chat_blocked``, ``bot_unavailable`` (Telegram no longer
    accepts the bot's token).
    """

    def __init__(self, message: str = "Telegram send refused", details: dict[str, Any] | None = None):
        super().__init__(message, "TELEGRAM_SEND_REFUSED", 403, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class UnboundedSendRuleError(StackError):
    """A policy allows a send without naming who receives it (400).

    ``rules`` lists each offending rule as a dict with ``rule_id``, ``connection_id``, ``provider``,
    ``reason``, ``intents`` and ``unbound_paths``. Bind those recipient fields, set the rule's ``recipients`` to
    ``"per_mission"`` so each Mission names them, or set the rule to review or deny.
    """

    def __init__(self, message: str = "Unbounded send rule", details: dict[str, Any] | None = None):
        super().__init__(message, "UNBOUNDED_SEND_RULE", 400, details)
        rules = self.details.get("rules")
        self.rules: list[dict[str, Any]] = [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []


class ControlDeniedError(ForbiddenError):
    """The customer's controls refused an action (403); nothing was charged.

    ``decision_id`` names the decision and ``reason_code`` says why (``None`` when the decider gave none).
    ``rule`` is set when a hosted policy refused: ``policy_id``, ``policy_revision``, ``section``, ``rule``,
    ``code`` and sometimes ``detail`` (the policy's own side of the comparison), never a value the call
    carried. ``reason_code`` is ``recipients_not_pinned`` when the Mission does not name who it may send to, and
    ``recipient_not_allowed`` for someone it did not name. ``retry`` is set when the action is held for a person:
    ``{"ref": ..., "after_seconds": ...}``; retry the same call with header ``X-Control-Ref: <ref>`` once it is
    approved. A ``ForbiddenError``, so existing ``except ForbiddenError`` handlers keep catching it.
    """

    def __init__(self, message: str = "Your controls refused this action", details: dict[str, Any] | None = None):
        StackError.__init__(self, message, "CONTROL_DENIED", 403, details)
        self.decision_id: str | None = _detail_str(self.details, "decision_id")
        self.reason_code: str | None = _detail_str(self.details, "reason_code")
        self.retry: dict[str, Any] | None = _detail_dict(self.details, "retry")
        self.rule: dict[str, Any] | None = _detail_dict(self.details, "rule")


class ControlLimitExceededError(ForbiddenError):
    """A limit of the customer's policy was reached while the action was being paid for (403).

    Nothing was reserved or charged. ``limit`` is ``{"window": ..., "unit": ...}`` (the window is day, month,
    mission or action; a spend rule's counter adds ``"scope": "spend:<rule id>"``), ``remaining`` is what is
    left of it and ``max_per_action_cents`` is the most one action may cost (set only when that ceiling
    refused it). A ``ForbiddenError``.
    """

    def __init__(
        self, message: str = "Your controls set a limit this action would pass", details: dict[str, Any] | None = None
    ):
        StackError.__init__(self, message, "CONTROL_LIMIT_EXCEEDED", 403, details)
        self.limit: dict[str, Any] | None = _detail_dict(self.details, "limit")
        self.remaining: int | None = _detail_int(self.details, "remaining")
        self.max_per_action_cents: int | None = _detail_int(self.details, "max_per_action_cents")


class WebsitePublishRejectedError(StackError):
    """The publish scan found something STACK does not host, so nothing went live (422).

    ``findings`` lists each one as ``{"code": ..., "path": ...}`` (``path`` is ``None`` when it is not about one
    file). A ``scanner_unavailable`` finding means the scan could not run and publishing is refused rather than
    accepted unscanned: retry later. Fix the others and publish again.
    """

    def __init__(self, message: str = "The site was not published", details: dict[str, Any] | None = None):
        super().__init__(message, "WEBSITE_PUBLISH_REJECTED", 422, details)
        raw = self.details.get("findings")
        self.findings: list[dict[str, Any]] = (
            [
                {"code": str(f.get("code", "")), "path": f["path"] if isinstance(f.get("path"), str) else None}
                for f in raw
                if isinstance(f, dict)
            ]
            if isinstance(raw, list)
            else []
        )


class WebsiteLimitExceededError(ForbiddenError):
    """The account is at ``max`` for ``limit`` for a website (403)."""

    def __init__(self, message: str = "Website limit reached", details: dict[str, Any] | None = None):
        StackError.__init__(self, message, "WEBSITE_LIMIT_EXCEEDED", 403, details)
        self.limit: str | None = _detail_str(self.details, "limit")
        self.max: int | None = _detail_int(self.details, "max")


class WebsiteSuspendedError(ForbiddenError):
    """The site is ``suspended`` or ``taken_down`` (``state``), by ``by``, so nothing can be published to it (403)."""

    def __init__(self, message: str = "This site is suspended", details: dict[str, Any] | None = None):
        StackError.__init__(self, message, "WEBSITE_SUSPENDED", 403, details)
        self.state: str | None = _detail_str(self.details, "state")
        self.by: str | None = _detail_str(self.details, "by")


class WebsiteHostnameUnavailableError(StackError):
    """The address is taken, is not a name STACK can serve, or is not proven yet (409). ``reason`` says which."""

    def __init__(self, message: str = "Hostname unavailable", details: dict[str, Any] | None = None):
        super().__init__(message, "WEBSITE_HOSTNAME_UNAVAILABLE", 409, details)
        self.reason: str | None = _detail_str(self.details, "reason")


class PaymentConnectionRequiredError(StackError):
    """The account has no active Stripe connection (409). The customer connects their own Stripe first."""

    def __init__(self, message: str = "No Stripe connection", details: dict[str, Any] | None = None):
        super().__init__(message, "PAYMENT_CONNECTION_REQUIRED", 409, details)


class StripeRequestFailedError(StackError):
    """Stripe refused or failed a call made with the customer's key; nothing was created.

    ``kind`` is ``permission``, ``rejected`` or ``unavailable`` (502: try again shortly); ``provider_status`` is
    Stripe's own HTTP status.
    """

    def __init__(self, message: str = "Stripe request failed", details: dict[str, Any] | None = None):
        super().__init__(message, "STRIPE_REQUEST_FAILED", 422, details)
        self.kind: str | None = _detail_str(self.details, "kind")
        self.provider_status: int | None = _detail_int(self.details, "provider_status")


def _detail_str(details: dict[str, Any], key: str) -> str | None:
    value = details.get(key)
    return value if isinstance(value, str) else None


def _detail_dict(details: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = details.get(key)
    return value if isinstance(value, dict) else None


def _detail_int(details: dict[str, Any], key: str) -> int | None:
    value = details.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


_MISSION_STATE_PATTERNS = (
    (re.compile(r"Mission (ms_[\w-]+) is completed"), "completed"),
    (re.compile(r"Mission (ms_[\w-]+) is revoked"), "revoked"),
    (re.compile(r"Mission (ms_[\w-]+) has expired"), "expired"),
    (re.compile(r"Mission (ms_[\w-]+) not found"), "not_found"),
    (re.compile(r"Mission not found: (ms_[\w-]+)"), "not_found"),
)


def mission_ended_error(exc: StackError) -> MissionEndedError | None:
    """Return a MissionEndedError when ``exc`` is the API refusing a passport
    call because its Mission is no longer live, else ``None``."""
    if exc.status_code not in (403, 404):
        return None
    message = str(exc)
    for pattern, state in _MISSION_STATE_PATTERNS:
        match = pattern.search(message)
        if match:
            return MissionEndedError(match.group(1), state, exc.status_code, message)
    if exc.status_code == 403 and "bound to exactly one Mission" in message:
        return MissionEndedError(None, "missing", 403, message)
    return None


# Error codes with their own class; checked before the status code.
_CODE_MAP: dict[str, Callable[[str, dict[str, Any]], StackError]] = {
    "GOVERNANCE_APPROVAL_REQUIRED": GovernanceApprovalRequiredError,
    "GOVERNANCE_APPROVAL_PENDING": _governance_state("GOVERNANCE_APPROVAL_PENDING"),
    "GOVERNANCE_APPROVAL_REJECTED": _governance_state("GOVERNANCE_APPROVAL_REJECTED"),
    "GOVERNANCE_APPROVAL_EXPIRED": _governance_state("GOVERNANCE_APPROVAL_EXPIRED"),
    "AGENT_BUDGET_EXCEEDED": AgentBudgetExceededError,
    "ACCOUNT_PIECE_NOT_READY": AccountPieceNotReadyError,
    "PROVIDER_CAPACITY_UNAVAILABLE": ProviderCapacityUnavailableError,
    "BROWSER_TIME_USED_UP": BrowserTimeUsedUpError,
    "BROWSER_SESSION_LENGTH_REFUSED": BrowserSessionLengthRefusedError,
    "ACCOUNT_CALL_FAILED": AccountCallFailedError,
    "RECIPIENT_OPTED_OUT": RecipientOptedOutError,
    "DESTINATION_NOT_AVAILABLE": DestinationNotAvailableError,
    "TOOL_PRICE_REFUSED": ToolPriceRefusedError,
    "TOOLS_UNAVAILABLE": ToolsUnavailableError,
    "TOOL_RUN_REJECTED": ToolRunRejectedError,
    "CONNECTION_AMBIGUOUS": ConnectionAmbiguousError,
    "MODEL_COST_CAP": ModelCostCapError,
    "CATALOGUE_UNAVAILABLE": CatalogueUnavailableError,
    "POST_REFUSED": PostRefusedError,
    "POST_UNAVAILABLE": PostUnavailableError,
    "POSTAL_ADDRESS_NOT_ACTIVE": PostalAddressNotActiveError,
    "MAKING_UNAVAILABLE": MakingUnavailableError,
    "BUDGET_NEEDS_CONTROLS": BudgetNeedsControlsError,
    "PLATFORM_SUBSCRIPTION_REQUIRED": PlatformSubscriptionRequiredError,
    "CONTROLS_REQUIRED": ControlsRequiredError,
    "SHARED_MAIL_DAILY_LIMIT": SharedMailDailyLimitError,
    "TELEGRAM_SEND_REFUSED": TelegramSendRefusedError,
    "UNBOUNDED_SEND_RULE": UnboundedSendRuleError,
    "CONTROL_DENIED": ControlDeniedError,
    "CONTROL_LIMIT_EXCEEDED": ControlLimitExceededError,
    "WEBSITE_PUBLISH_REJECTED": WebsitePublishRejectedError,
    "WEBSITE_LIMIT_EXCEEDED": WebsiteLimitExceededError,
    "WEBSITE_SUSPENDED": WebsiteSuspendedError,
    "WEBSITE_HOSTNAME_UNAVAILABLE": WebsiteHostnameUnavailableError,
    "PAYMENT_CONNECTION_REQUIRED": PaymentConnectionRequiredError,
    "STRIPE_REQUEST_FAILED": StripeRequestFailedError,
}

# Map HTTP status codes to error classes
_STATUS_MAP = {
    401: UnauthorizedError,
    403: ForbiddenError,
    404: NotFoundError,
}


def raise_for_status(status_code: int, body: Any) -> None:
    """Raise an appropriate StackError from an API error response."""
    payload = body if isinstance(body, dict) else {}
    error = payload.get("error", {})

    if isinstance(error, dict):
        message = error.get("message", f"API error: {status_code}")
        code = error.get("code", "UNKNOWN")
        details = error.get("details", {})
    else:
        # OAuth errors use the RFC 6749 shape: `error` is a short string and
        # `error_description` carries the human-readable explanation.
        message = payload.get("error_description") or payload.get("message") or str(error)
        code = str(error).upper() if error else "UNKNOWN"
        details = {key: value for key, value in payload.items() if key not in {"error", "error_description", "message"}}

    if not isinstance(message, str) or not message:
        message = f"API error: {status_code}"

    details = details if isinstance(details, dict) else {}
    coded = _CODE_MAP.get(code) if isinstance(code, str) else None
    exc: StackError = coded(message, details) if coded else _STATUS_MAP.get(status_code, StackError)(message)
    exc.code = code if isinstance(code, str) else "UNKNOWN"
    exc.status_code = status_code
    exc.details = details
    raise exc
