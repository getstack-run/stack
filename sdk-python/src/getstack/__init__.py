"""STACK Python SDK.

Fleet Mission example::

    import hashlib
    import json
    from getstack.errors import StackError


    def run_fleet_mission_example(stack, request, provider_url="https://slack.com/api/chat.postMessage"):
        started = stack.missions.start(request)
        repeated = stack.missions.start(request)
        assert repeated["mission_id"] == started["mission_id"]
        operation_id = hashlib.sha256(json.dumps([started["mission_id"], "support-update"]).encode()).hexdigest()
        response = stack.proxy.request("slack", provider_url, "POST",
            body={"channel": "C123", "text": "Support update"},
            passport_token=started["passport"]["token"], authority_request_id=operation_id)
        assert response.status == 200
        try:
            stack.proxy.request("slack", provider_url, "POST", body={"channel": "OTHER", "text": "Support update"},
                passport_token=started["passport"]["token"], authority_request_id=operation_id + "_denied")
        except StackError as error:
            assert error.status_code == 403
        else:
            raise AssertionError("Expected channel restriction")
        before = stack.missions.get(started["mission_id"])
        renewed = stack.missions.renew(started["mission_id"])
        after = stack.missions.get(renewed["mission_id"])
        assert renewed["mission_id"] == started["mission_id"]
        assert after["fleet"]["limits"] == before["fleet"]["limits"]
        assert after["fleet"]["usage"] == before["fleet"]["usage"]
        completed = stack.missions.complete(started["mission_id"], output={"done": True})
        assert completed["terminal_state"] == "completed_successful"
        stopped = stack.missions.start({**request, "idempotency_key": request["idempotency_key"] + "-stop"})
        stack.missions.revoke(stopped["mission_id"], reason="operator_initiated_clean")
        try:
            stack.missions.renew(stopped["mission_id"])
        except StackError:
            pass
        else:
            raise AssertionError("Expected revoked Mission")
        return {"mission_id": started["mission_id"], "operation_id": operation_id, "completed": True, "revoked": True}
"""

from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Any

from ._async.accounts import AsyncAccountsService
from ._async.authority import AsyncAuthorityService
from ._async.brain import AsyncBrainService
from ._async.catalogue import AsyncCatalogueService
from ._async.drive import AsyncDriveService
from ._async.fleets import AsyncFleetsService
from ._async.memory import AsyncMemoryService
from ._async.payments import AsyncPaymentsService
from ._async.website import AsyncWebsiteService
from ._authority_request import create_authority_request_id
from ._control_ref import scoped_stack
from .accounts import AccountsService
from .agent_auth import AgentKeypairAuth
from .agent_identity import AgentIdentityService
from .agents import AgentService
from .audit import AuditService
from .auth import ApiKeyAuth, CredentialsFileAuth, OAuthAuth, SessionAuth
from .authority import AuthorityService
from .billing import BillingService
from .brain import BrainService
from .calendar import CalendarService
from .catalogue import CatalogueService
from .chat_channels import ChatChannelsService
from .client import DEFAULT_BASE_URL, AsyncHttpClient, HttpClient
from .control_policies import ControlPoliciesService, ControlReviewsService
from .control_server import (
    ControlSignatureError,
    SignedControlAnswer,
    sign_control_answer,
    verify_control_request,
)
from .control_socket import ControlSocketService
from .credentials import CredentialService
from .delivery_methods import DeliveryMethodService
from .detector_config import DetectorConfigService
from .drive import DriveService
from .dropoffs import DropoffService
from .errors import (
    AccountCallFailedError,
    AccountPieceNotReadyError,
    AgentBudgetExceededError,
    BrowserSessionLengthRefusedError,
    BrowserTimeUsedUpError,
    BudgetNeedsControlsError,
    CatalogueUnavailableError,
    ControlDeniedError,
    ControlLimitExceededError,
    ControlsRequiredError,
    DestinationNotAvailableError,
    ForbiddenError,
    GovernanceApprovalRequiredError,
    GovernanceApprovalStateError,
    MakingUnavailableError,
    MissionEndedError,
    ModelCostCapError,
    NotFoundError,
    PassportBlockedError,
    PaymentConnectionRequiredError,
    PlatformSubscriptionRequiredError,
    PostalAddressNotActiveError,
    PostRefusedError,
    PostUnavailableError,
    ProviderCapacityUnavailableError,
    RecipientOptedOutError,
    SharedMailDailyLimitError,
    StackError,
    StripeRequestFailedError,
    TelegramSendRefusedError,
    ToolPriceRefusedError,
    ToolRunRejectedError,
    ToolsUnavailableError,
    UnauthorizedError,
    UnboundedSendRuleError,
    ValidationError,
    WebsiteHostnameUnavailableError,
    WebsiteLimitExceededError,
    WebsitePublishRejectedError,
    WebsiteSuspendedError,
)
from .evidence_packs import EvidencePacksService
from .flagged_content import FlaggedContentService
from .fleets import FleetsService
from .governance import GovernanceService
from .identity import IdentityService
from .inbound_webhooks import InboundWebhookService
from .intents import IntentsService
from .llm import LlmService
from .meetings import MeetingsService
from .memory import MemoryService
from .message_access import MessageAccessService
from .missions import MissionsService
from .network import NetworkService
from .network_install import AsyncInstallClient, InstallClient
from .network_keys import InstallKey, install_key_thumbprint, passport_digest
from .notifications import NotificationService
from .partner_accounts import PartnerAccountsService
from .passport_header_verify import verify_passport_header
from .passport_session import PassportSession
from .passports import Mission, PassportService, _require_one_mission
from .payments import PaymentsService
from .pii_config import PiiConfigService
from .post import PostService
from .proxy import ProxyOperation, ProxyResponse
from .proxy import ProxyService as ProxySvc
from .rentahuman import RentAHumanService
from .reviews import ReviewService
from .scan import ScanService
from .security_events import SecurityEventService as SecurityEventSvc
from .services import ServiceService
from .sign_claim import sign_claim_envelope
from .skills import SkillService
from .team import TeamService
from .trust import TrustService
from .types import (
    Agent,
    AuthorityReference,
    CatalogueAccountPiece,
    CatalogueAccountView,
    CatalogueActionBand,
    CatalogueConnectedService,
    CatalogueCostCap,
    CatalogueDocument,
    CatalogueEntry,
    CatalogueKind,
    CatalogueModalities,
    CatalogueOrigin,
    CataloguePrice,
    CataloguePricing,
    CatalogueProviderCost,
    CatalogueRead,
    CatalogueResultTrust,
    CatalogueRun,
    CatalogueSearchResult,
    CatalogueSection,
    CheckoutResult,
    CheckpointResult,
    Credential,
    EmailAttachment,
    EmailDriveAttachment,
    EmailDropped,
    EmailInlineAttachment,
    EmailSendResult,
    EmailSentAttachment,
    ForwardEmailInput,
    IdentityClaim,
    IdentityProvider,
    IdentitySettings,
    MessageAttachment,
    MessageEnvelope,
    NotificationChannel,
    Passport,
    PassportReport,
    PassportStackClaims,
    ReplaceServiceRequirementResult,
    ReplyEmailInput,
    ReviewDecisionResult,
    ReviewFlag,
    ReviewQueue,
    ReviewQueueItem,
    SendEmailInput,
    ServiceRequirement,
    SetServiceRequirementInput,
    Skill,
    SkillInvocation,
    SkillRequest,
    ToolCall,
    ToolRunFile,
    ToolRunResult,
    VerificationSession,
    VerifiedPassportClaims,
)
from .usage import UsageService
from .verify_agent_identity import AgentIdentityVerificationError, verify_agent_identity
from .verify_network import (
    NetworkVerificationError,
    revocation_covers,
    verify_countersigned_passport,
    verify_detection_rules,
    verify_revocation_list,
    verify_verified_statement,
)
from .verify_offline import verify_passport_offline
from .wake import WakesService
from .wake_webhook import WakeSignatureError, verify_wake_webhook
from .wallet_key import (
    AgentWalletKey,
    WalletKeyInSandboxError,
    WalletPaymentTarget,
    generate_agent_wallet_key,
    load_agent_wallet_key,
    sign_wallet_payment,
    wallet_payment_authorization_payload,
)
from .webhook import ReplayGuard, WebhookSignatureError, verify_webhook
from .website import WebsiteService, site_files
from .x402 import X402PaymentError, X402Result, X402Wallet, pay_x402, pay_x402_async, read_x402_ask

if TYPE_CHECKING:
    from ._async.passport_session import AsyncPassportSession

try:
    __version__ = version("getstack")
except PackageNotFoundError:
    __version__ = "0+unknown"


def _build_static_auth(
    *,
    api_key: str | None,
    base_url: str,
) -> ApiKeyAuth | CredentialsFileAuth:
    """helper. Resolve a static-bearer auth strategy for the
    one-time agent-enrollment dance — explicit api_key, STACK_API_KEY
    env var, or ~/.stack/credentials.json (CLI-managed OAuth refresh).
    """
    if api_key:
        return ApiKeyAuth(api_key)
    env_key = os.environ.get("STACK_API_KEY")
    if env_key:
        return ApiKeyAuth(env_key)
    return _resolve_creds_or_bootstrap(base_url)


def _resolve_creds_or_bootstrap(base_url: str) -> CredentialsFileAuth:
    """Read ~/.stack/credentials.json — and if it's missing AND the
    process looks interactive (TTY + not CI), spawn the browser-spawn
    OAuth bootstrap to create it. Raises ValueError when neither path
    resolves.
    """
    try:
        return CredentialsFileAuth(api_base_url=base_url)
    except RuntimeError as err:
        from .browser_bootstrap import browser_bootstrap, should_run_browser_bootstrap

        if should_run_browser_bootstrap():
            browser_bootstrap(base_url)
            try:
                return CredentialsFileAuth(api_base_url=base_url)
            except RuntimeError as e:
                raise ValueError(
                    "STACK SDK: browser bootstrap reported success but credentials file still missing."
                ) from e
        raise ValueError("No STACK credentials found. Run `npx @getstackrun/cli auth login`.") from err


__all__ = [
    "AccountCallFailedError",
    "AccountPieceNotReadyError",
    "AccountsService",
    "Agent",
    "AgentBudgetExceededError",
    "AgentIdentityService",
    "AgentIdentityVerificationError",
    "AgentWalletKey",
    "AsyncAccountsService",
    "AsyncAuthorityService",
    "AsyncBrainService",
    "AsyncCatalogueService",
    "AsyncDriveService",
    "AsyncFleetsService",
    "AsyncInstallClient",
    "AsyncMemoryService",
    "AsyncPaymentsService",
    "AsyncStack",
    "AsyncWebsiteService",
    "AuthorityReference",
    "AuthorityService",
    "BrainService",
    "BrowserSessionLengthRefusedError",
    "BrowserTimeUsedUpError",
    "BudgetNeedsControlsError",
    "CalendarService",
    "CatalogueAccountPiece",
    "CatalogueAccountView",
    "CatalogueActionBand",
    "CatalogueConnectedService",
    "CatalogueCostCap",
    "CatalogueDocument",
    "CatalogueEntry",
    "CatalogueKind",
    "CatalogueModalities",
    "CatalogueOrigin",
    "CataloguePrice",
    "CataloguePricing",
    "CatalogueProviderCost",
    "CatalogueRead",
    "CatalogueResultTrust",
    "CatalogueRun",
    "CatalogueSearchResult",
    "CatalogueSection",
    "CatalogueService",
    "CatalogueUnavailableError",
    "CheckoutResult",
    "CheckpointResult",
    "ControlDeniedError",
    "ControlLimitExceededError",
    "ControlPoliciesService",
    "ControlReviewsService",
    "ControlSignatureError",
    "ControlSocketService",
    "ControlsRequiredError",
    "Credential",
    "DeliveryMethodService",
    "DestinationNotAvailableError",
    "DetectorConfigService",
    "DriveService",
    "EmailAttachment",
    "EmailDriveAttachment",
    "EmailDropped",
    "EmailInlineAttachment",
    "EmailSendResult",
    "EmailSentAttachment",
    "FleetsService",
    "ForbiddenError",
    "ForwardEmailInput",
    "GovernanceApprovalRequiredError",
    "GovernanceApprovalStateError",
    "IdentityClaim",
    "IdentityProvider",
    "IdentitySettings",
    "InstallClient",
    "InstallKey",
    "MakingUnavailableError",
    "MemoryService",
    "MessageAccessService",
    "MessageAttachment",
    "MessageEnvelope",
    "Mission",
    "MissionEndedError",
    "ModelCostCapError",
    "NetworkService",
    "NetworkVerificationError",
    "NotFoundError",
    "NotificationChannel",
    "Passport",
    "PassportBlockedError",
    "PassportReport",
    "PassportStackClaims",
    "PaymentConnectionRequiredError",
    "PaymentsService",
    "PiiConfigService",
    "PlatformSubscriptionRequiredError",
    "PostRefusedError",
    "PostService",
    "PostUnavailableError",
    "PostalAddressNotActiveError",
    "ProviderCapacityUnavailableError",
    "ProxyOperation",
    "ProxyResponse",
    "RecipientOptedOutError",
    "ReplaceServiceRequirementResult",
    "ReplayGuard",
    "ReplyEmailInput",
    "ReviewDecisionResult",
    "ReviewFlag",
    "ReviewQueue",
    "ReviewQueueItem",
    "SendEmailInput",
    "ServiceRequirement",
    "SetServiceRequirementInput",
    "SharedMailDailyLimitError",
    "SignedControlAnswer",
    "Skill",
    "SkillInvocation",
    "SkillRequest",
    "Stack",
    "StackError",
    "StripeRequestFailedError",
    "TeamService",
    "TelegramSendRefusedError",
    "ToolCall",
    "ToolPriceRefusedError",
    "ToolRunFile",
    "ToolRunRejectedError",
    "ToolRunResult",
    "ToolsUnavailableError",
    "TrustService",
    "UnauthorizedError",
    "UnboundedSendRuleError",
    "ValidationError",
    "VerificationSession",
    "VerifiedPassportClaims",
    "WakeSignatureError",
    "WakesService",
    "WalletKeyInSandboxError",
    "WalletPaymentTarget",
    "WebhookSignatureError",
    "WebsiteHostnameUnavailableError",
    "WebsiteLimitExceededError",
    "WebsitePublishRejectedError",
    "WebsiteService",
    "WebsiteSuspendedError",
    "X402PaymentError",
    "X402Result",
    "X402Wallet",
    "__version__",
    "create_authority_request_id",
    "generate_agent_wallet_key",
    "install_key_thumbprint",
    "load_agent_wallet_key",
    "passport_digest",
    "pay_x402",
    "pay_x402_async",
    "read_x402_ask",
    "revocation_covers",
    "sign_claim_envelope",
    "sign_control_answer",
    "sign_wallet_payment",
    "site_files",
    "verify_agent_identity",
    "verify_control_request",
    "verify_countersigned_passport",
    "verify_detection_rules",
    "verify_passport_header",
    "verify_passport_offline",
    "verify_revocation_list",
    "verify_verified_statement",
    "verify_wake_webhook",
    "verify_webhook",
    "wallet_payment_authorization_payload",
]


class Stack:
    """Synchronous STACK client.

    Args:
        api_key: A STACK API key (``sk_live_...``).
        base_url: Override the API base URL.
        timeout: HTTP timeout in seconds.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        agent_id: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        _auth: ApiKeyAuth | SessionAuth | OAuthAuth | CredentialsFileAuth | AgentKeypairAuth | None = None,
    ):
        # Four-source resolution, in priority order:
        #   1. Explicit _auth (callers that pre-built a strategy).
        #   2. agent_id (agent keypair runtime mode). Static
        #      bearer is auto-resolved for enrollment via api_key/env/file.
        #   3. api_key arg or STACK_API_KEY env var (legacy sk_live_*).
        #   4. ~/.stack/credentials.json — OAuth refresh token written
        #      by `stack-cli auth login`.
        if _auth:
            auth: ApiKeyAuth | SessionAuth | OAuthAuth | CredentialsFileAuth | AgentKeypairAuth = _auth
        elif agent_id:
            auth = AgentKeypairAuth(
                agent_id=agent_id,
                api_base_url=base_url,
                bearer_provider=lambda: (
                    _build_static_auth(api_key=api_key, base_url=base_url)
                    .get_headers()["Authorization"]
                    .split(" ", 1)[1]
                ),
            )
        elif api_key or os.environ.get("STACK_API_KEY"):
            auth = ApiKeyAuth(api_key or os.environ["STACK_API_KEY"])
        else:
            auth = _resolve_creds_or_bootstrap(base_url)

        self._client = HttpClient(auth, base_url=base_url, timeout=timeout)
        self.agents = AgentService(self._client)
        self.passports = PassportService(self._client)
        self.credentials = CredentialService(self._client)
        self.services = ServiceService(self._client)
        self.dropoffs = DropoffService(self._client)
        self.reviews = ReviewService(self._client)
        self.notifications = NotificationService(self._client)
        self.audit = AuditService(self._client)
        self.proxy = ProxySvc(self._client)
        self.scan = ScanService(self._client)
        self.usage = UsageService(self._client)
        self.billing = BillingService(self._client)
        self.control_socket = ControlSocketService(self._client)
        self.network = NetworkService(self._client)
        self.agent_identity = AgentIdentityService(self._client)
        self.control_policies = ControlPoliciesService(self._client)
        self.control_reviews = ControlReviewsService(self._client)
        self.wakes = WakesService(self._client)
        self.trust = TrustService(self._client)
        self.message_access = MessageAccessService(self._client)
        self.calendar = CalendarService(self._client)
        self.meetings = MeetingsService(self._client)
        self.rentahuman = RentAHumanService(self._client)
        self.governance = GovernanceService(self._client)
        self.flagged_content = FlaggedContentService(self._client)
        self.chat_channels = ChatChannelsService(self._client)
        self.security_events = SecurityEventSvc(self._client)
        self.skills = SkillService(self._client)
        self.identity = IdentityService(self._client)
        self.intents = IntentsService(self._client)
        self.missions = MissionsService(self._client)
        self.fleets = FleetsService(self._client)
        self.evidence_packs = EvidencePacksService(self._client)
        self.llm = LlmService(self._client)
        self.inbound_webhooks = InboundWebhookService(self._client)
        self.partner_accounts = PartnerAccountsService(self._client)
        self.team = TeamService(self._client)
        self.delivery_methods = DeliveryMethodService(self._client)
        self.detector_config = DetectorConfigService(self._client)
        self.pii_config = PiiConfigService(self._client)
        self.authority = AuthorityService(self._client)
        self.accounts = AccountsService(self._client)
        self.catalogue = CatalogueService(self._client)
        self.drive = DriveService(self._client)
        self.memory = MemoryService(self._client)
        self.brain = BrainService(self._client)
        self.website = WebsiteService(self._client)
        self.payments = PaymentsService(self._client)
        self.post = PostService(self._client)

    def issue_passport(
        self,
        *,
        agent_id: str,
        services: list[dict[str, Any]] | None = None,
        intents: list[dict[str, Any]] | None = None,
        ttl_seconds: int | None = None,
        accountability_mode: str | None = None,
        authority_binding_ids: list[str] | None = None,
        mission_ids: list[str] | None = None,
        **kwargs: Any,
    ) -> PassportSession:
        """issue a passport and return a PassportSession
        that holds the token + auto-refreshes ~60s before expiry. Pass
        the returned session to LLM calls instead of threading a raw
        token per call. ``mission_ids`` must hold exactly one Mission id;
        once that Mission ends, refresh raises ``MissionEndedError``::

            mission = stack.missions.open("Answer support tickets", agent_id="agt_x")
            session = stack.issue_passport(agent_id="agt_x", mission_ids=[mission["mission_id"]])
            for i in range(1000):
                stack.llm.anthropic.messages.create(body, passport=session)
        """
        issue_input: dict[str, Any] = {
            "agent_id": agent_id,
            **kwargs,
            "mission_ids": _require_one_mission(mission_ids),
        }
        if services is not None:
            issue_input["services"] = services
        if intents is not None:
            issue_input["intents"] = intents
        if ttl_seconds is not None:
            issue_input["ttl_seconds"] = ttl_seconds
        if accountability_mode is not None:
            issue_input["accountability_mode"] = accountability_mode
        if authority_binding_ids is not None:
            issue_input["authority_binding_ids"] = authority_binding_ids
        issued = self._client.post("/v1/passports/issue", json=issue_input)
        return PassportSession(self._client, issued, issue_input)

    @classmethod
    def from_session(cls, session_token: str, **kwargs: Any) -> Stack:
        """Create a client authenticated with a session JWT."""
        return cls(_auth=SessionAuth(session_token), **kwargs)

    @classmethod
    def from_oauth(
        cls,
        client_id: str,
        client_secret: str,
        access_token: str,
        refresh_token: str,
        token_endpoint: str = "https://api.getstack.run/v1/oauth/token",
        **kwargs: Any,
    ) -> Stack:
        """Create a client with OAuth tokens. Auto-refreshes when expired."""
        auth = OAuthAuth(
            client_id=client_id,
            client_secret=client_secret,
            access_token=access_token,
            refresh_token=refresh_token,
            token_endpoint=token_endpoint,
        )
        return cls(_auth=auth, **kwargs)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def with_control_ref(self, ref: str) -> Stack:
        """The same client with ``X-Control-Ref: <ref>`` on every call it makes.

        When a policy holds a call for the owner, the refusal (``ControlDeniedError``, reason ``review_required``)
        names a ref in ``retry``; once the owner has approved, make the identical call again through this:
        ``stack.with_control_ref(ref).accounts.send_email(...)``. It shares this client's connection and credential
        and is meant for that one call.
        """
        return scoped_stack(self, ref)

    def __enter__(self) -> Stack:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncStack:
    """Asynchronous STACK client.

    full parity with Stack. All 14 typed services are
       async-native, plus AsyncMission for the bounded-mission context
       manager. Uses httpx.AsyncClient under the hood.

       Args:
           api_key: A STACK API key (``sk_live_...``).
           base_url: Override the API base URL.
           timeout: HTTP timeout in seconds.

       Example::

           from getstack import AsyncStack

           async with AsyncStack(api_key="sk_live_...") as stack:
               agents = await stack.agents.list()
               async with stack.passports.mission(
                   agent_id=agents[0].id,
                   intent="Process invoices",
                   services=["slack", "stripe"],
               ) as mission:
                   resp = await mission.proxy(
                       "stripe", "https://api.stripe.com/v1/charges",
                       method="POST", body={"amount": 50},
                       _proxy_service=stack.proxy,
                   )
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        agent_id: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        _auth: ApiKeyAuth | SessionAuth | OAuthAuth | CredentialsFileAuth | AgentKeypairAuth | None = None,
    ):
        # Same four-source resolution as Stack — see Stack.__init__.
        if _auth:
            auth: ApiKeyAuth | SessionAuth | OAuthAuth | CredentialsFileAuth | AgentKeypairAuth = _auth
        elif agent_id:
            auth = AgentKeypairAuth(
                agent_id=agent_id,
                api_base_url=base_url,
                bearer_provider=lambda: (
                    _build_static_auth(api_key=api_key, base_url=base_url)
                    .get_headers()["Authorization"]
                    .split(" ", 1)[1]
                ),
            )
        elif api_key or os.environ.get("STACK_API_KEY"):
            auth = ApiKeyAuth(api_key or os.environ["STACK_API_KEY"])
        else:
            auth = _resolve_creds_or_bootstrap(base_url)

        self._client = AsyncHttpClient(auth, base_url=base_url, timeout=timeout)

        # 14 typed async services attached eagerly
        # matching Stack's posture. Footprint is small; lazy init
        # would only buy us memory we don't need to save.
        from ._async.agent_identity import AsyncAgentIdentityService
        from ._async.agents import AsyncAgentService
        from ._async.audit import AsyncAuditService
        from ._async.authority import AsyncAuthorityService
        from ._async.billing import AsyncBillingService
        from ._async.calendar import AsyncCalendarService
        from ._async.chat_channels import AsyncChatChannelsService
        from ._async.control_policies import AsyncControlPoliciesService, AsyncControlReviewsService
        from ._async.control_socket import AsyncControlSocketService
        from ._async.credentials import AsyncCredentialService
        from ._async.delivery_methods import AsyncDeliveryMethodService
        from ._async.detector_config import AsyncDetectorConfigService
        from ._async.dropoffs import AsyncDropoffService
        from ._async.evidence_packs import AsyncEvidencePacksService
        from ._async.flagged_content import AsyncFlaggedContentService
        from ._async.governance import AsyncGovernanceService
        from ._async.identity import AsyncIdentityService
        from ._async.inbound_webhooks import AsyncInboundWebhookService
        from ._async.intents import AsyncIntentsService
        from ._async.llm import AsyncLlmService
        from ._async.meetings import AsyncMeetingsService
        from ._async.message_access import AsyncMessageAccessService
        from ._async.missions import AsyncMissionsService
        from ._async.network import AsyncNetworkService
        from ._async.notifications import AsyncNotificationService
        from ._async.partner_accounts import AsyncPartnerAccountsService
        from ._async.passport_session import AsyncPassportSession
        from ._async.passports import AsyncPassportService
        from ._async.pii_config import AsyncPiiConfigService
        from ._async.post import AsyncPostService
        from ._async.proxy import AsyncProxyService
        from ._async.rentahuman import AsyncRentAHumanService
        from ._async.reviews import AsyncReviewService
        from ._async.scan import AsyncScanService
        from ._async.security_events import AsyncSecurityEventService
        from ._async.services import AsyncServiceService
        from ._async.skills import AsyncSkillService
        from ._async.team import AsyncTeamService
        from ._async.trust import AsyncTrustService
        from ._async.usage import AsyncUsageService
        from ._async.wake import AsyncWakesService

        self.agents = AsyncAgentService(self._client)
        self.passports = AsyncPassportService(self._client)
        self.credentials = AsyncCredentialService(self._client)
        self.services = AsyncServiceService(self._client)
        self.dropoffs = AsyncDropoffService(self._client)
        self.reviews = AsyncReviewService(self._client)
        self.notifications = AsyncNotificationService(self._client)
        self.audit = AsyncAuditService(self._client)
        self.proxy = AsyncProxyService(self._client)
        self.scan = AsyncScanService(self._client)
        self.usage = AsyncUsageService(self._client)
        self.billing = AsyncBillingService(self._client)
        self.control_socket = AsyncControlSocketService(self._client)
        self.network = AsyncNetworkService(self._client)
        self.agent_identity = AsyncAgentIdentityService(self._client)
        self.control_policies = AsyncControlPoliciesService(self._client)
        self.control_reviews = AsyncControlReviewsService(self._client)
        self.wakes = AsyncWakesService(self._client)
        self.trust = AsyncTrustService(self._client)
        self.message_access = AsyncMessageAccessService(self._client)
        self.calendar = AsyncCalendarService(self._client)
        self.meetings = AsyncMeetingsService(self._client)
        self.rentahuman = AsyncRentAHumanService(self._client)
        self.governance = AsyncGovernanceService(self._client)
        self.flagged_content = AsyncFlaggedContentService(self._client)
        self.chat_channels = AsyncChatChannelsService(self._client)
        self.security_events = AsyncSecurityEventService(self._client)
        self.skills = AsyncSkillService(self._client)
        self.identity = AsyncIdentityService(self._client)
        self.intents = AsyncIntentsService(self._client)
        self.missions = AsyncMissionsService(self._client)
        self.fleets = AsyncFleetsService(self._client)
        self.llm = AsyncLlmService(self._client)
        self.inbound_webhooks = AsyncInboundWebhookService(self._client)
        self.partner_accounts = AsyncPartnerAccountsService(self._client)
        self.evidence_packs = AsyncEvidencePacksService(self._client)
        self.team = AsyncTeamService(self._client)
        self.delivery_methods = AsyncDeliveryMethodService(self._client)
        self.detector_config = AsyncDetectorConfigService(self._client)
        self.pii_config = AsyncPiiConfigService(self._client)
        self.authority = AsyncAuthorityService(self._client)
        self.accounts = AsyncAccountsService(self._client)
        self.catalogue = AsyncCatalogueService(self._client)
        self.drive = AsyncDriveService(self._client)
        self.memory = AsyncMemoryService(self._client)
        self.brain = AsyncBrainService(self._client)
        self.website = AsyncWebsiteService(self._client)
        self.payments = AsyncPaymentsService(self._client)
        self.post = AsyncPostService(self._client)
        # Stash for issue_passport() — Python doesn't easily expose the
        # class binding without re-importing inside the method body.
        self._AsyncPassportSession = AsyncPassportSession

    async def issue_passport(
        self,
        *,
        agent_id: str,
        services: list[dict[str, Any]] | None = None,
        intents: list[dict[str, Any]] | None = None,
        ttl_seconds: int | None = None,
        accountability_mode: str | None = None,
        authority_binding_ids: list[str] | None = None,
        mission_ids: list[str] | None = None,
        **kwargs: Any,
    ) -> AsyncPassportSession:
        """async passport issue + session wrapper.
        ``mission_ids`` must hold exactly one Mission id."""
        issue_input: dict[str, Any] = {
            "agent_id": agent_id,
            **kwargs,
            "mission_ids": _require_one_mission(mission_ids),
        }
        if services is not None:
            issue_input["services"] = services
        if intents is not None:
            issue_input["intents"] = intents
        if ttl_seconds is not None:
            issue_input["ttl_seconds"] = ttl_seconds
        if accountability_mode is not None:
            issue_input["accountability_mode"] = accountability_mode
        if authority_binding_ids is not None:
            issue_input["authority_binding_ids"] = authority_binding_ids
        issued = await self._client.post("/v1/passports/issue", json=issue_input)
        return self._AsyncPassportSession(self._client, issued, issue_input)

    @classmethod
    def from_session(cls, session_token: str, **kwargs: Any) -> AsyncStack:
        """Create an async client authenticated with a session JWT."""
        return cls(_auth=SessionAuth(session_token), **kwargs)

    @classmethod
    def from_oauth(
        cls,
        client_id: str,
        client_secret: str,
        access_token: str,
        refresh_token: str,
        token_endpoint: str = "https://api.getstack.run/v1/oauth/token",
        **kwargs: Any,
    ) -> AsyncStack:
        """Create an async client with OAuth tokens. Auto-refreshes when expired."""
        auth = OAuthAuth(
            client_id=client_id,
            client_secret=client_secret,
            access_token=access_token,
            refresh_token=refresh_token,
            token_endpoint=token_endpoint,
        )
        return cls(_auth=auth, **kwargs)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.close()

    def with_control_ref(self, ref: str) -> AsyncStack:
        """The same client with ``X-Control-Ref: <ref>`` on every call it makes (see ``Stack.with_control_ref``)."""
        return scoped_stack(self, ref)

    async def __aenter__(self) -> AsyncStack:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
