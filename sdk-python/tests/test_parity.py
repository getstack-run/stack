"""Surface-parity guard for the Python SDK.

Asserts the sync Stack and async AsyncStack expose the same services and
that the services carry the methods a real integration needs. This is the
regression guard for the Python-parity work: if a new service or
method is added to one client and not the other (the exact sync/async drift
that let the async `register` fall behind), this fails.

Run: python -m pytest sdk-python/tests/test_parity.py
     (or: python sdk-python/tests/test_parity.py)
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import (
    AccountPieceNotReadyError,
    AccountsService,
    AgentBudgetExceededError,
    AsyncAccountsService,
    AsyncAuthorityService,
    AsyncCatalogueService,
    AsyncStack,
    AuthorityReference,
    AuthorityService,
    CatalogueAccountView,
    CatalogueDocument,
    CatalogueEntry,
    CatalogueRead,
    CatalogueSearchResult,
    CatalogueService,
    CatalogueUnavailableError,
    DeliveryMethodService,
    DetectorConfigService,
    GovernanceApprovalRequiredError,
    PiiConfigService,
    ReplaceServiceRequirementResult,
    ServiceRequirement,
    SetServiceRequirementInput,
    Stack,
    TeamService,
    ToolRunFile,
    ToolRunResult,
    VerifiedPassportClaims,
    WalletKeyInSandboxError,
    generate_agent_wallet_key,
    load_agent_wallet_key,
    sign_claim_envelope,
    sign_wallet_payment,
    verify_passport_header,
    verify_passport_offline,
    wallet_payment_authorization_payload,
)
from getstack._async.missions import AsyncMissionsService
from getstack._async.passports import AsyncPassportService
from getstack.missions import MissionsService
from getstack.passports import PassportService

# Services that must exist on BOTH clients.
EXPECTED_SERVICES = [
    "agents",
    "passports",
    "credentials",
    "services",
    "dropoffs",
    "reviews",
    "notifications",
    "audit",
    "proxy",
    "scan",
    "usage",
    "security_events",
    "skills",
    "identity",
    "intents",
    "missions",
    "evidence_packs",
    "llm",
    "inbound_webhooks",
    "partner_accounts",
    "team",
    "delivery_methods",
    "detector_config",
    "pii_config",
    "authority",
    "fleets",
    "accounts",
    "catalogue",
    "drive",
    "memory",
    "brain",
    "billing",
    "governance",
    "flagged_content",
    "control_socket",
    "network",
    "agent_identity",
    "control_policies",
    "control_reviews",
    "wakes",
    "trust",
    "message_access",
    "calendar",
    "meetings",
    "rentahuman",
    "chat_channels",
    "website",
    "payments",
    "post",
]

# (service, method) pairs that must exist on both clients — the integration-
# critical surface, incl. the gaps an earlier change closed.
EXPECTED_METHODS = [
    ("fleets", "workload_enrollment_challenge"),
    ("fleets", "enroll_workload"),
    ("fleets", "enroll_workload_local"),
    ("fleets", "members"),
    ("fleets", "revoke_member"),
    ("fleets", "session"),
    ("fleets", "enroll_local"),
    ("fleets", "list"),
    ("fleets", "activate"),
    ("fleets", "revise"),
    ("fleets", "revoke"),
    ("fleets", "enrollment_challenge"),
    ("fleets", "enroll"),
    ("agents", "setup"),
    ("agents", "dismiss_warnings"),
    ("agents", "overview"),
    ("missions", "start"),
    ("missions", "renew"),
    ("missions", "review"),
    ("missions", "set_making_allowance"),
    ("inbound_webhooks", "set_provider_signing_secret"),
    ("services", "connect"),
    ("services", "connect_custom"),
    ("services", "rename"),
    ("services", "grant_agent_access"),
    ("services", "revoke_agent_access"),
    ("services", "get_agent_permissions"),
    ("passports", "issue"),
    ("passports", "delegate"),
    ("passports", "revoke"),
    ("passports", "revoke_agent"),
    ("passports", "revoke_session"),
    ("passports", "revoke_all"),
    ("passports", "list_active"),
    ("dropoffs", "expire"),
    ("notifications", "update"),
    ("team", "invite"),
    ("team", "clear_sso_bindings"),
    ("delivery_methods", "add"),
    ("delivery_methods", "rotate_secret"),
    ("detector_config", "upsert"),
    ("pii_config", "get"),
    ("pii_config", "update"),
    ("pii_config", "reset"),
    ("identity", "get_verification_session"),
    ("identity", "replace_service_requirement"),
    ("identity", "list_sso_domains"),
    ("identity", "add_sso_domain"),
    ("identity", "verify_sso_domain"),
    ("identity", "remove_sso_domain"),
    ("usage", "get"),
    ("missions", "activity"),
    ("missions", "list_operator_reviews"),
    ("missions", "download_operator_review"),
    ("missions", "add_recipients"),
    ("authority", "create_principal"),
    ("authority", "create_enterprise_oidc_request"),
    ("authority", "get_enterprise_oidc_request"),
    ("authority", "import_proof"),
    ("authority", "create_binding"),
    ("authority", "activate_binding"),
    ("authority", "create_receiver"),
    ("authority", "list_uses"),
    ("drive", "upload"),
    ("drive", "create_upload_link"),
    ("drive", "upload_to_link"),
    ("drive", "list"),
    ("drive", "get"),
    ("drive", "read"),
    ("drive", "update"),
    ("drive", "copy"),
    ("drive", "delete"),
    ("drive", "share"),
    ("drive", "links"),
    ("drive", "revoke_link"),
    ("memory", "add_memory"),
    ("memory", "add_triplet"),
    ("memory", "search_nodes"),
    ("memory", "search_memory_facts"),
    ("memory", "get_episodes"),
    ("memory", "get_entity_edge"),
    ("memory", "get_episode_entities"),
    ("memory", "delete_episode"),
    ("memory", "delete_entity_edge"),
    ("memory", "summarize_saga"),
    ("memory", "get_settings"),
    ("memory", "update_settings"),
    ("memory", "list_entity_types"),
    ("memory", "create_entity_type"),
    ("memory", "update_entity_type"),
    ("memory", "retire_entity_type"),
    ("memory", "get_history"),
    ("memory", "undo_write"),
    ("brain", "add"),
    ("brain", "remove"),
    ("brain", "search"),
    ("brain", "list"),
    ("accounts", "open"),
    ("accounts", "get"),
    ("accounts", "list"),
    ("accounts", "close"),
    ("accounts", "send_email"),
    ("accounts", "reply_email"),
    ("accounts", "forward_email"),
    ("accounts", "send_sms"),
    ("accounts", "resume_piece"),
    ("accounts.messages", "list"),
    ("accounts.messages", "get"),
    ("accounts.messages", "delete"),
    ("accounts.opt_outs", "list"),
    ("accounts.opt_outs", "add"),
    ("accounts.opt_outs", "remove"),
    ("accounts.blocked_callers", "list"),
    ("accounts.blocked_callers", "add"),
    ("accounts.blocked_callers", "remove"),
    ("accounts.toll_free_verification", "submit"),
    ("accounts.toll_free_verification", "get"),
    ("accounts.calls", "place"),
    ("accounts.calls", "list"),
    ("accounts.calls", "get"),
    ("accounts.calls", "answer"),
    ("accounts.calls", "decline"),
    ("accounts.calls", "say"),
    ("accounts.calls", "press_keys"),
    ("accounts.calls", "set_call_voice"),
    ("accounts.calls", "hang_up"),
    ("accounts.calls", "get_account_voice"),
    ("accounts.calls", "set_account_voice"),
    ("accounts.calls", "live"),
    ("accounts.tools", "discover"),
    ("accounts.tools", "inspect"),
    ("accounts.tools", "run"),
    ("accounts.tools", "get_run"),
    ("accounts.workspace", "exec"),
    ("accounts.workspace", "read_file"),
    ("accounts.workspace", "write_file"),
    ("accounts.workspace", "save_file"),
    ("accounts.workspace", "list"),
    ("accounts.workspace", "set_sharing"),
    ("accounts.workspace", "stop"),
    ("accounts.browser", "start_session"),
    ("accounts.browser", "navigate"),
    ("accounts.browser", "act"),
    ("accounts.browser", "read"),
    ("accounts.browser", "screenshot"),
    ("accounts.browser", "end_session"),
    ("accounts.browser", "checkout"),
    ("accounts.purchases", "get"),
    ("accounts.purchases", "report_merchant_result"),
    ("accounts.wallet", "pay"),
    ("accounts.wallet", "pay_url"),
    ("accounts.wallet", "owner_status"),
    ("accounts.mail_domains", "list"),
    ("accounts.mail_domains", "connect"),
    ("accounts.mail_domains", "verify"),
    ("catalogue", "get"),
    ("catalogue", "search"),
    ("catalogue", "for_account"),
    ("accounts.signing_keys", "list"),
    ("accounts.signing_keys", "rotate"),
    ("accounts.identity", "get"),
    ("accounts.identity", "update"),
    ("billing", "subscriptions"),
    ("billing", "subscribe_platform"),
    ("billing", "subscribe_controls"),
    ("website", "publish"),
    ("website", "add_hostname"),
    ("website", "set_prices"),
    ("website", "suspend"),
    ("website", "report"),
    ("payments", "start_stripe"),
    ("payments", "create_link"),
    ("payments", "create_checkout_session"),
    ("payments", "list_payments"),
    ("services", "create_connect_link"),
    ("services", "get_connect_link"),
    ("governance", "get_approval"),
    ("governance", "list_approvals"),
    ("control_socket", "get"),
    ("control_socket", "set_decision_address"),
    ("control_socket", "set_events_address"),
    ("control_socket", "clear"),
    ("control_socket", "verify"),
    ("control_socket", "test"),
    ("control_socket", "rotate_secret"),
    ("control_socket", "set_mode"),
    ("control_socket", "set_checked_types"),
    ("control_socket", "set_on_unavailable"),
    ("control_socket", "list_decisions"),
    ("control_socket", "get_decision"),
    ("network", "publish_revocation"),
    ("network", "jwks"),
    ("network", "signed_revocations"),
    ("network", "revocations"),
    ("network", "verify"),
    ("network", "verified"),
    ("agent_identity", "lookup"),
    ("agent_identity", "verified"),
    ("agent_identity", "urls"),
    ("network.installs", "register"),
    ("network.installs", "list"),
    ("network.installs", "get"),
    ("network.installs", "request_key_challenge"),
    ("network.installs", "add_key"),
    ("network.installs", "register_key"),
    ("network.installs", "revoke_key"),
    ("network.installs", "revoke"),
    ("network.subscriptions", "create"),
    ("network.subscriptions", "list"),
    ("network.subscriptions", "delete"),
    ("network.subscriptions", "resume"),
    ("network.licences", "revoke"),
    ("network.licences", "list"),
    ("control_policies", "list"),
    ("control_policies", "get"),
    ("control_policies", "set"),
    ("control_policies", "delete"),
    ("control_policies", "start_from_current_access"),
    ("control_policies", "simulate"),
    ("control_policies", "revisions"),
    ("control_reviews", "list"),
    ("control_reviews", "get"),
    ("wakes", "list"),
    ("wakes", "acknowledge"),
    ("wakes", "set_settings"),
    ("wakes", "rotate_webhook_secret"),
    ("wakes", "create_rule"),
    ("wakes", "create_schedule"),
    ("calendar", "list_events"),
    ("calendar", "create_event"),
    ("calendar", "update_event"),
    ("calendar", "cancel_event"),
    ("calendar", "agenda"),
    ("calendar", "respond"),
    ("calendar", "rotate_feed"),
    ("meetings", "join"),
    ("meetings", "say"),
    ("meetings", "chat"),
    ("meetings", "leave"),
    ("meetings", "live"),
    ("meetings", "get_voice"),
    ("meetings", "set_voice"),
    ("rentahuman", "join"),
    ("rentahuman", "complete_join"),
    ("rentahuman", "join_with_key"),
    ("rentahuman", "fund"),
    ("rentahuman", "complete_fund"),
    ("rentahuman", "fund_with_key"),
    ("rentahuman", "get"),
    ("proxy", "service_tools"),
    ("proxy", "service_call_tool"),
    ("post", "get_address"),
    ("post", "start_address"),
    ("post", "connect_address"),
    ("post", "scan_item"),
    ("post", "forward_item"),
    ("post", "shred_item"),
    ("post", "check_address"),
    ("post", "send"),
    ("post", "list_letters"),
    ("post", "get_letter"),
]


def _service(client, path):
    for part in path.split("."):
        client = getattr(client, part)
    return client


def _clients():
    kw = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    return Stack(**kw), AsyncStack(**kw)


def test_both_clients_have_all_services():
    s, a = _clients()
    for name in EXPECTED_SERVICES:
        assert hasattr(s, name), f"sync Stack missing service '{name}'"
        assert hasattr(a, name), f"async AsyncStack missing service '{name}'"


def test_both_clients_have_all_methods():
    s, a = _clients()
    for svc, method in EXPECTED_METHODS:
        assert hasattr(_service(s, svc), method), f"sync {svc}.{method} missing"
        assert hasattr(_service(a, svc), method), f"async {svc}.{method} missing"


def test_register_accepts_key_mode_on_both():
    s, a = _clients()
    assert "key_mode" in inspect.signature(s.agents.register).parameters
    assert "key_mode" in inspect.signature(a.agents.register).parameters
    # And profile / credential_access (the posture fields).
    for client in (s, a):
        params = inspect.signature(client.agents.register).parameters
        assert "profile" in params and "credential_access" in params
        # LLM gateway toggles.
        assert "llm_inject_system_prompt" in params and "llm_redact_pii" in params


def test_dropoff_agent_calls_accept_a_passport_on_both():
    # Every agent drop-off action needs a Mission Passport (beginAgentRuntime).
    s, a = _clients()
    for client in (s, a):
        for method in ("create", "deposit", "collect"):
            params = inspect.signature(getattr(client.dropoffs, method)).parameters
            assert "passport_token" in params, f"dropoffs.{method} lacks passport_token"


def test_account_governance_actions_accept_an_approval_on_both():
    # Submitting toll-free details is a governance step-up. Resuming a paused piece is not.
    s, a = _clients()
    for client in (s, a):
        assert "governance_approval_id" not in inspect.signature(client.accounts.resume_piece).parameters
        for method in (client.accounts.toll_free_verification.submit,):
            assert "governance_approval_id" in inspect.signature(method).parameters, method.__qualname__


def test_billing_governance_actions_accept_an_approval_on_both():
    # Starting a subscription is a governance step-up.
    s, a = _clients()
    for client in (s, a):
        for method in (
            client.billing.subscribe_platform,
            client.billing.subscribe_controls,
        ):
            assert "governance_approval_id" in inspect.signature(method).parameters, method.__qualname__


def test_control_socket_governance_actions_accept_an_approval_on_both():
    # An address change, a rotation and anything that loosens are governance step-ups.
    s, a = _clients()
    for client in (s, a):
        for method in (
            client.control_socket.set_decision_address,
            client.control_socket.set_events_address,
            client.control_socket.clear,
            client.control_socket.verify,
            client.control_socket.rotate_secret,
            client.control_socket.set_mode,
            client.control_socket.set_checked_types,
            client.control_socket.set_on_unavailable,
        ):
            assert "governance_approval_id" in inspect.signature(method).parameters, method.__qualname__


def test_control_policy_governance_actions_accept_an_approval_on_both():
    # Loosening or deleting a policy waits for a person; the retry carries the approval.
    s, a = _clients()
    for client in (s, a):
        for method in (
            client.control_policies.set,
            client.control_policies.delete,
            client.control_policies.start_from_current_access,
        ):
            assert "governance_approval_id" in inspect.signature(method).parameters, method.__qualname__


# Minimal valid agent response for _to_agent; llm_redact_pii=False proves
# the response field lands on the model instead of the True fallback.
_AGENT_RESPONSE = {
    "id": "agent_x",
    "operator_id": "op_x",
    "name": "bot",
    "status": "active",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "llm_inject_system_prompt": True,
    "llm_redact_pii": False,
}


class _CaptureClient:
    """Stands in for HttpClient/AsyncHttpClient; records the last body."""

    def __init__(self, is_async: bool = False):
        self.is_async = is_async
        self.json = None

    def _record(self, json):
        self.json = json
        return dict(_AGENT_RESPONSE)

    def post(self, path, json=None, **kw):
        if self.is_async:

            async def _coro():
                return self._record(json)

            return _coro()
        return self._record(json)

    patch = post


# Minimal valid passport response for _to_passport.
_PASSPORT_RESPONSE = {
    "token": "eyJfake",
    "jti": "ppt_x",
    "expires_at": "2026-01-01T00:00:00Z",
}


class _PassportCaptureClient:
    """Records the last body posted to /v1/passports/issue."""

    def __init__(self, is_async: bool = False):
        self.is_async = is_async
        self.json = None

    def _record(self, json):
        self.json = json
        return dict(_PASSPORT_RESPONSE)

    def post(self, path, json=None, **kw):
        if self.is_async:

            async def _coro():
                return self._record(json)

            return _coro()
        return self._record(json)


def test_register_llm_toggles_round_trip_sync():
    s, _ = _clients()
    s.agents._client = stub = _CaptureClient()
    agent = s.agents.register("bot", llm_inject_system_prompt=True, llm_redact_pii=False)
    # Both flags reach the body; explicit False is sent, not dropped.
    assert stub.json["llm_inject_system_prompt"] is True
    assert stub.json["llm_redact_pii"] is False
    # And the response fields land on the Agent model.
    assert agent.llm_inject_system_prompt is True and agent.llm_redact_pii is False
    # Unset -> omitted, so the server/profile default is never clobbered.
    s.agents.register("bot2")
    assert "llm_inject_system_prompt" not in stub.json
    assert "llm_redact_pii" not in stub.json


def test_register_llm_toggles_round_trip_async():
    import asyncio

    _, a = _clients()
    a.agents._client = stub = _CaptureClient(is_async=True)
    agent = asyncio.run(a.agents.register("bot", llm_redact_pii=False))
    assert stub.json["llm_redact_pii"] is False
    assert "llm_inject_system_prompt" not in stub.json
    assert agent.llm_redact_pii is False


def test_update_llm_toggles_pass_through():
    s, _ = _clients()
    s.agents._client = stub = _CaptureClient()
    agent = s.agents.update("agent_x", llm_redact_pii=False)
    assert stub.json == {"llm_redact_pii": False}
    assert agent.llm_redact_pii is False


def test_register_names_no_mode_and_sends_eval_traffic_only_when_set():
    s, a = _clients()
    s.agents._client = stub = _CaptureClient()
    s.agents.register("bot")
    # A bare registration names nothing: the server default (logged) applies, and nothing clobbers it.
    assert stub.json == {"name": "bot"}
    s.agents.register("bot", eval_traffic=True, accountability_mode="enforced")
    assert stub.json == {"name": "bot", "accountability_mode": "enforced", "eval_traffic": True}
    s.agents.register("bot", eval_traffic=False)
    assert stub.json["eval_traffic"] is False

    import asyncio

    a.agents._client = astub = _CaptureClient(is_async=True)
    asyncio.run(a.agents.register("bot", eval_traffic=True))
    assert astub.json == {"name": "bot", "eval_traffic": True}


class _RecordingClient:
    """Records each request of the sync/async agent setup and dismissal calls."""

    def __init__(self, is_async: bool = False):
        self.is_async = is_async
        self.calls: list[tuple[str, dict, dict | None]] = []

    def post(self, path, json=None, extra_headers=None, **kw):
        self.calls.append((path, json, extra_headers))
        if self.is_async:

            async def _coro():
                return {"ok": True}

            return _coro()
        return {"ok": True}


def test_setup_is_one_request_with_the_approval_header_on_the_retry():
    s, a = _clients()
    s.agents._client = stub = _RecordingClient()
    grant = {"service_connection_id": "scon_a", "scopes": ["read"]}
    hosts = {"service_connection_id": "scon_a", "allowed_hosts": ["api.example.com"]}
    s.agents.setup({"name": "bot"}, grants=[grant], allowed_hosts=[hosts])
    s.agents.setup({"name": "bot"}, grants=[grant], governance_approval_id="gvr_1")
    first, retry = stub.calls
    assert first == (
        "/v1/agents/setup",
        {"agent": {"name": "bot"}, "grants": [grant], "allowed_hosts": [hosts]},
        None,
    )
    assert retry[1] == {"agent": {"name": "bot"}, "grants": [grant], "allowed_hosts": []}
    assert retry[2] == {"X-Governance-Approval": "gvr_1"}

    import asyncio

    a.agents._client = astub = _RecordingClient(is_async=True)
    asyncio.run(a.agents.setup({"name": "bot"}, grants=[grant], governance_approval_id="gvr_1"))
    assert astub.calls[0][2] == {"X-Governance-Approval": "gvr_1"}


def test_dismiss_warnings_posts_an_empty_body_to_the_agent_route():
    s, a = _clients()
    s.agents._client = stub = _RecordingClient()
    s.agents.dismiss_warnings("agt_one")
    assert stub.calls == [("/v1/agents/agt_one/dismiss-warnings", {}, None)]

    import asyncio

    a.agents._client = astub = _RecordingClient(is_async=True)
    asyncio.run(a.agents.dismiss_warnings("agt_one"))
    assert astub.calls == [("/v1/agents/agt_one/dismiss-warnings", {}, None)]


_ADF_SCOPES = [
    {
        "service_connection_id": "scon_resend",
        "scopes": ["email:send"],
        "allow_data_from": ["guestbook"],
    }
]


def test_issue_threads_allow_data_from_sync():
    s, _ = _clients()
    s.passports._client = stub = _PassportCaptureClient()
    s.passports.issue(agent_id="agt_x", mission_ids=["ms_x"], scopes=_ADF_SCOPES)
    # The per-scope allow_data_from reaches the issue body verbatim.
    assert stub.json["scopes"][0]["allow_data_from"] == ["guestbook"]
    assert stub.json["mission_ids"] == ["ms_x"]


def test_issue_threads_allow_data_from_async():
    import asyncio

    _, a = _clients()
    a.passports._client = stub = _PassportCaptureClient(is_async=True)
    asyncio.run(a.passports.issue(agent_id="agt_x", mission_ids=["ms_x"], scopes=_ADF_SCOPES))
    assert stub.json["scopes"][0]["allow_data_from"] == ["guestbook"]
    assert stub.json["mission_ids"] == ["ms_x"]


def test_issue_threads_authority_binding_ids_sync():
    s, _ = _clients()
    s.passports._client = stub = _PassportCaptureClient()
    s.passports.issue(agent_id="agt_x", mission_ids=["ms_x"], authority_binding_ids=["abn_tax"])
    assert stub.json["authority_binding_ids"] == ["abn_tax"]


def test_issue_threads_authority_binding_ids_async():
    import asyncio

    _, a = _clients()
    a.passports._client = stub = _PassportCaptureClient(is_async=True)
    asyncio.run(a.passports.issue(agent_id="agt_x", mission_ids=["ms_x"], authority_binding_ids=["abn_tax"]))
    assert stub.json["authority_binding_ids"] == ["abn_tax"]


def test_issue_requires_exactly_one_mission():
    import asyncio

    import pytest

    s, a = _clients()
    s.passports._client = stub = _PassportCaptureClient()
    a.passports._client = astub = _PassportCaptureClient(is_async=True)
    for bad in (None, [], ["ms_a", "ms_b"], [""]):
        with pytest.raises(ValueError, match="exactly one Mission"):
            s.passports.issue(agent_id="agt_x", mission_ids=bad)
        with pytest.raises(ValueError, match="exactly one Mission"):
            asyncio.run(a.passports.issue(agent_id="agt_x", mission_ids=bad))
        with pytest.raises(ValueError, match="exactly one Mission"):
            s.issue_passport(agent_id="agt_x", mission_ids=bad)
    # Refused before any request.
    assert stub.json is None and astub.json is None


def test_mission_context_manager_signature_parity():
    for name in ("mission", "continuous_mission"):
        sync_params = list(inspect.signature(getattr(PassportService, name)).parameters)
        async_params = list(inspect.signature(getattr(AsyncPassportService, name)).parameters)
        assert sync_params == async_params
        assert "mission_id" in sync_params and "expires_in" in sync_params
    assert list(inspect.signature(MissionsService.start).parameters) == list(
        inspect.signature(AsyncMissionsService.start).parameters
    )
    assert "agent_id" in inspect.signature(MissionsService.open).parameters
    assert "agent_id" in inspect.signature(AsyncMissionsService.open).parameters


def test_authority_service_method_parity():
    sync_methods = {
        name for name, value in inspect.getmembers(AuthorityService, inspect.isfunction) if not name.startswith("_")
    }
    async_methods = {
        name
        for name, value in inspect.getmembers(AsyncAuthorityService, inspect.isfunction)
        if not name.startswith("_")
    }
    assert sync_methods == async_methods


def test_offline_crypto_exported():
    assert callable(verify_passport_offline)
    assert callable(verify_passport_header)
    assert callable(sign_claim_envelope)
    assert callable(generate_agent_wallet_key) and callable(load_agent_wallet_key)
    assert callable(sign_wallet_payment) and callable(wallet_payment_authorization_payload)


def test_service_classes_exported():
    assert TeamService and DeliveryMethodService and DetectorConfigService
    assert PiiConfigService
    assert AuthorityService and AsyncAuthorityService
    assert AuthorityReference and VerifiedPassportClaims
    assert SetServiceRequirementInput and ServiceRequirement
    assert ReplaceServiceRequirementResult
    assert AccountsService and AsyncAccountsService
    assert GovernanceApprovalRequiredError and AgentBudgetExceededError and AccountPieceNotReadyError
    assert WalletKeyInSandboxError
    assert CatalogueService and AsyncCatalogueService and CatalogueRead
    assert CatalogueUnavailableError
    assert CatalogueDocument and CatalogueEntry and CatalogueSearchResult and CatalogueAccountView
    assert ToolRunFile and ToolRunResult


if __name__ == "__main__":
    test_both_clients_have_all_services()
    test_both_clients_have_all_methods()
    test_register_accepts_key_mode_on_both()
    test_register_llm_toggles_round_trip_sync()
    test_register_llm_toggles_round_trip_async()
    test_update_llm_toggles_pass_through()
    test_issue_threads_allow_data_from_sync()
    test_issue_threads_allow_data_from_async()
    test_issue_threads_authority_binding_ids_sync()
    test_issue_threads_authority_binding_ids_async()
    test_issue_requires_exactly_one_mission()
    test_mission_context_manager_signature_parity()
    test_authority_service_method_parity()
    test_offline_crypto_exported()
    test_service_classes_exported()
    print("all parity tests passed")
