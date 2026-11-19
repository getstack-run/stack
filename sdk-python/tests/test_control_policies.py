"""Control policies and reviews: request shapes (sync and async alike), approval headers, errors and the routes."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.control_policies import AsyncControlPoliciesService, AsyncControlReviewsService
from getstack._async.services import AsyncServiceService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.control_policies import ControlPoliciesService, ControlReviewsService
from getstack.errors import (
    ControlDeniedError,
    ControlLimitExceededError,
    ForbiddenError,
    GovernanceApprovalRequiredError,
    UnboundedSendRuleError,
)
from getstack.services import ServiceService

DEFINITION: dict[str, Any] = {"name": "Support agent", "spend": {"max_per_action_cents": 500}}
CALL: dict[str, Any] = {"action": "card.checkout", "amount_cents": 900, "target": {"merchant": "shop.example.com"}}
APPROVAL = {"X-Governance-Approval": "gvr_1"}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive_sync(policies: ControlPoliciesService, reviews: ControlReviewsService) -> None:
    policies.list()
    policies.get("default")
    policies.get("agt_1")
    policies.set("default", DEFINITION)
    policies.set("agt_1", DEFINITION, expected_revision=0, governance_approval_id="gvr_1")
    policies.delete("default")
    policies.delete("agt_1", expected_revision=3, governance_approval_id="gvr_1")
    policies.start_from_current_access("agt_1")
    policies.start_from_current_access("agt_1", governance_approval_id="gvr_1")
    policies.simulate(CALL, agent_id="agt_1")
    policies.simulate(CALL, definition=DEFINITION)
    policies.revisions("cpl_1")
    reviews.list()
    reviews.list(status="all", limit=20)
    reviews.get("crv_1")


async def _drive_async(policies: AsyncControlPoliciesService, reviews: AsyncControlReviewsService) -> None:
    await policies.list()
    await policies.get("default")
    await policies.get("agt_1")
    await policies.set("default", DEFINITION)
    await policies.set("agt_1", DEFINITION, expected_revision=0, governance_approval_id="gvr_1")
    await policies.delete("default")
    await policies.delete("agt_1", expected_revision=3, governance_approval_id="gvr_1")
    await policies.start_from_current_access("agt_1")
    await policies.start_from_current_access("agt_1", governance_approval_id="gvr_1")
    await policies.simulate(CALL, agent_id="agt_1")
    await policies.simulate(CALL, definition=DEFINITION)
    await policies.revisions("cpl_1")
    await reviews.list()
    await reviews.list(status="all", limit=20)
    await reviews.get("crv_1")


EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", "/v1/control-policies", {}),
    ("GET", "/v1/control-policies/default", {}),
    ("GET", "/v1/control-policies/agents/agt_1", {}),
    ("PUT", "/v1/control-policies/default", {"json": {"definition": DEFINITION}, "extra_headers": None}),
    (
        "PUT",
        "/v1/control-policies/agents/agt_1",
        {"json": {"definition": DEFINITION, "expected_revision": 0}, "extra_headers": APPROVAL},
    ),
    ("DELETE", "/v1/control-policies/default", {"params": None, "extra_headers": None}),
    (
        "DELETE",
        "/v1/control-policies/agents/agt_1",
        {"params": {"expected_revision": 3}, "extra_headers": APPROVAL},
    ),
    ("POST", "/v1/control-policies/agents/agt_1/start-from-current-access", {"json": {}, "extra_headers": None}),
    ("POST", "/v1/control-policies/agents/agt_1/start-from-current-access", {"json": {}, "extra_headers": APPROVAL}),
    ("POST", "/v1/control-policies/simulate", {"json": {"call": CALL, "agent_id": "agt_1"}}),
    ("POST", "/v1/control-policies/simulate", {"json": {"call": CALL, "definition": DEFINITION}}),
    ("GET", "/v1/control-policies/cpl_1/revisions", {}),
    ("GET", "/v1/control-reviews", {"params": None}),
    ("GET", "/v1/control-reviews", {"params": {"status": "all", "limit": 20}}),
    ("GET", "/v1/control-reviews/crv_1", {}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(ControlPoliciesService(client), ControlReviewsService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncControlPoliciesService(client), AsyncControlReviewsService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


ROUTES_FILE = Path(__file__).resolve().parents[2] / "apps" / "api" / "src" / "routes" / "control-policies.ts"


@pytest.mark.skipif(not ROUTES_FILE.exists(), reason="the monorepo's API routes are not next to this package")
def test_every_request_path_is_a_route_the_api_registers() -> None:
    registered = {
        (method.upper(), re.sub(r":\w+", "*", path))
        for method, path in re.findall(
            r"app\.(get|put|post|delete)\('(/v1/control-[^']+)'", ROUTES_FILE.read_text("utf-8")
        )
    }
    assert registered, "no routes parsed from the API file"
    for method, path, _ in EXPECTED_CALLS:
        wild = re.sub(r"/agents/[^/]+", "/agents/*", path)
        wild = re.sub(r"/(cpl|crv)_[^/]+", "/*", wild)
        assert (method, wild) in registered, (method, path)


@pytest.mark.parametrize(
    "call",
    [
        lambda p, r: p.get(""),
        lambda p, r: p.set("", DEFINITION),
        lambda p, r: p.delete(""),
        lambda p, r: p.set("default", "not a definition"),
        lambda p, r: p.start_from_current_access("default"),
        lambda p, r: p.start_from_current_access(""),
        lambda p, r: p.simulate(CALL),
        lambda p, r: p.simulate({"target": {}}, agent_id="agt_1"),
        lambda p, r: p.revisions(""),
        lambda p, r: r.list(status="done"),
        lambda p, r: r.get(""),
    ],
)
def test_a_bad_scope_body_or_id_is_refused_before_any_request(call: Any) -> None:
    client = Capture()
    with pytest.raises(ValueError):
        call(ControlPoliciesService(client), ControlReviewsService(client))  # type: ignore[arg-type]
    assert client.calls == []


def test_an_id_is_escaped_into_the_path() -> None:
    client = Capture()
    policies = ControlPoliciesService(client)  # type: ignore[arg-type]
    policies.get("agt_/../x?y")
    policies.revisions("cpl_/../x")
    ControlReviewsService(client).get("crv_/x")  # type: ignore[arg-type]
    assert [call[1] for call in client.calls] == [
        "/v1/control-policies/agents/agt_%2F..%2Fx%3Fy",
        "/v1/control-policies/cpl_%2F..%2Fx/revisions",
        "/v1/control-reviews/crv_%2Fx",
    ]


def test_both_clients_expose_the_same_surface() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    sync, asynchronous = Stack(**kw), AsyncStack(**kw)
    expected = {
        "control_policies": {"list", "get", "set", "delete", "start_from_current_access", "simulate", "revisions"},
        "control_reviews": {"list", "get"},
    }
    for service, names in expected.items():
        s_methods = {n: m for n, m in inspect.getmembers(getattr(sync, service), inspect.ismethod) if n[0] != "_"}
        a_methods = {
            n: m for n, m in inspect.getmembers(getattr(asynchronous, service), inspect.ismethod) if n[0] != "_"
        }
        assert set(s_methods) == set(a_methods) == names
        for name, method in s_methods.items():
            assert inspect.iscoroutinefunction(a_methods[name]), name
            assert list(inspect.signature(method).parameters) == list(inspect.signature(a_methods[name]).parameters), (
                name
            )


def _client(handler: Any) -> HttpClient:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return http


def test_the_approval_header_the_body_and_the_query_reach_the_wire() -> None:
    seen: list[httpx.Request] = []
    view = {"change": "tighten", "policy": {"id": "cpl_1", "revision": 2}}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=view)

    policies = ControlPoliciesService(_client(handler))
    assert policies.set("agt_1", DEFINITION, expected_revision=1, governance_approval_id="gvr_9") == view
    policies.delete("default", expected_revision=0)
    policies.simulate(CALL, agent_id="agt_1")
    assert [(r.method, r.url.path) for r in seen] == [
        ("PUT", "/v1/control-policies/agents/agt_1"),
        ("DELETE", "/v1/control-policies/default"),
        ("POST", "/v1/control-policies/simulate"),
    ]
    assert seen[0].headers["x-governance-approval"] == "gvr_9"
    assert json.loads(seen[0].content) == {"definition": DEFINITION, "expected_revision": 1}
    assert dict(seen[1].url.params) == {"expected_revision": "0"}
    assert "x-governance-approval" not in seen[1].headers
    assert json.loads(seen[2].content) == {"call": CALL, "agent_id": "agt_1"}


def test_the_async_wire_matches() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"reviews": []})

    async def run() -> Any:
        http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
        http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return await AsyncControlReviewsService(http).list(status="all", limit=5)

    assert asyncio.run(run()) == {"reviews": []}
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/v1/control-reviews"
    assert dict(seen[0].url.params) == {"status": "all", "limit": "5"}


def _error_client(status: int, code: str, details: dict[str, Any]) -> HttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": f"{code} message", "details": details}})

    return _client(handler)


def test_a_loosening_is_a_typed_error_with_the_approval_link() -> None:
    client = _error_client(
        403, "GOVERNANCE_APPROVAL_REQUIRED", {"approval_id": "gvr_77", "approval_url": "https://getstack.run/approve/x"}
    )
    with pytest.raises(GovernanceApprovalRequiredError) as refused:
        ControlPoliciesService(client).delete("agt_1", expected_revision=2)
    assert refused.value.approval_id == "gvr_77"
    assert refused.value.approval_url == "https://getstack.run/approve/x"


def test_an_unbounded_send_rule_is_a_typed_error() -> None:
    rules = [{"rule_id": "mail", "connection_id": "scon_x", "unbound_paths": ["body.to"]}]
    with pytest.raises(UnboundedSendRuleError) as refused:
        ControlPoliciesService(_error_client(400, "UNBOUNDED_SEND_RULE", {"rules": rules})).set("default", DEFINITION)
    assert refused.value.rules == rules


def test_a_policy_set_per_job_and_a_call_tried_inside_a_mission_go_through_unchanged() -> None:
    from getstack.control_policies import POLICY_RECIPIENTS_PER_MISSION

    definition: dict[str, Any] = {
        "name": "Per job",
        "connections": {
            "mode": "listed",
            "rules": [
                {
                    "id": "mail-per-job",
                    "effect": "allow",
                    "recipients": POLICY_RECIPIENTS_PER_MISSION,
                    "access": {"connection_id": "scon_1", "intents": [{"name": "resend.send_email"}]},
                }
            ],
        },
        "recipients": {
            "email": POLICY_RECIPIENTS_PER_MISSION,
            "sms": POLICY_RECIPIENTS_PER_MISSION,
            "call": ["+14155550100"],
        },
    }
    call = {"action": "email.send", "mission_id": "ms_1", "target": {"to": "ana@example.com"}}
    capture = Capture()
    policies = ControlPoliciesService(capture)  # type: ignore[arg-type]

    policies.set("default", definition)
    policies.simulate(call, agent_id="agt_1")

    assert POLICY_RECIPIENTS_PER_MISSION == "per_mission"
    assert capture.calls[0][2]["json"] == {"definition": definition}
    assert capture.calls[1][2]["json"] == {"call": call, "agent_id": "agt_1"}


@pytest.mark.parametrize("code", ["recipients_not_pinned", "recipient_not_allowed"])
def test_a_send_outside_what_the_mission_pinned_is_a_refusal_with_its_reason(code: str) -> None:
    rule = {"policy_id": "cpl_1", "policy_revision": 2, "section": "connections", "rule": "mail-per-job", "code": code}
    client = _error_client(403, "CONTROL_DENIED", {"decision_id": "dec_1", "reason_code": code, "rule": rule})
    with pytest.raises(ControlDeniedError) as refused:
        ControlPoliciesService(client).get("default")
    assert refused.value.reason_code == code
    assert refused.value.rule == rule


def test_a_refusal_names_its_rule_and_a_held_action_its_retry() -> None:
    rule = {
        "policy_id": "cpl_1",
        "policy_revision": 3,
        "section": "spend",
        "rule": "max_per_action_cents",
        "code": "over_per_action_ceiling",
        "detail": {"max_per_action_cents": 500},
    }
    retry = {"ref": "ctl_ref_1", "after_seconds": 30}
    client = _error_client(
        403,
        "CONTROL_DENIED",
        {"decision_id": "dec_1", "reason_code": "needs_review", "retry": retry, "rule": rule},
    )
    with pytest.raises(ForbiddenError) as refused:
        ControlPoliciesService(client).get("default")
    error = refused.value
    assert isinstance(error, ControlDeniedError)
    assert (error.code, error.status_code) == ("CONTROL_DENIED", 403)
    assert (error.decision_id, error.reason_code, error.retry, error.rule) == ("dec_1", "needs_review", retry, rule)


def test_a_refusal_without_a_rule_or_retry_has_none() -> None:
    client = _error_client(403, "CONTROL_DENIED", {"decision_id": "dec_2", "reason_code": None})
    with pytest.raises(ControlDeniedError) as refused:
        ControlPoliciesService(client).list()
    assert (refused.value.reason_code, refused.value.retry, refused.value.rule) == (None, None, None)


def test_a_spend_limit_is_a_typed_error() -> None:
    client = _error_client(
        403,
        "CONTROL_LIMIT_EXCEEDED",
        {"limit": {"window": "month", "unit": "cents"}, "remaining": 120, "max_per_action_cents": 500},
    )
    with pytest.raises(ControlLimitExceededError) as refused:
        ControlPoliciesService(client).list()
    error = refused.value
    assert isinstance(error, ForbiddenError)
    assert (error.limit, error.remaining, error.max_per_action_cents) == (
        {"window": "month", "unit": "cents"},
        120,
        500,
    )


def test_a_limit_without_a_per_action_ceiling_leaves_it_unset() -> None:
    client = _error_client(
        403, "CONTROL_LIMIT_EXCEEDED", {"limit": {"window": "day", "unit": "actions"}, "remaining": 0}
    )
    with pytest.raises(ControlLimitExceededError) as refused:
        ControlPoliciesService(client).list()
    assert refused.value.max_per_action_cents is None
    assert refused.value.remaining == 0


NOTICE: dict[str, Any] = {
    "policy_id": "cpl_1",
    "policy_revision": 3,
    "source": "agent",
    "agent_id": "agt_1",
    "connection_id": "scon_late",
    "action_needed": "list_connection",
    "revision_needed": 4,
    "message": "The grant is made, but this agent cannot call the connection until a revision lists it.",
}


def test_a_grant_under_controls_returns_what_the_policy_still_needs() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"id": "grant_1", "control_policy": NOTICE})

    granted = ServiceService(_client(handler)).grant_agent_access("agt_1", "scon_late", ["read"])
    assert (seen[0].method, seen[0].url.path) == ("POST", "/v1/services/grant")
    assert json.loads(seen[0].content) == {
        "agent_id": "agt_1",
        "service_connection_id": "scon_late",
        "scopes": ["read"],
    }
    assert granted["control_policy"] == NOTICE

    async def run() -> Any:
        http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
        http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return await AsyncServiceService(http).grant_agent_access("agt_1", "scon_late", ["read"])

    assert asyncio.run(run())["control_policy"] == NOTICE


def test_a_grant_sends_its_rules_as_alternatives_and_leaves_out_what_it_was_not_given() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"id": "grant_1"})

    alternatives = [
        {"constraints": [{"path": "method", "op": "eq", "value": "GET"}]},
        {"intents": [{"name": "slack.post_to_channel", "params": {"channel": ["C0123"]}}]},
    ]
    ServiceService(_client(handler)).grant_agent_access(
        "agt_1", "scon_late", ["read"], alternatives=alternatives, allow_data_from=["slack"]
    )
    assert json.loads(seen[0].content) == {
        "agent_id": "agt_1",
        "service_connection_id": "scon_late",
        "scopes": ["read"],
        "alternatives": alternatives,
        "allow_data_from": ["slack"],
    }

    async def run() -> Any:
        http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
        http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return await AsyncServiceService(http).grant_agent_access(
            "agt_1", "scon_late", ["read"], alternatives=alternatives
        )

    asyncio.run(run())
    assert json.loads(seen[1].content)["alternatives"] == alternatives
    assert "constraints" not in json.loads(seen[1].content)


def test_a_connection_the_policy_does_not_list_is_a_refusal_that_names_the_revision() -> None:
    rule = {
        "policy_id": "cpl_1",
        "policy_revision": 3,
        "section": "connections",
        "rule": "mode",
        "code": "connection_not_listed",
        "detail": {"connection_id": "scon_late", "revision_needed": 4},
    }
    client = _error_client(
        403, "CONTROL_DENIED", {"decision_id": "dec_3", "reason_code": "connection_not_listed", "rule": rule}
    )
    with pytest.raises(ControlDeniedError) as refused:
        ControlPoliciesService(client).list()
    assert refused.value.rule == rule
