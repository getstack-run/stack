"""Agent-account subscriptions: request shapes, sync and async alike, approval headers and typed errors."""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.billing import AsyncBillingService
from getstack.auth import ApiKeyAuth
from getstack.billing import BillingService
from getstack.client import AsyncHttpClient, HttpClient
from getstack.errors import (
    ForbiddenError,
    GovernanceApprovalRequiredError,
    PlatformSubscriptionRequiredError,
    StackError,
)

CHECKOUT = {"checkout_url": "https://checkout.stripe.test/c/pay/cs_1", "session_id": "cs_1", "trial": True}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return CHECKOUT


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive_sync(billing: BillingService) -> None:
    billing.subscriptions()
    billing.subscribe_platform()
    billing.subscribe_platform(governance_approval_id="gvr_1")
    billing.subscribe_controls()
    billing.subscribe_controls(governance_approval_id="gvr_2")


async def _drive_async(billing: AsyncBillingService) -> None:
    await billing.subscriptions()
    await billing.subscribe_platform()
    await billing.subscribe_platform(governance_approval_id="gvr_1")
    await billing.subscribe_controls()
    await billing.subscribe_controls(governance_approval_id="gvr_2")


EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", "/v1/billing/subscriptions", {}),
    ("POST", "/v1/billing/platform/subscribe", {"json": {}, "extra_headers": None}),
    ("POST", "/v1/billing/platform/subscribe", {"json": {}, "extra_headers": {"X-Governance-Approval": "gvr_1"}}),
    ("POST", "/v1/billing/controls/subscribe", {"json": {}, "extra_headers": None}),
    ("POST", "/v1/billing/controls/subscribe", {"json": {}, "extra_headers": {"X-Governance-Approval": "gvr_2"}}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(BillingService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncBillingService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_both_clients_expose_the_same_billing_surface() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    s, a = Stack(**kw).billing, AsyncStack(**kw).billing
    s_methods = {n: m for n, m in inspect.getmembers(s, inspect.ismethod) if not n.startswith("_")}
    a_methods = {n: m for n, m in inspect.getmembers(a, inspect.ismethod) if not n.startswith("_")}
    assert (
        set(s_methods)
        == set(a_methods)
        == {
            "subscriptions",
            "subscribe_platform",
            "subscribe_controls",
        }
    )
    for name, method in s_methods.items():
        assert inspect.iscoroutinefunction(a_methods[name]), name
        assert list(inspect.signature(method).parameters) == list(inspect.signature(a_methods[name]).parameters), name


def _client(handler: Any) -> HttpClient:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return http


def test_the_approval_header_and_a_json_body_reach_the_wire() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=CHECKOUT)

    billing = BillingService(_client(handler))
    result = billing.subscribe_platform()
    billing.subscribe_controls(governance_approval_id="gvr_1")
    assert result == CHECKOUT
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/v1/billing/platform/subscribe"),
        ("POST", "/v1/billing/controls/subscribe"),
    ]
    assert "X-Governance-Approval" not in seen[0].headers
    assert seen[1].headers["X-Governance-Approval"] == "gvr_1"
    assert [r.content for r in seen] == [b"{}", b"{}"]


def test_subscription_status_is_returned_as_the_api_sent_it() -> None:
    status = {
        "platform": {"status": "trialing", "active": True, "contract": False},
        "controls": {"status": "off"},
        "this_month": {"account_actions": 12, "control_checks": 0},
    }
    billing = BillingService(_client(lambda request: httpx.Response(200, json=status)))
    assert billing.subscriptions() == status


def _error(status: int, code: str, details: dict[str, Any] | None = None) -> BillingService:
    body = {"error": {"code": code, "message": f"{code} message", "details": details or {}}}
    return BillingService(_client(lambda request: httpx.Response(status, json=body)))


def test_governance_approval_required_carries_the_approval() -> None:
    billing = _error(
        403,
        "GOVERNANCE_APPROVAL_REQUIRED",
        {"approval_id": "gvr_9", "approval_url": "https://getstack.run/governance/approvals/gvr_9"},
    )
    with pytest.raises(GovernanceApprovalRequiredError) as raised:
        billing.subscribe_platform()
    assert isinstance(raised.value, ForbiddenError)
    assert raised.value.approval_id == "gvr_9"


def test_platform_subscription_required_on_a_controls_checkout() -> None:
    with pytest.raises(PlatformSubscriptionRequiredError):
        _error(402, "PLATFORM_SUBSCRIPTION_REQUIRED", {"status": "none"}).subscribe_controls()


@pytest.mark.parametrize(
    ("status", "code"),
    [(409, "SUBSCRIPTION_CONFLICT"), (503, "BILLING_NOT_CONFIGURED")],
)
def test_conflicts_stay_plain_stack_errors(status: int, code: str) -> None:
    with pytest.raises(StackError) as raised:
        _error(status, code).subscribe_controls()
    assert not isinstance(raised.value, GovernanceApprovalRequiredError)
    assert raised.value.code == code
    assert raised.value.status_code == status


def test_async_client_raises_the_same_typed_error() -> None:
    body = {
        "error": {
            "code": "GOVERNANCE_APPROVAL_REQUIRED",
            "message": "approval",
            "details": {"approval_id": "gvr_9", "approval_url": "https://getstack.run/governance/approvals/gvr_9"},
        }
    }
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(403, json=body)))

    async def run() -> None:
        with pytest.raises(GovernanceApprovalRequiredError):
            await AsyncBillingService(http).subscribe_controls()

    asyncio.run(run())
