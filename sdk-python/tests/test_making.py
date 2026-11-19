"""Making: request shapes, sync and async alike, and the typed refusals."""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.accounts import AsyncAccountsService
from getstack._async.making import AsyncMakingService
from getstack.accounts import AccountsService
from getstack.errors import MakingUnavailableError, StackError, raise_for_status
from getstack.making import MakingService

ACCT = "acct_one/two"
BASE = "/v1/accounts/acct_one%2Ftwo/making"
RECIPIENT = {
    "name": "Pat Doe",
    "email": "pat@example.test",
    "phone": "+14155550123",
    "address1": "1 Main St",
    "city": "Austin",
    "state": "TX",
    "postal_code": "78701",
}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {"ok": True}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive(making: MakingService) -> None:
    making.upload_design(ACCT, {"file_name": "a.stl", "content_base64": "c29saWQ="}, passport_token="ppt")
    making.quote(ACCT, {"design_id": "mkd_1", "recipient": RECIPIENT}, passport_token="ppt")
    making.order(ACCT, "mkq_1", passport_token="ppt")
    making.get_design(ACCT, "mkd/1")
    making.list_designs(ACCT, limit=5, passport_token="ppt")
    making.get_quote(ACCT, "mkq_1")
    making.get_order(ACCT, "mko_1", passport_token="ppt")
    making.list_orders(ACCT)
    making.cancel_order(ACCT, "mko_1", passport_token="ppt")
    making.approve_order(ACCT, "mko_1", governance_approval_id="gvr_1")
    making.reject_order(ACCT, "mko_1")
    making.list_suppliers()
    making.connect_supplier("lulu", api_key="key-value-1", api_secret="secret-value-1")
    making.connect_printful()
    making.disconnect_supplier("lulu")


async def _drive_async(making: AsyncMakingService) -> None:
    await making.upload_design(ACCT, {"file_name": "a.stl", "content_base64": "c29saWQ="}, passport_token="ppt")
    await making.quote(ACCT, {"design_id": "mkd_1", "recipient": RECIPIENT}, passport_token="ppt")
    await making.order(ACCT, "mkq_1", passport_token="ppt")
    await making.get_design(ACCT, "mkd/1")
    await making.list_designs(ACCT, limit=5, passport_token="ppt")
    await making.get_quote(ACCT, "mkq_1")
    await making.get_order(ACCT, "mko_1", passport_token="ppt")
    await making.list_orders(ACCT)
    await making.cancel_order(ACCT, "mko_1", passport_token="ppt")
    await making.approve_order(ACCT, "mko_1", governance_approval_id="gvr_1")
    await making.reject_order(ACCT, "mko_1")
    await making.list_suppliers()
    await making.connect_supplier("lulu", api_key="key-value-1", api_secret="secret-value-1")
    await making.connect_printful()
    await making.disconnect_supplier("lulu")


def _shape(calls: list[tuple[str, str, dict[str, Any]]]) -> list[tuple[str, str, Any, Any, Any]]:
    return [(m, p, k.get("json"), k.get("params"), k.get("extra_headers")) for m, p, k in calls]


EXPECTED = [
    (
        "POST",
        f"{BASE}/designs",
        {"file_name": "a.stl", "content_base64": "c29saWQ="},
        None,
        {"X-Passport-Token": "ppt"},
    ),
    ("POST", f"{BASE}/quotes", {"design_id": "mkd_1", "recipient": RECIPIENT}, None, {"X-Passport-Token": "ppt"}),
    ("POST", f"{BASE}/orders", {"quote_id": "mkq_1"}, None, {"X-Passport-Token": "ppt"}),
    ("GET", f"{BASE}/designs/mkd%2F1", None, None, None),
    ("GET", f"{BASE}/designs", None, {"limit": 5}, {"X-Passport-Token": "ppt"}),
    ("GET", f"{BASE}/quotes/mkq_1", None, None, None),
    ("GET", f"{BASE}/orders/mko_1", None, None, {"X-Passport-Token": "ppt"}),
    ("GET", f"{BASE}/orders", None, None, None),
    ("POST", f"{BASE}/orders/mko_1/cancel", {}, None, {"X-Passport-Token": "ppt"}),
    ("POST", f"{BASE}/orders/mko_1/approve", {}, None, {"X-Governance-Approval": "gvr_1"}),
    ("POST", f"{BASE}/orders/mko_1/reject", {}, None, None),
    ("GET", "/v1/accounts/making/suppliers", None, None, None),
    (
        "PUT",
        "/v1/accounts/making/suppliers/lulu",
        {"api_key": "key-value-1", "api_secret": "secret-value-1"},
        None,
        None,
    ),
    ("POST", "/v1/accounts/making/suppliers/printful/connect", {}, None, None),
    ("DELETE", "/v1/accounts/making/suppliers/lulu", None, None, None),
]


def test_sync_requests() -> None:
    client = Capture()
    _drive(MakingService(client))  # type: ignore[arg-type]
    assert _shape(client.calls) == EXPECTED


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncMakingService(client)))  # type: ignore[arg-type]
    assert _shape(client.calls) == EXPECTED


def test_agent_actions_refuse_an_empty_passport_before_any_request() -> None:
    client = Capture()
    making = MakingService(client)  # type: ignore[arg-type]
    for call in (
        lambda: making.upload_design(ACCT, {"file_name": "a.stl"}, passport_token=""),
        lambda: making.quote(ACCT, {}, passport_token=""),
        lambda: making.order(ACCT, "mkq_1", passport_token=""),
    ):
        with pytest.raises(ValueError):
            call()
    assert client.calls == []


def test_accounts_carry_making_and_both_flavours_match() -> None:
    assert hasattr(AccountsService, "__init__") and hasattr(AsyncAccountsService, "__init__")
    sync_methods = {n for n, _ in inspect.getmembers(MakingService, inspect.isfunction) if not n.startswith("_")}
    async_methods = {
        n for n, _ in inspect.getmembers(AsyncMakingService, inspect.iscoroutinefunction) if not n.startswith("_")
    }
    assert sync_methods == async_methods


def test_an_unavailable_answer_is_typed() -> None:
    unavailable = {
        "error": {"code": "MAKING_UNAVAILABLE", "message": "later", "details": {"reason": "no_supplier_available"}}
    }
    with pytest.raises(MakingUnavailableError) as other:
        raise_for_status(503, unavailable)
    assert other.value.reason == "no_supplier_available"
    assert isinstance(other.value, StackError)
