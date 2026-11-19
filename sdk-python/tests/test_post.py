"""Post: request shapes, sync and async alike, and typed errors."""

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
from getstack._async.post import AsyncPostService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.errors import PostalAddressNotActiveError, PostRefusedError, PostUnavailableError, StackError
from getstack.post import PostService

ACCT = "acct_one/two"
Q = "acct_one%2Ftwo"
TO = {"name": "Pat Doe", "line1": "1 Main St", "city": "Reno", "state": "NV", "postal_code": "89501"}
LETTER = {"to": TO, "sender_name": "Acme Dental", "content": {"text": "Hello Pat"}, "use_type": "operational"}
POSTCARD = {
    "kind": "postcard",
    "to": TO,
    "sender_name": "Acme Dental",
    "front": {"text": "Hi"},
    "back": {"text": "There"},
    "use_type": "marketing",
}
PPT = {"X-Passport-Token": "ppt"}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {"ok": True}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive_sync(post: PostService) -> None:
    post.get_address()
    post.start_address()
    post.connect_address("sk_agent_key", webhook_secret="whsec_x")
    post.connect_address("sk_agent_key")
    post.refresh_address()
    post.pause_address()
    post.resume_address()
    post.close_address()
    post.list_items()
    post.list_items(limit=5, cursor="c1", routing="unassigned")
    post.assign_item("pit/1", ACCT)
    post.account_address(ACCT)
    post.account_address(ACCT, passport_token="ppt")
    post.list_account_items(ACCT, limit=3, cursor="c1", passport_token="ppt")
    post.get_account_item(ACCT, "pit/1")
    post.scan_item(ACCT, "pit/1")
    post.scan_item(ACCT, "pit/1", capture="both", idempotency_key="scan-key-0001", passport_token="ppt")
    post.forward_item(ACCT, "pit/1", TO, mail_class="usps_first_class", idempotency_key="fwd-key-0001")
    post.shred_item(ACCT, "pit/1", passport_token="ppt")
    post.check_address(ACCT, TO)
    post.send(ACCT, LETTER, passport_token="ppt")
    post.send(ACCT, POSTCARD)
    post.list_letters(ACCT, limit=2)
    post.get_letter(ACCT, "plt/1", passport_token="ppt")


async def _drive_async(post: AsyncPostService) -> None:
    await post.get_address()
    await post.start_address()
    await post.connect_address("sk_agent_key", webhook_secret="whsec_x")
    await post.connect_address("sk_agent_key")
    await post.refresh_address()
    await post.pause_address()
    await post.resume_address()
    await post.close_address()
    await post.list_items()
    await post.list_items(limit=5, cursor="c1", routing="unassigned")
    await post.assign_item("pit/1", ACCT)
    await post.account_address(ACCT)
    await post.account_address(ACCT, passport_token="ppt")
    await post.list_account_items(ACCT, limit=3, cursor="c1", passport_token="ppt")
    await post.get_account_item(ACCT, "pit/1")
    await post.scan_item(ACCT, "pit/1")
    await post.scan_item(ACCT, "pit/1", capture="both", idempotency_key="scan-key-0001", passport_token="ppt")
    await post.forward_item(ACCT, "pit/1", TO, mail_class="usps_first_class", idempotency_key="fwd-key-0001")
    await post.shred_item(ACCT, "pit/1", passport_token="ppt")
    await post.check_address(ACCT, TO)
    await post.send(ACCT, LETTER, passport_token="ppt")
    await post.send(ACCT, POSTCARD)
    await post.list_letters(ACCT, limit=2)
    await post.get_letter(ACCT, "plt/1", passport_token="ppt")


EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", "/v1/post/address", {}),
    ("POST", "/v1/post/address", {"json": {}}),
    ("POST", "/v1/post/address/connect", {"json": {"api_key": "sk_agent_key", "webhook_secret": "whsec_x"}}),
    ("POST", "/v1/post/address/connect", {"json": {"api_key": "sk_agent_key"}}),
    ("POST", "/v1/post/address/refresh", {"json": {}}),
    ("POST", "/v1/post/address/pause", {"json": {}}),
    ("POST", "/v1/post/address/resume", {"json": {}}),
    ("DELETE", "/v1/post/address", {}),
    ("GET", "/v1/post/items", {}),
    ("GET", "/v1/post/items", {"params": {"limit": 5, "cursor": "c1", "routing": "unassigned"}}),
    ("POST", "/v1/post/items/pit%2F1/assign", {"json": {"account_id": ACCT}}),
    ("GET", f"/v1/accounts/{Q}/post/address", {}),
    ("GET", f"/v1/accounts/{Q}/post/address", {"extra_headers": PPT}),
    ("GET", f"/v1/accounts/{Q}/post/items", {"params": {"limit": 3, "cursor": "c1"}, "extra_headers": PPT}),
    ("GET", f"/v1/accounts/{Q}/post/items/pit%2F1", {}),
    ("POST", f"/v1/accounts/{Q}/post/items/pit%2F1/scan", {"json": {}}),
    (
        "POST",
        f"/v1/accounts/{Q}/post/items/pit%2F1/scan",
        {"json": {"capture": "both"}, "extra_headers": {**PPT, "Idempotency-Key": "scan-key-0001"}},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/post/items/pit%2F1/forward",
        {
            "json": {"destination": TO, "mail_class": "usps_first_class"},
            "extra_headers": {"Idempotency-Key": "fwd-key-0001"},
        },
    ),
    ("POST", f"/v1/accounts/{Q}/post/items/pit%2F1/shred", {"json": {"confirm": True}, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/post/address-check", {"json": {"address": TO}}),
    ("POST", f"/v1/accounts/{Q}/post/letters", {"json": LETTER, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/post/letters", {"json": POSTCARD}),
    ("GET", f"/v1/accounts/{Q}/post/letters", {"params": {"limit": 2}}),
    ("GET", f"/v1/accounts/{Q}/post/letters/plt%2F1", {"extra_headers": PPT}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(PostService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncPostService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_both_clients_expose_post_with_the_same_methods() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    sync, async_ = Stack(**kw), AsyncStack(**kw)
    s_methods = {n: m for n, m in inspect.getmembers(sync.post, inspect.ismethod) if not n.startswith("_")}
    a_methods = {n: m for n, m in inspect.getmembers(async_.post, inspect.ismethod) if not n.startswith("_")}
    assert set(s_methods) == set(a_methods)
    for name, method in s_methods.items():
        assert inspect.iscoroutinefunction(a_methods[name]), name
        assert list(inspect.signature(method).parameters) == list(inspect.signature(a_methods[name]).parameters), name


def test_send_passes_an_optional_return_address_through_unchanged() -> None:
    client = Capture()
    ret = {
        "name": "Acme Dental",
        "line1": "77 Sender Way",
        "city": "Carson City",
        "state": "NV",
        "postal_code": "89701",
    }
    PostService(client).send(ACCT, {**LETTER, "return_address": ret})
    assert client.calls[0][2]["json"]["return_address"] == ret


def test_send_refuses_mail_that_does_not_say_what_it_is_before_any_request() -> None:
    client = Capture()
    aclient = AsyncCapture()
    bad = {"to": TO, "content": {"text": "x"}}
    with pytest.raises(ValueError, match="use_type"):
        PostService(client).send(ACCT, bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="use_type"):
        asyncio.run(AsyncPostService(aclient).send(ACCT, {**bad, "use_type": "promo"}))  # type: ignore[arg-type]
    assert client.calls == [] and aclient.calls == []


def _error_response(status: int, code: str, details: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": f"{code} message", "details": details}})

    return httpx.MockTransport(handler)


ERROR_CASES = [
    (422, "POST_REFUSED", {"reason": "provider_refused"}, PostRefusedError, {"reason": "provider_refused"}),
    (
        503,
        "POST_UNAVAILABLE",
        {"reason": "letters_not_configured"},
        PostUnavailableError,
        {"reason": "letters_not_configured"},
    ),
    (
        409,
        "POSTAL_ADDRESS_NOT_ACTIVE",
        {"status": "pending_identity"},
        PostalAddressNotActiveError,
        {"address_status": "pending_identity"},
    ),
]


@pytest.mark.parametrize(("status", "code", "details", "cls", "attrs"), ERROR_CASES)
def test_sync_client_raises_typed_post_errors(
    status: int, code: str, details: dict[str, Any], cls: type[StackError], attrs: dict[str, Any]
) -> None:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=_error_response(status, code, details))
    with pytest.raises(cls) as raised:
        PostService(http).send(ACCT, LETTER)
    error = raised.value
    assert (error.code, error.status_code, error.details) == (code, status, details)
    for name, value in attrs.items():
        assert getattr(error, name) == value


@pytest.mark.parametrize(("status", "code", "details", "cls", "attrs"), ERROR_CASES)
def test_async_client_raises_typed_post_errors(
    status: int, code: str, details: dict[str, Any], cls: type[StackError], attrs: dict[str, Any]
) -> None:
    async def run() -> StackError:
        http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
        http._client = httpx.AsyncClient(transport=_error_response(status, code, details))
        try:
            await AsyncPostService(http).get_letter(ACCT, "plt_1")
        except StackError as error:
            return error
        raise AssertionError("expected an error")

    error = asyncio.run(run())
    assert type(error) is cls
    for name, value in attrs.items():
        assert getattr(error, name) == value
