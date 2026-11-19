"""RentAHuman: request shapes (sync and async), the two steps of a signup and a top-up, and the service tools."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.proxy import AsyncProxyService
from getstack._async.rentahuman import AsyncRentAHumanService
from getstack.errors import StackError
from getstack.proxy import ProxyService
from getstack.rentahuman import RentAHumanService, sign_rentahuman_payment
from getstack.service_mcp import SERVICE_MCP_ENDPOINTS
from getstack.wallet_key import WalletPaymentTarget, generate_agent_wallet_key, wallet_payment_authorization_payload

PASSPORT = {"X-Passport-Token": "ppt_1"}
BASE = "/v1/accounts/acct_1/rentahuman"
START = {
    "join_id": "rahj_1",
    "fund_id": "rahj_2",
    "amount_cents": 1000,
    "pay_to": "0x3333333333333333333333333333333333333333",
    "typed_data": {"domain": {"name": "USD Coin"}, "message": {"value": "10000000"}},
    "wallet": {"privy_app_id": "app_1", "wallet_id": "w_1"},
    "expires_at": "2026-11-05T12:00:00.000Z",
}


class Capture:
    def __init__(self, answer: Any = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.answer = answer

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        if callable(self.answer):
            return self.answer(method, path, kwargs)
        return self.answer if self.answer is not None else dict(START)

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return await self.request("GET", path, **kwargs)


def _drive_sync(service: RentAHumanService) -> None:
    service.join("acct_1", country="US", accept_terms=True, passport_token="ppt_1")
    service.complete_join("acct_1", "rahj_1", "c2ln", passport_token="ppt_1")
    service.fund("acct_1", 2500, passport_token="ppt_1")
    service.complete_fund("acct_1", "rahj_2", "c2ln", passport_token="ppt_1")
    service.get("acct_1")


async def _drive_async(service: AsyncRentAHumanService) -> None:
    await service.join("acct_1", country="US", accept_terms=True, passport_token="ppt_1")
    await service.complete_join("acct_1", "rahj_1", "c2ln", passport_token="ppt_1")
    await service.fund("acct_1", 2500, passport_token="ppt_1")
    await service.complete_fund("acct_1", "rahj_2", "c2ln", passport_token="ppt_1")
    await service.get("acct_1")


EXPECTED: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", f"{BASE}/join", {"json": {"country": "US", "accept_terms": True}, "extra_headers": PASSPORT}),
    ("POST", f"{BASE}/join/complete", {"json": {"join_id": "rahj_1", "signed": "c2ln"}, "extra_headers": PASSPORT}),
    ("POST", f"{BASE}/fund", {"json": {"amount_cents": 2500}, "extra_headers": PASSPORT}),
    ("POST", f"{BASE}/fund/complete", {"json": {"fund_id": "rahj_2", "signed": "c2ln"}, "extra_headers": PASSPORT}),
    ("GET", BASE, {"extra_headers": None}),
]


def test_sync_requests_match_the_routes() -> None:
    capture = Capture()
    _drive_sync(RentAHumanService(capture))  # type: ignore[arg-type]
    assert capture.calls == EXPECTED


def test_async_requests_match_the_routes() -> None:
    capture = AsyncCapture()
    asyncio.run(_drive_async(AsyncRentAHumanService(capture)))  # type: ignore[arg-type]
    assert capture.calls == EXPECTED


def test_a_signup_needs_the_terms_accepted_and_sends_only_what_was_given() -> None:
    capture = Capture()
    service = RentAHumanService(capture)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.join("acct_1", country="US", accept_terms=False)
    assert capture.calls == []
    service.join("acct_1", country="US", city="Austin", agent_name="Scout", accept_terms=True)
    assert capture.calls[0][2]["json"] == {
        "country": "US",
        "accept_terms": True,
        "city": "Austin",
        "agent_name": "Scout",
    }


def test_both_steps_sign_with_the_agents_own_key_and_send_only_the_signature() -> None:
    key = generate_agent_wallet_key()
    expected = wallet_payment_authorization_payload(
        WalletPaymentTarget(app_id="app_1", wallet_id="w_1", typed_data=START["typed_data"])  # type: ignore[arg-type]
    )
    signed = sign_rentahuman_payment(key, START)
    assert re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", signed)
    assert signed != expected

    def answer(method: str, path: str, kwargs: dict[str, Any]) -> Any:
        return dict(START) if path.endswith("/join") else {"join_id": "rahj_1", "status": "completed"}

    capture = Capture(answer)
    result = RentAHumanService(capture).join_with_key(  # type: ignore[arg-type]
        "acct_1", key, country="US", accept_terms=True, passport_token="ppt_1"
    )
    assert result["status"] == "completed"
    body = capture.calls[1][2]["json"]
    assert body["join_id"] == "rahj_1" and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", body["signed"])
    assert "wallet-auth:" not in str(capture.calls)


def test_an_id_goes_into_the_path_as_one_segment() -> None:
    capture = Capture()
    with pytest.raises(ValueError):
        RentAHumanService(capture).get("")  # type: ignore[arg-type]
    RentAHumanService(capture).get("../x")  # type: ignore[arg-type]
    assert capture.calls[0][1] == "/v1/accounts/..%2Fx/rentahuman"


def test_both_clients_expose_rentahuman() -> None:
    kw = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    assert isinstance(Stack(**kw).rentahuman, RentAHumanService)
    assert isinstance(AsyncStack(**kw).rentahuman, AsyncRentAHumanService)


# The account's connection list: each connection's effective mcp_url answers where a service's calls go.
CONNECTIONS = [
    {"id": "scon_1", "provider": "rentahuman", "status": "active", "mcp_url": "https://rentahuman.ai/api/mcp"},
    {"id": "scon_2", "provider": "custom_acme_tools", "status": "active", "mcp_url": "https://mcp.acme.example/rpc"},
    {"id": "scon_3", "provider": "slack", "status": "active", "mcp_url": None},
]


def _proxied(rpc: Any) -> Any:
    def answer(method: str, path: str, kwargs: Any) -> Any:
        if path == "/v1/services/connected":
            return CONNECTIONS
        return {"status": 200, "headers": {}, "body": rpc}

    return answer


def _proxy_calls(capture: Capture) -> list[tuple[str, str, dict[str, Any]]]:
    return [call for call in capture.calls if call[1] == "/v1/proxy"]


def test_service_tools_send_tools_list_through_the_proxy_and_mark_the_answer_untrusted() -> None:
    capture = Capture(_proxied({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "send_message"}, {"x": 1}]}}))
    result = ProxyService(capture).service_tools("rentahuman", passport_token="ppt_1")  # type: ignore[arg-type]
    assert result == {"service": "rentahuman", "tools": [{"name": "send_message"}], "untrusted": True}
    assert [(c[0], c[1]) for c in capture.calls] == [("GET", "/v1/services/connected"), ("POST", "/v1/proxy")]
    method, path, kwargs = _proxy_calls(capture)[0]
    assert (method, path) == ("POST", "/v1/proxy")
    assert kwargs["json"]["url"] == "https://rentahuman.ai/api/mcp"
    assert kwargs["json"]["body"]["method"] == "tools/list"
    assert kwargs["extra_headers"]["X-Passport-Token"] == "ppt_1"
    assert re.fullmatch(r"[A-Za-z0-9_-]{22,256}", kwargs["extra_headers"]["X-STACK-Authority-Request-Id"])


def test_service_call_tool_sends_the_arguments_reads_an_event_stream_and_flags_a_tool_error() -> None:
    event = '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}],"isError":true}}'
    stream = f"event: message\ndata: {event}\n\n"
    capture = Capture(_proxied(stream))
    result = ProxyService(capture).service_call_tool(  # type: ignore[arg-type]
        "rentahuman",
        "send_message",
        {"conversationId": "cnv_1", "content": "Thursday."},
        passport_token="ppt_1",
        authority_request_id="a" * 32,
    )
    assert result["is_error"] is True and result["untrusted"] is True and result["content"][0]["text"] == "hi"
    assert _proxy_calls(capture)[0][2]["json"]["body"]["params"] == {
        "name": "send_message",
        "arguments": {"conversationId": "cnv_1", "content": "Thursday."},
    }
    assert _proxy_calls(capture)[0][2]["extra_headers"]["X-STACK-Authority-Request-Id"] == "a" * 32


def test_any_connected_service_with_an_mcp_url_is_called_at_that_address() -> None:
    capture = Capture(_proxied({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "lookup"}], "content": []}}))
    proxy = ProxyService(capture)  # type: ignore[arg-type]
    assert proxy.service_tools("custom_acme_tools", passport_token="ppt_1")["tools"] == [{"name": "lookup"}]
    proxy.service_call_tool("custom_acme_tools", "lookup", {"q": "x"}, passport_token="ppt_1")
    sent = _proxy_calls(capture)
    assert [c[2]["json"]["url"] for c in sent] == ["https://mcp.acme.example/rpc"] * 2
    assert sent[1][2]["json"]["body"]["params"] == {"name": "lookup", "arguments": {"q": "x"}}
    assert all(c[2]["json"]["service"] == "custom_acme_tools" for c in sent)


def test_a_services_own_error_and_a_service_with_no_mcp_endpoint_are_raised() -> None:
    capture = Capture(_proxied({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}))
    proxy = ProxyService(capture)  # type: ignore[arg-type]
    with pytest.raises(StackError) as refused:
        proxy.service_call_tool("rentahuman", "nope", passport_token="ppt_1")
    assert refused.value.code == "SERVICE_MCP_ERROR"
    calls = len(_proxy_calls(capture))
    with pytest.raises(StackError) as none:
        proxy.service_tools("slack", passport_token="ppt_1")
    assert none.value.code == "SERVICE_HAS_NO_MCP_ENDPOINT" and len(_proxy_calls(capture)) == calls
    bad = ProxyService(  # type: ignore[arg-type]
        Capture(
            lambda m, p, k: (
                CONNECTIONS if p == "/v1/services/connected" else {"status": 502, "headers": {}, "body": "bad gateway"}
            )
        )
    )
    with pytest.raises(StackError) as http:
        bad.service_tools("rentahuman", passport_token="ppt_1")
    assert http.value.code == "SERVICE_MCP_HTTP_ERROR"


def test_a_services_own_refusal_is_passed_on_whole() -> None:
    words = "why " * 1000
    capture = Capture(_proxied({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": words}}))
    with pytest.raises(StackError) as refused:
        ProxyService(capture).service_call_tool("rentahuman", "nope", passport_token="ppt_1")  # type: ignore[arg-type]
    assert refused.value.code == "SERVICE_MCP_ERROR"
    assert str(refused.value).endswith(words)


def test_the_async_proxy_has_the_same_tools() -> None:
    capture = AsyncCapture(_proxied({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}))
    result = asyncio.run(AsyncProxyService(capture).service_tools("rentahuman", passport_token="ppt_1"))  # type: ignore[arg-type]
    assert result["untrusted"] is True


def test_the_endpoint_table_equals_stacks_own_when_the_monorepo_is_present() -> None:
    source = Path(__file__).resolve().parents[2] / "packages" / "shared" / "src" / "constants" / "service-mcp.ts"
    if not source.exists():
        pytest.skip("the monorepo is not here")
    table = dict(re.findall(r"^\s+(\w+): '(https://[^']+)',$", source.read_text(encoding="utf-8"), re.M))
    assert table == SERVICE_MCP_ENDPOINTS
