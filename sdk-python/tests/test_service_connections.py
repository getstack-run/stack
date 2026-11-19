"""Several named connections per service: the selector on proxy calls, the name on connect, rename, and the MCP pick."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.proxy import AsyncProxyService
from getstack._async.services import AsyncServiceService
from getstack.errors import ConnectionAmbiguousError, StackError, raise_for_status
from getstack.proxy import ProxyService
from getstack.service_mcp import service_mcp_url_of
from getstack.services import ServiceService

PROXIED = {"status": 200, "headers": {}, "body": {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}}
TWO = [
    {"id": "scon_a", "provider": "acme", "name": "Work", "status": "active", "mcp_url": "https://a.example/mcp"},
    {"id": "scon_b", "provider": "acme", "name": "Personal", "status": "active", "mcp_url": "https://b.example/mcp"},
    {"id": "scon_c", "provider": "acme", "name": "Old", "status": "revoked", "mcp_url": "https://c.example/mcp"},
    {"id": "scon_d", "provider": "slack", "name": "default", "status": "active", "mcp_url": None},
]


class Capture:
    def __init__(self, connections: Any = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.connections = connections

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return PROXIED

    def get(self, path: str, **kwargs: Any) -> Any:
        self.calls.append(("GET", path, kwargs))
        return self.connections

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self.request("PATCH", path, **kwargs)


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().get(path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request("POST", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request("PATCH", path, **kwargs)


def _proxy_payload(capture: Capture) -> dict[str, Any]:
    return next(c for c in capture.calls if c[1] == "/v1/proxy")[2]["json"]


def test_a_proxy_call_carries_connection_only_when_given() -> None:
    capture = Capture()
    proxy = ProxyService(capture)  # type: ignore[arg-type]
    proxy.request("acme", "https://a.example/x", "GET", passport_token="ppt_1")
    assert "connection" not in _proxy_payload(capture)
    capture.calls.clear()
    proxy.post("acme", "https://a.example/x", connection="Work", passport_token="ppt_1")
    assert _proxy_payload(capture)["connection"] == "Work"
    for verb in ("get", "put", "patch", "delete"):
        capture.calls.clear()
        getattr(proxy, verb)("acme", "https://a.example/x", connection="scon_a", passport_token="ppt_1")
        assert _proxy_payload(capture)["connection"] == "scon_a"


def test_the_async_proxy_call_carries_connection_only_when_given() -> None:
    capture = AsyncCapture()
    proxy = AsyncProxyService(capture)  # type: ignore[arg-type]
    asyncio.run(proxy.get("acme", "https://a.example/x", passport_token="ppt_1"))
    assert "connection" not in _proxy_payload(capture)
    capture.calls.clear()
    asyncio.run(proxy.post("acme", "https://a.example/x", connection="Work", passport_token="ppt_1"))
    assert _proxy_payload(capture)["connection"] == "Work"


def test_service_tools_and_call_tool_send_the_connection_and_use_its_endpoint() -> None:
    capture = Capture(TWO)
    proxy = ProxyService(capture)  # type: ignore[arg-type]
    proxy.service_tools("acme", connection="personal", passport_token="ppt_1")
    payload = _proxy_payload(capture)
    assert payload["connection"] == "personal" and payload["url"] == "https://b.example/mcp"
    capture.calls.clear()
    proxy.service_call_tool("acme", "lookup", {"q": 1}, connection="scon_a", passport_token="ppt_1")
    payload = _proxy_payload(capture)
    assert payload["connection"] == "scon_a" and payload["url"] == "https://a.example/mcp"


def test_async_service_tools_and_call_tool_send_the_connection() -> None:
    capture = AsyncCapture(TWO)
    proxy = AsyncProxyService(capture)  # type: ignore[arg-type]
    asyncio.run(proxy.service_tools("acme", connection="WORK", passport_token="ppt_1"))
    assert _proxy_payload(capture)["connection"] == "WORK"
    capture.calls.clear()
    asyncio.run(proxy.service_call_tool("acme", "t", None, connection="scon_b", passport_token="ppt_1"))
    assert _proxy_payload(capture)["url"] == "https://b.example/mcp"


def test_service_mcp_picks_by_id_or_by_name_in_any_case() -> None:
    assert service_mcp_url_of(TWO, "acme", "scon_b") == "https://b.example/mcp"
    assert service_mcp_url_of(TWO, "acme", "work") == "https://a.example/mcp"
    assert service_mcp_url_of(TWO, "acme", "PERSONAL") == "https://b.example/mcp"


def test_service_mcp_with_several_addresses_and_no_selector_raises_and_never_picks_the_first() -> None:
    with pytest.raises(ConnectionAmbiguousError) as ambiguous:
        service_mcp_url_of(TWO, "acme")
    assert ambiguous.value.code == "CONNECTION_AMBIGUOUS" and ambiguous.value.status_code == 409
    assert ambiguous.value.connections == [{"id": "scon_a", "name": "Work"}, {"id": "scon_b", "name": "Personal"}]
    assert "connection" in str(ambiguous.value)
    with pytest.raises(ConnectionAmbiguousError):
        ProxyService(Capture(TWO)).service_tools("acme", passport_token="ppt_1")  # type: ignore[arg-type]


def test_service_mcp_with_several_connections_sharing_one_address_uses_it_unnamed() -> None:
    shared = [{**TWO[0]}, {**TWO[1], "mcp_url": TWO[0]["mcp_url"]}]
    assert service_mcp_url_of(shared, "acme") == "https://a.example/mcp"
    capture = Capture(shared)
    ProxyService(capture).service_tools("acme", passport_token="ppt_1")  # type: ignore[arg-type]
    assert _proxy_payload(capture)["url"] == "https://a.example/mcp"
    mixed = [{**TWO[0], "mcp_url": None}, TWO[1]]
    with pytest.raises(ConnectionAmbiguousError):
        service_mcp_url_of(mixed, "acme")


def test_service_mcp_with_one_active_connection_works_unnamed_and_ignores_revoked_rows() -> None:
    one = [TWO[0], TWO[2]]
    assert service_mcp_url_of(one, "acme") == "https://a.example/mcp"
    with pytest.raises(StackError) as none:
        service_mcp_url_of(TWO, "slack")
    assert none.value.code == "SERVICE_HAS_NO_MCP_ENDPOINT"


def test_service_mcp_selector_naming_nothing_active_is_not_found_and_not_another_connection() -> None:
    with pytest.raises(StackError) as missing:
        service_mcp_url_of(TWO, "acme", "Old")
    assert missing.value.code == "NOT_FOUND" and missing.value.status_code == 404
    with pytest.raises(StackError):
        service_mcp_url_of(TWO, "acme", "scon_d")


def test_the_ambiguity_refusal_from_the_api_is_a_typed_error() -> None:
    body = {
        "error": {
            "code": "CONNECTION_AMBIGUOUS",
            "message": "Pass connection.",
            "details": {"connections": [{"id": "scon_a", "name": "Work"}, {"id": "scon_b", "name": "Personal"}]},
        }
    }
    with pytest.raises(ConnectionAmbiguousError) as refused:
        raise_for_status(409, body)
    assert refused.value.status_code == 409 and [c["name"] for c in refused.value.connections] == ["Work", "Personal"]


def test_connect_calls_send_connection_name_only_when_given() -> None:
    capture = Capture()
    services = ServiceService(capture)  # type: ignore[arg-type]
    services.connect("slack", "tok", ["chat:write"])
    services.connect_custom("Acme", "key", allowed_hosts=["a.example"])
    services.create_connect_link("github")
    assert all("connection_name" not in c[2]["json"] for c in capture.calls)
    capture.calls.clear()
    services.connect("slack", "tok", ["chat:write"], connection_name="Work")
    services.connect_custom("Acme", "key", allowed_hosts=["a.example"], connection_name="Work")
    services.create_connect_link("github", connection_name="Work")
    assert [(c[1], c[2]["json"]["connection_name"]) for c in capture.calls] == [
        ("/v1/services/connect", "Work"),
        ("/v1/services/custom", "Work"),
        ("/v1/services/connect-links", "Work"),
    ]


def test_connect_link_puts_the_name_where_the_api_takes_it() -> None:
    capture = Capture()
    services = ServiceService(capture)  # type: ignore[arg-type]
    custom = {"name": "Acme", "allowed_hosts": ["a.example"]}
    services.create_connect_link(custom=custom, connection_name="Work")
    services.create_connect_link(custom={**custom, "connection_name": "Own"}, connection_name="Work")
    services.create_connect_link(connect={"kind": "post_address"})
    assert [c[2]["json"] for c in capture.calls] == [
        {"custom": {**custom, "connection_name": "Work"}},
        {"custom": {**custom, "connection_name": "Own"}},
        {"connect": {"kind": "post_address"}},
    ]
    assert "connection_name" not in custom
    with pytest.raises(ValueError):
        services.create_connect_link(connect={"kind": "post_address"}, connection_name="Work")
    aservices = AsyncServiceService(AsyncCapture())  # type: ignore[arg-type]
    acapture = aservices._client  # type: ignore[attr-defined]
    asyncio.run(aservices.create_connect_link(custom=custom, connection_name="Work"))
    assert acapture.calls[0][2]["json"] == {"custom": {**custom, "connection_name": "Work"}}
    with pytest.raises(ValueError):
        asyncio.run(aservices.create_connect_link(connect={"kind": "post_address"}, connection_name="Work"))


def test_async_connect_calls_send_connection_name_only_when_given() -> None:
    capture = AsyncCapture()
    services = AsyncServiceService(capture)  # type: ignore[arg-type]

    async def drive(name: str | None) -> None:
        await services.connect("slack", "tok", ["chat:write"], connection_name=name)
        await services.connect_custom("Acme", "key", allowed_hosts=["a.example"], connection_name=name)
        await services.create_connect_link("github", connection_name=name)

    asyncio.run(drive(None))
    assert all("connection_name" not in c[2]["json"] for c in capture.calls)
    capture.calls.clear()
    asyncio.run(drive("Work"))
    assert [c[2]["json"]["connection_name"] for c in capture.calls] == ["Work"] * 3


def test_rename_patches_the_connection_with_the_id_as_one_path_segment() -> None:
    capture = Capture()
    ServiceService(capture).rename("scon_a", "Personal")  # type: ignore[arg-type]
    ServiceService(capture).rename("../x", "Personal")  # type: ignore[arg-type]
    assert capture.calls[0] == ("PATCH", "/v1/services/scon_a", {"json": {"connection_name": "Personal"}})
    assert capture.calls[1][1] == "/v1/services/..%2Fx"
    async_capture = AsyncCapture()
    asyncio.run(AsyncServiceService(async_capture).rename("scon_a", "Personal"))  # type: ignore[arg-type]
    assert async_capture.calls == [("PATCH", "/v1/services/scon_a", {"json": {"connection_name": "Personal"}})]
