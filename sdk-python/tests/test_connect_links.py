"""Connect links and governance approval reads: request shapes, sync and async alike."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.governance import AsyncGovernanceService
from getstack._async.services import AsyncServiceService
from getstack.governance import GovernanceService
from getstack.services import ServiceService

LINK = {"link_id": "cnl_abc", "status": "pending", "url": "https://getstack.run/app/connect/link/token"}
DETAIL = {
    "approval": {"id": "gvr_abc", "status": "pending", "summary": "Start the platform subscription"},
    "payload_hash": "a" * 64,
    "approval_url": "https://getstack.run/app/approve/gvr_abc",
}


class Capture:
    def __init__(self, reply: Any) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, path: str, **kwargs: Any) -> Any:
        self.calls.append(("GET", path, kwargs))
        return self.reply

    def post(self, path: str, **kwargs: Any) -> Any:
        self.calls.append(("POST", path, kwargs))
        return self.reply


class AsyncCapture(Capture):
    async def get(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().get(path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().post(path, **kwargs)


def test_create_connect_link_posts_the_service_and_scopes_only_when_given() -> None:
    client = Capture(LINK)
    services = ServiceService(client)  # type: ignore[arg-type]
    assert services.create_connect_link("github") == LINK
    services.create_connect_link("github", ["repo", "read:user"])
    services.create_connect_link("github", [])
    assert client.calls == [
        ("POST", "/v1/services/connect-links", {"json": {"service_id": "github"}}),
        ("POST", "/v1/services/connect-links", {"json": {"service_id": "github", "scopes": ["repo", "read:user"]}}),
        ("POST", "/v1/services/connect-links", {"json": {"service_id": "github"}}),
    ]


def test_create_connect_link_for_the_accounts_own_api_posts_only_custom() -> None:
    custom = {"name": "Acme", "allowed_hosts": ["api.acme.example"]}
    sync_client = Capture(LINK)
    ServiceService(sync_client).create_connect_link(custom=custom)  # type: ignore[arg-type]
    assert sync_client.calls == [("POST", "/v1/services/connect-links", {"json": {"custom": custom}})]

    async_client = AsyncCapture(LINK)
    asyncio.run(AsyncServiceService(async_client).create_connect_link(custom=custom))  # type: ignore[arg-type]
    assert async_client.calls == [("POST", "/v1/services/connect-links", {"json": {"custom": custom}})]


def test_create_connect_link_needs_exactly_one_of_service_id_and_custom() -> None:
    custom = {"name": "Acme", "allowed_hosts": ["api.acme.example"]}
    services = ServiceService(Capture(LINK))  # type: ignore[arg-type]
    for kwargs in ({}, {"service_id": "github", "custom": custom}):
        try:
            services.create_connect_link(**kwargs)  # type: ignore[arg-type]
        except ValueError:
            continue
        raise AssertionError("expected a ValueError")


def test_get_connect_link_reads_by_escaped_id() -> None:
    client = Capture({"link_id": "cnl_abc", "status": "connected", "connection_id": "conn_1"})
    result = ServiceService(client).get_connect_link("cnl_a/b")  # type: ignore[arg-type]
    assert client.calls == [("GET", "/v1/services/connect-links/cnl_a%2Fb", {})]
    assert result["status"] == "connected"
    assert "url" not in result


def test_list_connect_links_reads_the_waiting_links_sync_and_async() -> None:
    reply = {"links": [{"link_id": "cnl_abc", "status": "pending"}]}
    sync_client = Capture(reply)
    assert ServiceService(sync_client).list_connect_links() == reply["links"]  # type: ignore[arg-type]
    assert sync_client.calls == [("GET", "/v1/services/connect-links", {})]

    async_client = AsyncCapture(reply)
    assert asyncio.run(AsyncServiceService(async_client).list_connect_links()) == reply["links"]  # type: ignore[arg-type]
    assert async_client.calls == [("GET", "/v1/services/connect-links", {})]


def test_async_connect_link_methods_send_the_same_requests() -> None:
    client = AsyncCapture(LINK)
    services = AsyncServiceService(client)  # type: ignore[arg-type]

    async def drive() -> None:
        await services.create_connect_link("github")
        await services.create_connect_link("github", ["repo"])
        await services.get_connect_link("cnl_a/b")

    asyncio.run(drive())
    assert client.calls == [
        ("POST", "/v1/services/connect-links", {"json": {"service_id": "github"}}),
        ("POST", "/v1/services/connect-links", {"json": {"service_id": "github", "scopes": ["repo"]}}),
        ("GET", "/v1/services/connect-links/cnl_a%2Fb", {}),
    ]


def test_list_approvals_reads_the_account_approvals_sync_and_async() -> None:
    reply = {"approvals": [DETAIL["approval"]]}
    sync_client = Capture(reply)
    assert GovernanceService(sync_client).list_approvals() == reply  # type: ignore[arg-type]
    assert sync_client.calls == [("GET", "/v1/governance/approvals", {})]

    async_client = AsyncCapture(reply)
    assert asyncio.run(AsyncGovernanceService(async_client).list_approvals()) == reply  # type: ignore[arg-type]
    assert async_client.calls == [("GET", "/v1/governance/approvals", {})]


def test_get_approval_reads_one_approval_by_escaped_id_sync_and_async() -> None:
    sync_client = Capture(DETAIL)
    assert GovernanceService(sync_client).get_approval("gvr_a/b?c") == DETAIL  # type: ignore[arg-type]
    assert sync_client.calls == [("GET", "/v1/governance/approvals/gvr_a%2Fb%3Fc", {})]

    async_client = AsyncCapture(DETAIL)
    detail = asyncio.run(AsyncGovernanceService(async_client).get_approval("gvr_abc"))  # type: ignore[arg-type]
    assert detail["payload_hash"] == "a" * 64
    assert async_client.calls == [("GET", "/v1/governance/approvals/gvr_abc", {})]
