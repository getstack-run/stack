"""The trust switch: the requests of both clients, and the refusals before any request."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.trust import AsyncTrustService
from getstack.trust import TrustService


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.headers: list[Any] = []

    def get(self, path: str) -> Any:
        self.calls.append(("GET", path, None))
        return {}

    def put(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        self.calls.append(("PUT", path, json))
        self.headers.append(extra_headers)
        return {}


class AsyncCapture(Capture):
    async def get(self, path: str) -> Any:  # type: ignore[override]
        return super().get(path)

    async def put(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().put(path, json, extra_headers)


EXPECTED = [
    ("GET", "/v1/trust", None),
    ("PUT", "/v1/trust", {"trust": "ask_first"}),
    ("GET", "/v1/agents/agt_one/trust", None),
    ("PUT", "/v1/agents/agt_one/trust", {"trust": "trust_agents"}),
    ("PUT", "/v1/agents/agt_one/trust", {"trust": None}),
]


def test_sync_requests() -> None:
    client = Capture()
    service = TrustService(client)  # type: ignore[arg-type]
    service.get()
    service.set("ask_first")
    service.get("agt_one")
    service.set("trust_agents", "agt_one")
    service.clear("agt_one")
    assert client.calls == EXPECTED


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    service = AsyncTrustService(client)  # type: ignore[arg-type]

    async def drive() -> None:
        await service.get()
        await service.set("ask_first")
        await service.get("agt_one")
        await service.set("trust_agents", "agt_one")
        await service.clear("agt_one")

    asyncio.run(drive())
    assert client.calls == EXPECTED


def test_approval_goes_only_as_the_governance_header() -> None:
    client = Capture()
    service = TrustService(client)  # type: ignore[arg-type]
    service.set("ask_first")
    service.set("trust_agents", governance_approval_id="gvr_one")
    service.clear("agt_one", governance_approval_id="gvr_two")
    assert client.headers == [None, {"X-Governance-Approval": "gvr_one"}, {"X-Governance-Approval": "gvr_two"}]

    async_client = AsyncCapture()
    async_service = AsyncTrustService(async_client)  # type: ignore[arg-type]
    asyncio.run(async_service.set("trust_agents", "agt_one", governance_approval_id="gvr_three"))
    assert async_client.headers == [{"X-Governance-Approval": "gvr_three"}]


@pytest.mark.parametrize("value", ["always", ""])
def test_refuses_an_unknown_value_before_any_request(value: str) -> None:
    client = Capture()
    with pytest.raises(ValueError):
        TrustService(client).set(value)  # type: ignore[arg-type]
    assert client.calls == []
