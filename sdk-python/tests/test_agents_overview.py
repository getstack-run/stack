"""The agents overview: the request of both clients, with the limit and cursor only when given."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.agents import AsyncAgentService
from getstack.agents import AgentService

PAGE = {"agents": [], "next_cursor": None}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    def get(self, path: str, params: Any = None, extra_headers: Any = None) -> Any:
        self.calls.append(("GET", path, params))
        return PAGE


class AsyncCapture(Capture):
    async def get(self, path: str, params: Any = None, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().get(path, params, extra_headers)


def test_overview_sends_only_what_is_given() -> None:
    client = Capture()
    service = AgentService(client)  # type: ignore[arg-type]
    assert service.overview() == PAGE
    service.overview(limit=50, cursor="abc")
    assert client.calls == [
        ("GET", "/v1/agents/overview", None),
        ("GET", "/v1/agents/overview", {"limit": 50, "cursor": "abc"}),
    ]


def test_async_overview_sends_only_what_is_given() -> None:
    client = AsyncCapture()
    service = AsyncAgentService(client)  # type: ignore[arg-type]

    async def run() -> None:
        assert await service.overview(limit=10) == PAGE
        await service.overview()

    asyncio.run(run())
    assert client.calls == [
        ("GET", "/v1/agents/overview", {"limit": 10}),
        ("GET", "/v1/agents/overview", None),
    ]
