"""What the customer's controls do with flagged content.

The requests of both clients, and the refusals before any request.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.flagged_content import AsyncFlaggedContentService
from getstack.flagged_content import FlaggedContentService


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    def get(self, path: str) -> Any:
        self.calls.append(("GET", path, None))
        return {"warning": "withhold", "critical": "withhold", "controls": True}

    def put(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        self.calls.append(("PUT", path, json))
        return {"warning": "deliver", "critical": "withhold", "controls": True}


class AsyncCapture(Capture):
    async def get(self, path: str) -> Any:  # type: ignore[override]
        return super().get(path)

    async def put(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().put(path, json, extra_headers)


EXPECTED = [
    ("GET", "/v1/flagged-content/settings", None),
    ("PUT", "/v1/flagged-content/settings", {"warning": "deliver"}),
    ("PUT", "/v1/flagged-content/settings", {"warning": "withhold", "critical": "deliver"}),
]


def test_sync_requests() -> None:
    client = Capture()
    service = FlaggedContentService(client)  # type: ignore[arg-type]
    service.get()
    service.set(warning="deliver")
    service.set(warning="withhold", critical="deliver")
    assert client.calls == EXPECTED


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    service = AsyncFlaggedContentService(client)  # type: ignore[arg-type]

    async def drive() -> None:
        await service.get()
        await service.set(warning="deliver")
        await service.set(warning="withhold", critical="deliver")

    asyncio.run(drive())
    assert client.calls == EXPECTED


@pytest.mark.parametrize("change", [{}, {"warning": "block"}, {"critical": "allow"}])
def test_refuses_a_bad_change_before_any_request(change: dict[str, str]) -> None:
    client = Capture()
    with pytest.raises(ValueError):
        FlaggedContentService(client).set(**change)  # type: ignore[arg-type]
    assert client.calls == []
