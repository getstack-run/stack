"""Brain calls: request shapes, sync and async alike, and the refusals made before any request."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncBrainService, BrainService

FILE = "drv_abcdefgh1234"
FILE2 = "drv_ijklmnop5678"
PASSPORT = {"X-Passport-Token": "ppt"}


class Capture:
    """Records (method, path, json, params, headers) of every call, answering what the API would."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any, Any, Any]] = []

    def _record(self, method: str, path: str, json: Any, params: Any, headers: Any) -> Any:
        self.calls.append((method, path, json, params, headers))
        return {"ok": True}

    def get(self, path: str, params: Any = None, extra_headers: Any = None) -> Any:
        return self._record("GET", path, None, params, extra_headers)

    def post(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        return self._record("POST", path, json, None, extra_headers)


class AsyncCapture(Capture):
    async def get(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().get(*a, **k)

    async def post(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().post(*a, **k)


def run_sync(use: Any) -> list[tuple[str, str, Any, Any, Any]]:
    capture = Capture()
    use(BrainService(capture))  # type: ignore[arg-type]
    return capture.calls


async def _await_all(*coros: Any) -> None:
    for coro in coros:
        await coro


def run_async(use: Any) -> list[tuple[str, str, Any, Any, Any]]:
    capture = AsyncCapture()
    asyncio.run(use(AsyncBrainService(capture)))  # type: ignore[arg-type]
    return capture.calls


def both(use: Any) -> list[tuple[str, str, Any, Any, Any]]:
    """The calls each client makes for the same use; sync and async must be identical."""
    sync_calls = run_sync(use)
    async_calls = run_async(lambda b: _await_all(*use(b)))
    assert sync_calls == async_calls
    return sync_calls


def test_add_sends_the_selection_and_the_passport_only_as_a_header() -> None:
    calls = both(
        lambda b: [
            b.add(file_id=FILE),
            b.add(file_ids=[FILE, FILE2], passport_token="ppt"),
            b.add(name_prefix="contracts/"),
        ]
    )
    assert calls[0] == ("POST", "/v1/brain/files", {"file_id": FILE}, None, None)
    assert calls[1] == ("POST", "/v1/brain/files", {"file_ids": [FILE, FILE2]}, None, PASSPORT)
    assert calls[2] == ("POST", "/v1/brain/files", {"name_prefix": "contracts/"}, None, None)


def test_remove_and_search() -> None:
    calls = both(
        lambda b: [
            b.remove(file_id=FILE),
            b.search("what is the total?", passport_token="ppt"),
        ]
    )
    assert calls[0] == ("POST", "/v1/brain/remove", {"file_id": FILE}, None, None)
    assert calls[1] == ("POST", "/v1/brain/search", {"query": "what is the total?"}, None, PASSPORT)


def test_list_sends_only_the_params_it_was_given() -> None:
    calls = both(lambda b: [b.list(status="searchable", limit=25)])
    assert calls[0] == ("GET", "/v1/brain/files", None, {"status": "searchable", "limit": 25}, None)

    none = both(lambda b: [b.list()])
    assert none[0] == ("GET", "/v1/brain/files", None, None, None)


def test_a_selection_of_not_exactly_one_is_refused_before_any_request() -> None:
    service = BrainService(Capture())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exactly one"):
        service.add()
    with pytest.raises(ValueError, match="exactly one"):
        service.add(file_id=FILE, name_prefix="x")
    with pytest.raises(ValueError, match="exactly one"):
        service.remove(file_id=FILE, file_ids=[FILE2])
