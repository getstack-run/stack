"""Meetings: request shapes (sync and async alike), passport headers, the routes the API registers."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.meetings import AsyncMeetingsService, AsyncMeetingStream
from getstack.meetings import MeetingsService, MeetingStream, stream_target

PASSPORT = {"X-Passport-Token": "ppt_1"}
BASE = "/v1/accounts/acct_1/meetings"


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


EXPECTED: list[tuple[str, str, dict[str, Any]]] = [
    (
        "POST",
        BASE,
        {"json": {"event_id": "cev_1", "max_seconds": 1800, "wait_seconds": 5}, "extra_headers": PASSPORT},
    ),
    ("POST", f"{BASE}/mtg_1/say", {"json": {"text": "Hello.", "wait_seconds": 10}, "extra_headers": None}),
    ("POST", f"{BASE}/mtg_1/say", {"json": {}, "extra_headers": PASSPORT}),
    ("POST", f"{BASE}/mtg_1/chat", {"json": {"text": "A link."}, "extra_headers": None}),
    ("POST", f"{BASE}/mtg_1/leave", {"json": {}, "extra_headers": None}),
    ("GET", BASE, {"params": {"status": "ended", "limit": 5}, "extra_headers": None}),
    ("GET", f"{BASE}/mtg_1", {"extra_headers": None}),
    ("GET", f"{BASE}/voice", {"extra_headers": PASSPORT}),
    ("PUT", f"{BASE}/voice", {"json": {"voice": "Claire", "language": "fr"}, "extra_headers": None}),
    ("PUT", f"{BASE}/voice", {"json": {}, "extra_headers": None}),
]


def _drive_sync(meetings: MeetingsService) -> None:
    meetings.join("acct_1", {"event_id": "cev_1", "max_seconds": 1800, "wait_seconds": 5}, passport_token="ppt_1")
    meetings.say("acct_1", "mtg_1", text="Hello.", wait_seconds=10)
    meetings.say("acct_1", "mtg_1", passport_token="ppt_1")
    meetings.chat("acct_1", "mtg_1", "A link.")
    meetings.leave("acct_1", "mtg_1")
    meetings.list("acct_1", status="ended", limit=5)
    meetings.get("acct_1", "mtg_1")
    meetings.get_voice("acct_1", passport_token="ppt_1")
    meetings.set_voice("acct_1", {"voice": "Claire", "language": "fr"})
    meetings.set_voice("acct_1", {})


async def _drive_async(meetings: AsyncMeetingsService) -> None:
    await meetings.join("acct_1", {"event_id": "cev_1", "max_seconds": 1800, "wait_seconds": 5}, passport_token="ppt_1")
    await meetings.say("acct_1", "mtg_1", text="Hello.", wait_seconds=10)
    await meetings.say("acct_1", "mtg_1", passport_token="ppt_1")
    await meetings.chat("acct_1", "mtg_1", "A link.")
    await meetings.leave("acct_1", "mtg_1")
    await meetings.list("acct_1", status="ended", limit=5)
    await meetings.get("acct_1", "mtg_1")
    await meetings.get_voice("acct_1", passport_token="ppt_1")
    await meetings.set_voice("acct_1", {"voice": "Claire", "language": "fr"})
    await meetings.set_voice("acct_1", {})


def test_sync_requests_match_the_routes() -> None:
    capture = Capture()
    _drive_sync(MeetingsService(capture))  # type: ignore[arg-type]
    assert capture.calls == EXPECTED


def test_async_requests_match_the_routes() -> None:
    capture = AsyncCapture()
    asyncio.run(_drive_async(AsyncMeetingsService(capture)))  # type: ignore[arg-type]
    assert capture.calls == EXPECTED


def test_an_id_goes_into_the_path_as_one_segment_and_a_join_needs_an_event() -> None:
    capture = Capture()
    meetings = MeetingsService(capture)  # type: ignore[arg-type]
    meetings.get("acct_1", "../x")
    assert capture.calls[0][1] == f"{BASE}/..%2Fx"
    with pytest.raises(ValueError):
        meetings.get("acct_1", "")
    with pytest.raises(ValueError):
        meetings.join("acct_1", {})
    assert len(capture.calls) == 1


def test_both_clients_expose_meetings() -> None:
    kw = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    assert isinstance(Stack(**kw).meetings, MeetingsService)
    assert isinstance(AsyncStack(**kw).meetings, AsyncMeetingsService)


def test_the_live_stream_is_opened_with_the_credential_and_the_passport() -> None:
    url, headers = stream_target("http://api.test", {"Authorization": "Bearer k"}, "acct_1", "mtg_1", "ppt_1")
    assert url == "ws://api.test/v1/accounts/acct_1/meetings/mtg_1/live"
    assert headers == {"Authorization": "Bearer k", "X-Passport-Token": "ppt_1"}
    url, headers = stream_target("https://api.test", {"Authorization": "Bearer k"}, "acct_1", "mtg_1", None)
    assert url.startswith("wss://api.test/") and "X-Passport-Token" not in headers


class FakeSocket:
    def __init__(self, incoming: list[dict[str, Any]]) -> None:
        self.incoming = [json.dumps(m) for m in incoming]
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    def __iter__(self) -> Any:
        return iter(self.incoming)

    def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def close(self) -> None:
        self.closed = True


def test_the_stream_yields_events_keeps_errors_and_sends_words_chat_and_leave() -> None:
    socket = FakeSocket(
        [
            {"seq": 1, "type": "heard", "speaker": "Olivia", "text": "Hi"},
            {"type": "error", "code": "VALIDATION_ERROR", "message": "no"},
            {"seq": 2, "type": "ended", "reason": "agent_left"},
        ]
    )
    stream = MeetingStream(socket)
    stream.text("One more thing.", True)
    stream.chat("A link.")
    stream.leave()
    assert [e["type"] for e in stream] == ["heard", "ended"]
    assert stream.errors == [{"type": "error", "code": "VALIDATION_ERROR", "message": "no"}]
    assert socket.sent == [
        {"type": "text", "token": "One more thing.", "last": True},
        {"type": "chat", "text": "A link."},
        {"type": "leave"},
    ]
    stream.close()
    assert socket.closed


def test_the_async_stream_yields_events_and_sends() -> None:
    class AsyncSocket:
        def __init__(self) -> None:
            self.sent: list[dict[str, Any]] = []

        def __aiter__(self) -> Any:
            async def gen() -> Any:
                yield json.dumps({"seq": 1, "type": "joined", "name": "Sam"})
                yield json.dumps({"type": "error", "code": "X", "message": "m"})

            return gen()

        async def send(self, message: str) -> None:
            self.sent.append(json.loads(message))

        async def close(self) -> None:
            pass

    async def run() -> None:
        socket = AsyncSocket()
        stream = AsyncMeetingStream(socket)
        await stream.text("Hi", False)
        await stream.chat("c")
        await stream.leave()
        seen = [e["type"] async for e in stream]
        assert seen == ["joined"]
        assert stream.errors[0]["code"] == "X"
        assert [m["type"] for m in socket.sent] == ["text", "chat", "leave"]

    asyncio.run(run())


def test_paths_exist_in_the_api_routes() -> None:
    root = Path(__file__).resolve().parents[2]
    source = root / "apps" / "api" / "src" / "hosted" / "routes" / "account-meetings.ts"
    if not source.exists():
        pytest.skip("the monorepo is not present")
    text = source.read_text(encoding="utf-8")
    registered = set(re.findall(r"app\.(?:get|post|put)\('([^']+)'", text))
    assert {
        "/v1/accounts/:id/meetings",
        "/v1/accounts/:id/meetings/:meetingId/say",
        "/v1/accounts/:id/meetings/:meetingId/chat",
        "/v1/accounts/:id/meetings/:meetingId/leave",
        "/v1/accounts/:id/meetings/:meetingId",
        "/v1/accounts/:id/meetings/voice",
    } <= registered
