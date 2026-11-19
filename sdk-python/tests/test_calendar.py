"""The calendar: request shapes (sync and async alike), passport headers, the routes the API registers."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.calendar import AsyncCalendarService
from getstack.calendar import CalendarService

PASSPORT = {"X-Passport-Token": "ppt_1"}
EVENT: dict[str, Any] = {
    "title": "Standup",
    "start": "2026-11-02T09:00",
    "time_zone": "Europe/Stockholm",
    "repeat": {"rule": "FREQ=DAILY;COUNT=5"},
    "guests": ["a@example.com"],
    "meeting": True,
    "attend": True,
}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive_sync(calendar: CalendarService) -> None:
    calendar.list_events("acct_1")
    calendar.list_events("acct_1", role="attendee", response="pending", limit=10, passport_token="ppt_1")
    calendar.get_event("acct_1", "cev_1")
    calendar.agenda("acct_1", "2026-11-01", "2026-11-30", time_zone="Europe/Stockholm", passport_token="ppt_1")
    calendar.create_event("acct_1", EVENT, passport_token="ppt_1")
    calendar.update_event("acct_1", "cev_1", {"start": "2026-11-04T10:00", "scope": "following", "occurrence": "x"})
    calendar.cancel_event("acct_1", "cev_1", occurrence="2026-11-05T09:00", scope="occurrence")
    calendar.respond("acct_1", "cev_2", "accept")
    calendar.respond("acct_1", "cev_2", "decline", notify_organizer=False, passport_token="ppt_1")
    calendar.decline_proposal("acct_1", "cev_1", "ccp_1", comment="No")
    calendar.feed("acct_1")
    calendar.rotate_feed("acct_1")
    calendar.revoke_feed("acct_1")


async def _drive_async(calendar: AsyncCalendarService) -> None:
    await calendar.list_events("acct_1")
    await calendar.list_events("acct_1", role="attendee", response="pending", limit=10, passport_token="ppt_1")
    await calendar.get_event("acct_1", "cev_1")
    await calendar.agenda("acct_1", "2026-11-01", "2026-11-30", time_zone="Europe/Stockholm", passport_token="ppt_1")
    await calendar.create_event("acct_1", EVENT, passport_token="ppt_1")
    await calendar.update_event(
        "acct_1", "cev_1", {"start": "2026-11-04T10:00", "scope": "following", "occurrence": "x"}
    )
    await calendar.cancel_event("acct_1", "cev_1", occurrence="2026-11-05T09:00", scope="occurrence")
    await calendar.respond("acct_1", "cev_2", "accept")
    await calendar.respond("acct_1", "cev_2", "decline", notify_organizer=False, passport_token="ppt_1")
    await calendar.decline_proposal("acct_1", "cev_1", "ccp_1", comment="No")
    await calendar.feed("acct_1")
    await calendar.rotate_feed("acct_1")
    await calendar.revoke_feed("acct_1")


BASE = "/v1/accounts/acct_1/calendar"
EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", f"{BASE}/events", {"params": None, "extra_headers": None}),
    (
        "GET",
        f"{BASE}/events",
        {"params": {"role": "attendee", "response": "pending", "limit": 10}, "extra_headers": PASSPORT},
    ),
    ("GET", f"{BASE}/events/cev_1", {"extra_headers": None}),
    (
        "GET",
        f"{BASE}/agenda",
        {
            "params": {"from": "2026-11-01", "to": "2026-11-30", "time_zone": "Europe/Stockholm"},
            "extra_headers": PASSPORT,
        },
    ),
    ("POST", f"{BASE}/events", {"json": EVENT, "extra_headers": PASSPORT}),
    (
        "PATCH",
        f"{BASE}/events/cev_1",
        {"json": {"start": "2026-11-04T10:00", "scope": "following", "occurrence": "x"}, "extra_headers": None},
    ),
    (
        "POST",
        f"{BASE}/events/cev_1/cancel",
        {"json": {"occurrence": "2026-11-05T09:00", "scope": "occurrence"}, "extra_headers": None},
    ),
    ("POST", f"{BASE}/events/cev_2/respond", {"json": {"response": "accept"}, "extra_headers": None}),
    (
        "POST",
        f"{BASE}/events/cev_2/respond",
        {"json": {"response": "decline", "notify_organizer": False}, "extra_headers": PASSPORT},
    ),
    ("POST", f"{BASE}/events/cev_1/counters/ccp_1/decline", {"json": {"comment": "No"}, "extra_headers": None}),
    ("GET", f"{BASE}/feed", {"extra_headers": None}),
    ("POST", f"{BASE}/feed", {"json": {}, "extra_headers": None}),
    ("DELETE", f"{BASE}/feed", {"extra_headers": None}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(CalendarService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncCalendarService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_both_clients_carry_the_service() -> None:
    stack = Stack(api_key="sk_live_x", base_url="http://api.fixture")
    assert isinstance(stack.calendar, CalendarService)
    astack = AsyncStack(api_key="sk_live_x", base_url="http://api.fixture")
    assert isinstance(astack.calendar, AsyncCalendarService)


def test_a_bad_request_is_refused_before_any_call() -> None:
    client = Capture()
    calendar = CalendarService(client)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        calendar.respond("acct_1", "cev_1", "maybe")
    with pytest.raises(ValueError):
        calendar.create_event("acct_1", ["not", "a", "dict"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        calendar.update_event("acct_1", "cev_1", {"scope": "sometimes"})
    with pytest.raises(ValueError):
        calendar.cancel_event("acct_1", "cev_1", scope="sometimes")
    with pytest.raises(ValueError):
        calendar.get_event("acct_1", "")
    assert client.calls == []


def test_ids_are_escaped_into_the_path() -> None:
    client = Capture()
    CalendarService(client).get_event("acct_1/../x", "cev 1")  # type: ignore[arg-type]
    assert client.calls[0][1] == "/v1/accounts/acct_1%2F..%2Fx/calendar/events/cev%201"


API_SRC = Path(__file__).resolve().parents[2] / "apps" / "api" / "src"
API_ROUTES = API_SRC / "hosted" / "routes"


@pytest.mark.skipif(not API_SRC.exists(), reason="the monorepo's API is not next to this package")
def test_every_request_path_is_a_route_the_api_registers() -> None:
    text = (API_ROUTES / "account-calendar.ts").read_text("utf-8")
    registered = {
        (method.upper(), re.sub(r":\w+", "*", path))
        for method, path in re.findall(r"app\.(get|put|post|patch|delete)\('(/v1/[^']+)'", text)
    }
    assert registered, "no routes parsed from the API file"
    for method, path, _ in EXPECTED_CALLS:
        wild = re.sub(r"/(acct|cev|ccp)_[A-Za-z0-9]+", "/*", path)
        assert (method, wild) in registered, f"{method} {path} is not a route"
