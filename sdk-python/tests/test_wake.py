"""Wake-ups: request shapes (sync and async alike), passport headers, the routes, and the webhook check."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack, WakeSignatureError, verify_wake_webhook
from getstack._async.wake import AsyncWakesService
from getstack.wake import WakesService

PASSPORT = {"X-Passport-Token": "ppt_1"}
RULE: dict[str, Any] = {"name": "Mail", "source": "email", "task": "Answer the customer."}
RING_RULE: dict[str, Any] = {"name": "Ring", "source": "incoming_call", "task": "Answer it or decline it."}
SCHEDULE: dict[str, Any] = {"name": "Morning", "cron": "30 9 * * *", "task": "Do the round."}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive_sync(wakes: WakesService) -> None:
    wakes.list("agt_1")
    wakes.list("agt_1", status="open", limit=5, cursor="c", passport_token="ppt_1")
    wakes.get("agt_1", "wke_1")
    wakes.acknowledge("agt_1", "wke_1", passport_token="ppt_1")
    wakes.get_settings()
    wakes.get_settings("agt_1")
    wakes.set_settings({"enabled": False})
    wakes.set_settings({"time_zone": None}, "agt_1")
    wakes.rotate_webhook_secret("agt_1")
    wakes.test_webhook("agt_1")
    wakes.list_rules()
    wakes.list_rules("agt_1")
    wakes.create_rule(RULE)
    wakes.create_rule(RULE, "agt_1")
    wakes.create_rule(RING_RULE, "agt_1")
    wakes.update_rule("wkr_1", RULE)
    wakes.delete_rule("wkr_1")
    wakes.list_schedules("agt_1")
    wakes.create_schedule("agt_1", SCHEDULE)
    wakes.update_schedule("agt_1", "wsc_1", SCHEDULE)
    wakes.delete_schedule("agt_1", "wsc_1")


async def _drive_async(wakes: AsyncWakesService) -> None:
    await wakes.list("agt_1")
    await wakes.list("agt_1", status="open", limit=5, cursor="c", passport_token="ppt_1")
    await wakes.get("agt_1", "wke_1")
    await wakes.acknowledge("agt_1", "wke_1", passport_token="ppt_1")
    await wakes.get_settings()
    await wakes.get_settings("agt_1")
    await wakes.set_settings({"enabled": False})
    await wakes.set_settings({"time_zone": None}, "agt_1")
    await wakes.rotate_webhook_secret("agt_1")
    await wakes.test_webhook("agt_1")
    await wakes.list_rules()
    await wakes.list_rules("agt_1")
    await wakes.create_rule(RULE)
    await wakes.create_rule(RULE, "agt_1")
    await wakes.create_rule(RING_RULE, "agt_1")
    await wakes.update_rule("wkr_1", RULE)
    await wakes.delete_rule("wkr_1")
    await wakes.list_schedules("agt_1")
    await wakes.create_schedule("agt_1", SCHEDULE)
    await wakes.update_schedule("agt_1", "wsc_1", SCHEDULE)
    await wakes.delete_schedule("agt_1", "wsc_1")


EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", "/v1/agents/agt_1/wakes", {"params": None, "extra_headers": None}),
    (
        "GET",
        "/v1/agents/agt_1/wakes",
        {"params": {"status": "open", "limit": 5, "cursor": "c"}, "extra_headers": PASSPORT},
    ),
    ("GET", "/v1/agents/agt_1/wakes/wke_1", {"extra_headers": None}),
    ("POST", "/v1/agents/agt_1/wakes/wke_1/acknowledge", {"json": {}, "extra_headers": PASSPORT}),
    ("GET", "/v1/wake/settings", {}),
    ("GET", "/v1/agents/agt_1/wake/settings", {}),
    ("PUT", "/v1/wake/settings", {"json": {"enabled": False}}),
    ("PUT", "/v1/agents/agt_1/wake/settings", {"json": {"time_zone": None}}),
    ("POST", "/v1/agents/agt_1/wake/webhook/rotate-secret", {"json": {}}),
    ("POST", "/v1/agents/agt_1/wake/webhook/test", {"json": {}}),
    ("GET", "/v1/wake/rules", {}),
    ("GET", "/v1/agents/agt_1/wake/rules", {}),
    ("POST", "/v1/wake/rules", {"json": RULE}),
    ("POST", "/v1/agents/agt_1/wake/rules", {"json": RULE}),
    ("POST", "/v1/agents/agt_1/wake/rules", {"json": RING_RULE}),
    ("PUT", "/v1/wake/rules/wkr_1", {"json": RULE}),
    ("DELETE", "/v1/wake/rules/wkr_1", {}),
    ("GET", "/v1/agents/agt_1/wake/schedules", {}),
    ("POST", "/v1/agents/agt_1/wake/schedules", {"json": SCHEDULE}),
    ("PUT", "/v1/agents/agt_1/wake/schedules/wsc_1", {"json": SCHEDULE}),
    ("DELETE", "/v1/agents/agt_1/wake/schedules/wsc_1", {}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(WakesService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncWakesService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_both_clients_carry_the_services() -> None:
    stack = Stack(api_key="sk_live_x", base_url="http://api.fixture")
    assert isinstance(stack.wakes, WakesService)
    astack = AsyncStack(api_key="sk_live_x", base_url="http://api.fixture")
    assert isinstance(astack.wakes, AsyncWakesService)


def test_a_bad_request_is_refused_before_any_call() -> None:
    client = Capture()
    wakes = WakesService(client)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        wakes.set_settings(["not", "a", "dict"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        wakes.get("agt_1", "")
    assert client.calls == []


def test_ids_are_escaped_into_the_path() -> None:
    client = Capture()
    WakesService(client).get("agt_1/../x", "wke 1")  # type: ignore[arg-type]
    assert client.calls[0][1] == "/v1/agents/agt_1%2F..%2Fx/wakes/wke%201"


API_SRC = Path(__file__).resolve().parents[2] / "apps" / "api" / "src"
API_ROUTES = API_SRC / "hosted" / "routes"


@pytest.mark.skipif(not API_SRC.exists(), reason="the monorepo's API is not next to this package")
def test_every_request_path_is_a_route_the_api_registers() -> None:
    registered = set()
    for name in ("wake.ts",):
        text = (API_ROUTES / name).read_text("utf-8")
        for method, path in re.findall(r"app\.(get|put|post|delete)\('(/v1/[^']+)'", text):
            registered.add((method.upper(), re.sub(r":\w+", "*", path)))
    assert registered, "no routes parsed from the API files"
    for method, path, _ in EXPECTED_CALLS:
        wild = re.sub(r"/(acct|agt|wke|wsc|wkr)_[A-Za-z0-9]+", "/*", path)
        assert (method, wild) in registered, f"{method} {path} is not a route"


# ── The webhook an agent receives ──────────────────────────────────────

SECRET = "whsec_" + base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
WAKE = {
    "type": "stack.wake",
    "version": "2",
    "wake_id": "wke_abc",
    "account_id": "acct_1",
    "agent_id": "agt_1",
    "mission_id": "ms_1",
    "source": "email",
    "task": "Read it.",
    "occurred_at": "2026-10-21T10:00:00Z",
    "event": {},
}


def _signed(
    body: str, wake_id: str = "wke_abc", timestamp: int = 1_790_000_000, secret: str = SECRET
) -> dict[str, str]:
    key = base64.b64decode(secret[len("whsec_") :])
    mac = hmac.new(key, f"{wake_id}.{timestamp}.{body}".encode(), hashlib.sha256).digest()
    return {
        "webhook-id": wake_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": "v1," + base64.b64encode(mac).decode(),
    }


def test_a_signed_wake_is_accepted_and_read() -> None:
    body = json.dumps(WAKE)
    assert verify_wake_webhook(_signed(body), body, SECRET, now=1_790_000_005) == WAKE
    assert verify_wake_webhook(_signed(body), body.encode(), [SECRET], now=1_790_000_005) == WAKE


def test_the_wake_of_a_ringing_call_carries_its_call_id_and_its_checks_never_the_number_calling() -> None:
    ringing = {
        **WAKE,
        "source": "incoming_call",
        "task": "Incoming call.",
        "event": {"call_id": "acall_1", "answer_by": "2026-10-21T10:00:30Z"},
        "sender_tags": ["new_sender"],
    }
    body = json.dumps(ringing)
    assert verify_wake_webhook(_signed(body), body, SECRET, now=1_790_000_005) == ringing


def test_a_decision_wake_of_an_agent_with_no_account_names_the_item_and_how_it_ended() -> None:
    decided = {
        **WAKE,
        "account_id": None,
        "mission_id": None,
        "source": "decision",
        "task": "Intent approval: approved.",
        "event": {"item_kind": "intent_approval", "item_id": "iap_1", "result": "approved"},
    }
    body = json.dumps(decided)
    assert verify_wake_webhook(_signed(body), body, SECRET, now=1_790_000_005) == decided


def test_a_wake_that_is_tampered_stale_or_not_a_wake_is_refused() -> None:
    body = json.dumps(WAKE)
    headers = _signed(body)
    with pytest.raises(WakeSignatureError) as tampered:
        verify_wake_webhook(headers, body.replace("Read it.", "Wire it."), SECRET, now=1_790_000_000)
    assert tampered.value.reason == "bad_signature"
    with pytest.raises(WakeSignatureError) as stale:
        verify_wake_webhook(headers, body, SECRET, now=1_790_000_900)
    assert stale.value.reason == "stale"
    with pytest.raises(WakeSignatureError) as missing:
        verify_wake_webhook({}, body, SECRET)
    assert missing.value.reason == "missing_headers"
    other = json.dumps({"hello": "world"})
    with pytest.raises(WakeSignatureError) as not_a_wake:
        verify_wake_webhook(_signed(other, "x"), other, SECRET, now=1_790_000_000)
    assert not_a_wake.value.reason == "bad_body"
    # A body of the version before the untrusted object was removed is not this version's wake.
    older = json.dumps({**WAKE, "version": "1"})
    with pytest.raises(WakeSignatureError) as old_version:
        verify_wake_webhook(_signed(older), older, SECRET, now=1_790_000_000)
    assert old_version.value.reason == "bad_body"
    with pytest.raises(WakeSignatureError) as another:
        verify_wake_webhook(_signed(body, "wke_other"), body, SECRET, now=1_790_000_000)
    assert another.value.reason == "id_mismatch"


def test_a_malformed_secret_is_a_setup_error_not_an_attack() -> None:
    with pytest.raises(ValueError):
        verify_wake_webhook({}, "", "plain")
