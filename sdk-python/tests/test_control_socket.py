"""Control socket: request shapes (sync and async alike), approval headers, and the signing helpers.

The signature vectors below were produced by the TypeScript reference
(`packages/shared/src/utils/standard-webhooks.ts`, run from its built output) and are also recomputed
here with `hmac`, so the two implementations are proven to agree byte for byte.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.control_socket import AsyncControlSocketService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.control_server import ControlSignatureError, sign_control_answer, verify_control_request
from getstack.control_socket import ControlSocketService
from getstack.errors import GovernanceApprovalRequiredError

SECRET = "whsec_" + "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="  # bytes 0..31
SECOND_SECRET = "whsec_" + "YW5vdGhlci1zZWNyZXQta2V5LTAxMjM0NTY3ODlhYg=="
DECISION_ID = "dec_0123456789abcdef"
TIMESTAMP = 1_760_000_000
BODY = '{"type":"stack.decision.request","decision_id":"dec_0123456789abcdef","action":{"type":"email.send"}}'
DIGEST = "sha256:" + "ab" * 32

# From the TypeScript reference: signStandardWebhook({id, body, secrets, timestamp}).
TS_SIGNATURE = "v1,SsTjPX5a3oJCkbsinP2BwVKnBxP4inDhsf2PdLvo664="
TS_SIGNATURE_SECOND = "v1,uKg7KKsPjxQ2E1PD7r0j5fDLVBotPYXBQsR5shTTa4g="
ANSWER_BODY = '{"decision_id":"dec_0123456789abcdef","request_digest":"' + DIGEST + '","verdict":"allow"}'
TS_ANSWER_SIGNATURE = "v1,guQq6rMNfxC/QF6mv7udEApHP3TYTCwmcyRGZKn4uqk="


def _hmac_signature(secret: str, message_id: str, timestamp: int, body: str) -> str:
    key = base64.b64decode(secret[len("whsec_") :])
    digest = hmac.new(key, f"{message_id}.{timestamp}.{body}".encode(), hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode()


def _headers(signature: str = TS_SIGNATURE, **overrides: str) -> dict[str, str]:
    headers = {
        "webhook-id": DECISION_ID,
        "webhook-timestamp": str(TIMESTAMP),
        "webhook-signature": signature,
    }
    headers.update(overrides)
    return headers


# --- signing ---------------------------------------------------------------------------------------


def test_the_reference_vectors_match_an_independent_hmac() -> None:
    assert _hmac_signature(SECRET, DECISION_ID, TIMESTAMP, BODY) == TS_SIGNATURE
    assert _hmac_signature(SECOND_SECRET, DECISION_ID, TIMESTAMP, BODY) == TS_SIGNATURE_SECOND
    assert _hmac_signature(SECRET, DECISION_ID, TIMESTAMP, ANSWER_BODY) == TS_ANSWER_SIGNATURE


def test_verify_accepts_the_typescript_signature() -> None:
    parsed = verify_control_request(_headers(), BODY, SECRET, now=TIMESTAMP)
    assert parsed["decision_id"] == DECISION_ID
    assert parsed["action"] == {"type": "email.send"}


def test_verify_takes_bytes_and_any_header_case() -> None:
    headers = {key.upper(): value for key, value in _headers().items()}
    assert verify_control_request(headers, BODY.encode(), SECRET, now=TIMESTAMP)["type"] == "stack.decision.request"
    listed = {key: [value] for key, value in _headers().items()}
    assert verify_control_request(listed, bytearray(BODY.encode()), SECRET, now=TIMESTAMP)


def test_verify_accepts_one_of_two_signatures_during_a_rotation() -> None:
    both = f"{TS_SIGNATURE} {TS_SIGNATURE_SECOND}"
    # Signed with both: either secret alone verifies it.
    assert verify_control_request(_headers(both), BODY, SECOND_SECRET, now=TIMESTAMP)
    assert verify_control_request(_headers(both), BODY, [SECOND_SECRET, SECRET], now=TIMESTAMP)
    # Signed with the old one only: a receiver holding both accepts it.
    assert verify_control_request(_headers(), BODY, [SECOND_SECRET, SECRET], now=TIMESTAMP)


@pytest.mark.parametrize(
    ("headers", "body", "secret", "now", "reason"),
    [
        (_headers(), BODY + " ", SECRET, TIMESTAMP, "bad_signature"),
        (_headers(), BODY, SECOND_SECRET, TIMESTAMP, "bad_signature"),
        (_headers("v2,abc"), BODY, SECRET, TIMESTAMP, "bad_signature"),
        (_headers("v1,not*base64"), BODY, SECRET, TIMESTAMP, "bad_signature"),
        (_headers(**{"webhook-id": "dec_other"}), BODY, SECRET, TIMESTAMP, "bad_signature"),
        (_headers(), BODY, SECRET, TIMESTAMP + 301, "stale"),
        (_headers(), BODY, SECRET, TIMESTAMP - 301, "stale"),
        (_headers(**{"webhook-timestamp": "17600000x0"}), BODY, SECRET, TIMESTAMP, "bad_timestamp"),
        (_headers(**{"webhook-timestamp": "-5"}), BODY, SECRET, TIMESTAMP, "bad_timestamp"),
        ({"webhook-id": DECISION_ID}, BODY, SECRET, TIMESTAMP, "missing_headers"),
        ({}, BODY, SECRET, TIMESTAMP, "missing_headers"),
    ],
)
def test_verify_refuses_what_it_should(headers: dict[str, str], body: str, secret: str, now: int, reason: str) -> None:
    with pytest.raises(ControlSignatureError) as refused:
        verify_control_request(headers, body, secret, now=now)
    assert refused.value.reason == reason


def test_the_tolerance_window_is_inclusive_and_configurable() -> None:
    assert verify_control_request(_headers(), BODY, SECRET, now=TIMESTAMP + 300)
    with pytest.raises(ControlSignatureError):
        verify_control_request(_headers(), BODY, SECRET, tolerance_seconds=10, now=TIMESTAMP + 11)
    assert verify_control_request(_headers(), BODY, SECRET, tolerance_seconds=10, now=TIMESTAMP - 10)


def test_a_good_signature_over_a_body_that_is_not_an_object_is_refused() -> None:
    body = "[1,2]"
    signature = _hmac_signature(SECRET, DECISION_ID, TIMESTAMP, body)
    with pytest.raises(ControlSignatureError) as refused:
        verify_control_request(_headers(signature), body, SECRET, now=TIMESTAMP)
    assert refused.value.reason == "bad_body"


@pytest.mark.parametrize("secret", ["abc", "whsec_!!!", "whsec_AAAA", ""])
def test_a_malformed_secret_is_a_setup_error_not_a_signature_failure(secret: str) -> None:
    with pytest.raises(ValueError, match="webhook secret") as raised:
        verify_control_request(_headers(), BODY, secret, now=TIMESTAMP)
    assert not isinstance(raised.value, ControlSignatureError)
    with pytest.raises(ValueError, match="at least one secret"):
        verify_control_request(_headers(), BODY, [], now=TIMESTAMP)


def test_sign_answer_matches_the_typescript_signature() -> None:
    signed = sign_control_answer(DECISION_ID, DIGEST, "allow", SECRET, timestamp=TIMESTAMP)
    assert signed.body == ANSWER_BODY
    assert signed.headers == {
        "webhook-id": DECISION_ID,
        "webhook-timestamp": str(TIMESTAMP),
        "webhook-signature": TS_ANSWER_SIGNATURE,
    }


def test_sign_answer_with_two_secrets_carries_both_signatures() -> None:
    signed = sign_control_answer(DECISION_ID, DIGEST, "allow", [SECRET, SECOND_SECRET], timestamp=TIMESTAMP)
    first, second = signed.headers["webhook-signature"].split(" ")
    assert first == TS_ANSWER_SIGNATURE
    assert second == _hmac_signature(SECOND_SECRET, DECISION_ID, TIMESTAMP, ANSWER_BODY)


def test_a_signed_answer_verifies_and_carries_every_field() -> None:
    signed = sign_control_answer(
        DECISION_ID,
        DIGEST,
        "deny",
        SECRET,
        reason={"code": "over_limit", "message": "Above the daily limit"},
        retry={"ref": "appr_1", "after_seconds": 30},
        policy_ref="policy:daily-limit",
        timestamp=TIMESTAMP,
    )
    parsed = verify_control_request(signed.headers, signed.body, SECRET, now=TIMESTAMP)
    assert parsed == {
        "decision_id": DECISION_ID,
        "request_digest": DIGEST,
        "verdict": "deny",
        "reason": {"code": "over_limit", "message": "Above the daily limit"},
        "retry": {"ref": "appr_1", "after_seconds": 30},
        "policy_ref": "policy:daily-limit",
    }


def test_sign_answer_stamps_the_clock_when_no_timestamp_is_given() -> None:
    signed = sign_control_answer(DECISION_ID, DIGEST, "allow", SECRET)
    assert abs(int(signed.headers["webhook-timestamp"]) - time.time()) < 5
    assert verify_control_request(signed.headers, signed.body, SECRET)["verdict"] == "allow"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"decision_id": ""},
        {"request_digest": "sha256:abc"},
        {"request_digest": "ab" * 32},
        {"verdict": "unavailable"},
        {"verdict": "ALLOW"},
        {"reason": {"code": "Over Limit"}},
        {"reason": {"message": "no code"}},
        {"reason": {"code": "ok", "message": "x" * 201}},
        {"retry": {"ref": ""}},
        {"retry": {"ref": "x" * 201}},
        {"retry": {"ref": "r", "after_seconds": -1}},
        {"retry": {"ref": "r", "after_seconds": 86_401}},
        {"retry": {"ref": "r", "after_seconds": 1.5}},
        {"retry": {"ref": "r", "after_seconds": True}},
        {"policy_ref": "x" * 201},
        {"secrets": []},
    ],
)
def test_sign_answer_refuses_what_the_server_would_ignore(kwargs: dict[str, Any]) -> None:
    arguments: dict[str, Any] = {
        "decision_id": DECISION_ID,
        "request_digest": DIGEST,
        "verdict": "allow",
        "secrets": SECRET,
    }
    arguments.update(kwargs)
    with pytest.raises(ValueError):
        sign_control_answer(**arguments)


# --- requests --------------------------------------------------------------------------------------


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


APPROVAL = {"X-Governance-Approval": "gvr_1"}


def _drive_sync(socket: ControlSocketService) -> None:
    socket.get()
    socket.set_decision_address("https://decide.example.com/stack")
    socket.set_decision_address("https://decide.example.com/stack", 800, governance_approval_id="gvr_1")
    socket.set_events_address("https://events.example.com/in", governance_approval_id="gvr_1")
    socket.clear("decision")
    socket.clear("events", governance_approval_id="gvr_1")
    socket.verify("decision")
    socket.verify("decision", governance_approval_id="gvr_1")
    socket.test("events")
    socket.rotate_secret("decision", governance_approval_id="gvr_1")
    socket.set_mode("hosted")
    socket.set_mode("none", governance_approval_id="gvr_1")
    socket.set_checked_types(["email.send", "card.checkout"])
    socket.set_checked_types(None, governance_approval_id="gvr_1")
    socket.set_on_unavailable("refuse")
    socket.set_on_unavailable("allow", governance_approval_id="gvr_1")
    socket.list_decisions()
    socket.list_decisions(limit=10, account_id="acct_1", verdict="deny", before="2026-10-21T10:00:00.000Z")
    socket.get_decision("dec_0123456789abcdef")


async def _drive_async(socket: AsyncControlSocketService) -> None:
    await socket.get()
    await socket.set_decision_address("https://decide.example.com/stack")
    await socket.set_decision_address("https://decide.example.com/stack", 800, governance_approval_id="gvr_1")
    await socket.set_events_address("https://events.example.com/in", governance_approval_id="gvr_1")
    await socket.clear("decision")
    await socket.clear("events", governance_approval_id="gvr_1")
    await socket.verify("decision")
    await socket.verify("decision", governance_approval_id="gvr_1")
    await socket.test("events")
    await socket.rotate_secret("decision", governance_approval_id="gvr_1")
    await socket.set_mode("hosted")
    await socket.set_mode("none", governance_approval_id="gvr_1")
    await socket.set_checked_types(["email.send", "card.checkout"])
    await socket.set_checked_types(None, governance_approval_id="gvr_1")
    await socket.set_on_unavailable("refuse")
    await socket.set_on_unavailable("allow", governance_approval_id="gvr_1")
    await socket.list_decisions()
    await socket.list_decisions(limit=10, account_id="acct_1", verdict="deny", before="2026-10-21T10:00:00.000Z")
    await socket.get_decision("dec_0123456789abcdef")


EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", "/v1/control-socket", {}),
    (
        "PUT",
        "/v1/control-socket/decision",
        {"json": {"url": "https://decide.example.com/stack"}, "extra_headers": None},
    ),
    (
        "PUT",
        "/v1/control-socket/decision",
        {"json": {"url": "https://decide.example.com/stack", "timeout_ms": 800}, "extra_headers": APPROVAL},
    ),
    ("PUT", "/v1/control-socket/events", {"json": {"url": "https://events.example.com/in"}, "extra_headers": APPROVAL}),
    ("DELETE", "/v1/control-socket/decision", {"extra_headers": None}),
    ("DELETE", "/v1/control-socket/events", {"extra_headers": APPROVAL}),
    ("POST", "/v1/control-socket/decision/verify", {"json": {}, "extra_headers": None}),
    ("POST", "/v1/control-socket/decision/verify", {"json": {}, "extra_headers": APPROVAL}),
    ("POST", "/v1/control-socket/events/test", {"json": {}}),
    ("POST", "/v1/control-socket/decision/secret/rotate", {"json": {}, "extra_headers": APPROVAL}),
    ("PUT", "/v1/control-socket/mode", {"json": {"mode": "hosted"}, "extra_headers": None}),
    ("PUT", "/v1/control-socket/mode", {"json": {"mode": "none"}, "extra_headers": APPROVAL}),
    (
        "PUT",
        "/v1/control-socket/checked-types",
        {"json": {"types": ["email.send", "card.checkout"]}, "extra_headers": None},
    ),
    ("PUT", "/v1/control-socket/checked-types", {"json": {"types": None}, "extra_headers": APPROVAL}),
    ("PUT", "/v1/control-socket/on-unavailable", {"json": {"on_unavailable": "refuse"}, "extra_headers": None}),
    ("PUT", "/v1/control-socket/on-unavailable", {"json": {"on_unavailable": "allow"}, "extra_headers": APPROVAL}),
    ("GET", "/v1/control-decisions", {"params": None}),
    (
        "GET",
        "/v1/control-decisions",
        {"params": {"limit": 10, "account_id": "acct_1", "verdict": "deny", "before": "2026-10-21T10:00:00.000Z"}},
    ),
    ("GET", "/v1/control-decisions/dec_0123456789abcdef", {}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(ControlSocketService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncControlSocketService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_a_bad_target_mode_or_id_is_refused_before_any_request() -> None:
    client = Capture()
    socket = ControlSocketService(client)  # type: ignore[arg-type]
    for call in (
        lambda: socket.clear("decisions"),
        lambda: socket.verify("../mode"),
        lambda: socket.test("other"),
        lambda: socket.rotate_secret("x"),
        lambda: socket.set_mode("remote"),
        lambda: socket.set_mode("auto"),
    ):
        with pytest.raises(ValueError):
            call()
    assert client.calls == []


def test_a_decision_id_is_escaped_into_the_path() -> None:
    client = Capture()
    ControlSocketService(client).get_decision("dec/../x?y")  # type: ignore[arg-type]
    assert client.calls[0][1] == "/v1/control-decisions/dec%2F..%2Fx%3Fy"


def test_both_clients_expose_the_same_control_socket_surface() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    s, a = Stack(**kw).control_socket, AsyncStack(**kw).control_socket
    s_methods = {n: m for n, m in inspect.getmembers(s, inspect.ismethod) if not n.startswith("_")}
    a_methods = {n: m for n, m in inspect.getmembers(a, inspect.ismethod) if not n.startswith("_")}
    expected = {
        "get",
        "set_decision_address",
        "set_events_address",
        "clear",
        "verify",
        "test",
        "rotate_secret",
        "set_mode",
        "set_checked_types",
        "set_on_unavailable",
        "list_decisions",
        "get_decision",
    }
    assert set(s_methods) == set(a_methods) == expected
    for name, method in s_methods.items():
        assert inspect.iscoroutinefunction(a_methods[name]), name
        assert list(inspect.signature(method).parameters) == list(inspect.signature(a_methods[name]).parameters), name


def _client(handler: Any) -> HttpClient:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return http


def test_the_approval_header_and_a_json_body_reach_the_wire() -> None:
    seen: list[httpx.Request] = []
    secret_view = {"socket": {"socket_id": "csk_1"}, "secret": SECRET}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=secret_view)

    socket = ControlSocketService(_client(handler))
    created = socket.set_decision_address("https://decide.example.com/stack", 900, governance_approval_id="gvr_9")
    socket.verify("decision")
    socket.list_decisions(limit=5, verdict="unavailable")
    assert created == secret_view
    assert [(r.method, r.url.path) for r in seen] == [
        ("PUT", "/v1/control-socket/decision"),
        ("POST", "/v1/control-socket/decision/verify"),
        ("GET", "/v1/control-decisions"),
    ]
    assert seen[0].headers["x-governance-approval"] == "gvr_9"
    assert json.loads(seen[0].content) == {"url": "https://decide.example.com/stack", "timeout_ms": 900}
    assert "x-governance-approval" not in seen[1].headers
    assert json.loads(seen[1].content) == {}
    assert dict(seen[2].url.params) == {"limit": "5", "verdict": "unavailable"}


def test_an_approval_wall_is_a_typed_error_with_the_approval_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "code": "GOVERNANCE_APPROVAL_REQUIRED",
                    "message": "Approval needed",
                    "details": {"approval_id": "gvr_77"},
                }
            },
        )

    with pytest.raises(GovernanceApprovalRequiredError) as refused:
        ControlSocketService(_client(handler)).rotate_secret("decision")
    assert refused.value.approval_id == "gvr_77"


def test_the_async_wire_matches() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"target": "events", "secret": SECRET, "previous_valid_until": None})

    async def run() -> Any:
        http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
        http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return await AsyncControlSocketService(http).rotate_secret("events", governance_approval_id="gvr_2")

    assert asyncio.run(run())["secret"] == SECRET
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/v1/control-socket/events/secret/rotate"
    assert seen[0].headers["x-governance-approval"] == "gvr_2"
