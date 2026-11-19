"""verify_webhook: the one receiver for every webhook STACK signs.

The signature vectors were produced by the TypeScript reference
(`packages/shared/src/utils/standard-webhooks.ts`, run from its built output) and are also recomputed here
with `hmac`, so the two implementations are proven to agree byte for byte. The checks mirror the
`webhooks` conformance suite (`spec/conformance/src/webhooks.mjs`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import ReplayGuard, WebhookSignatureError, verify_webhook
from getstack.control_server import ControlSignatureError, verify_control_request
from getstack.wake_webhook import WakeSignatureError
from getstack.webhook import webhook_secret_key

SECRET = "whsec_" + "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="  # bytes 0..31
OTHER = "whsec_" + "YW5vdGhlci1zZWNyZXQta2V5LTAxMjM0NTY3ODlhYg=="
# A secret from before the signed scheme: 64 hexadecimal characters (32 bytes of 0x5c).
LEGACY = "5c" * 32
CHOSEN = "a chosen secret, 30+ bytes long!"
ID = "msg_0123456789abcdef"
NOW = 1_760_000_000
BODY = (
    '{"id":"msg_0123456789abcdef","event_type":"test","severity":"info","payload":{},'
    '"timestamp":"2026-10-24T00:00:00.000Z"}'
)

# From the TypeScript reference: signStandardWebhook({ id: ID, body: BODY, secrets: [secret], timestamp: NOW }).
TS_SIGNATURE = "v1,h1fi9vlAd2Fz1B8z0oYaogY4aU836mIU5R2FqVIM6Gw="
TS_SIGNATURE_LEGACY = "v1,+WestFMEZMjiJUkUwcYm5OrdQNYrN3sQFrVCRWPhb8Q="


def _key(secret: str) -> bytes:
    if secret.startswith("whsec_"):
        return base64.b64decode(secret[len("whsec_") :])
    try:
        return base64.b64decode(secret, validate=True)
    except ValueError:
        return secret.encode()


def _sign(secrets: list[str], message_id: str = ID, timestamp: int = NOW, body: str = BODY) -> dict[str, str]:
    signatures = []
    for secret in secrets:
        digest = hmac.new(_key(secret), f"{message_id}.{timestamp}.{body}".encode(), hashlib.sha256).digest()
        signatures.append("v1," + base64.b64encode(digest).decode())
    return {
        "webhook-id": message_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": " ".join(signatures),
    }


def test_the_python_signature_equals_the_typescript_reference() -> None:
    assert _sign([SECRET])["webhook-signature"] == TS_SIGNATURE
    assert _sign([LEGACY])["webhook-signature"] == TS_SIGNATURE_LEGACY


def test_a_signed_message_is_accepted_and_read() -> None:
    headers = {"webhook-id": ID, "webhook-timestamp": str(NOW), "webhook-signature": TS_SIGNATURE}
    assert verify_webhook(headers, BODY, SECRET, now=NOW) == json.loads(BODY)
    # Header names in any case, bytes for the body, and the secret in a list.
    shouty = {k.upper(): v for k, v in headers.items()}
    assert verify_webhook(shouty, BODY.encode(), [SECRET], now=NOW)["id"] == ID


def test_a_captured_message_replayed_after_the_tolerance_is_refused() -> None:
    headers = _sign([SECRET])
    assert verify_webhook(headers, BODY, SECRET, now=NOW + 300)
    for now in (NOW + 301, NOW - 301):
        with pytest.raises(WebhookSignatureError) as error:
            verify_webhook(headers, BODY, SECRET, now=now)
        assert error.value.reason == "stale"
    assert verify_webhook(headers, BODY, SECRET, tolerance_seconds=7_200, now=NOW + 3_600)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda h, b: (h, b.replace("test", "tesu")), "bad_signature"),
        (lambda h, b: ({**h, "webhook-id": "msg_other"}, b), "bad_signature"),
        (lambda h, b: ({**h, "webhook-timestamp": str(NOW + 1)}, b), "bad_signature"),
        (lambda h, b: ({k: v for k, v in h.items() if k != "webhook-signature"}, b), "missing_headers"),
        (lambda h, b: ({}, b), "missing_headers"),
        (lambda h, b: ({**h, "webhook-timestamp": "soon"}, b), "bad_timestamp"),
        (lambda h, b: ({**h, "webhook-signature": "v1,!!!"}, b), "bad_signature"),
        (lambda h, b: ({**h, "webhook-signature": "v2," + "A" * 43}, b), "bad_signature"),
        (lambda h, b: ({**h, "webhook-signature": ""}, b), "missing_headers"),
    ],
)
def test_a_tampered_or_malformed_message_is_refused(change: Any, reason: str) -> None:
    headers, body = change(_sign([SECRET]), BODY)
    with pytest.raises(WebhookSignatureError) as error:
        verify_webhook(headers, body, SECRET, now=NOW)
    assert error.value.reason == reason


def test_a_wrong_secret_is_refused_and_either_secret_works_during_a_rotation() -> None:
    with pytest.raises(WebhookSignatureError):
        verify_webhook(_sign([SECRET]), BODY, OTHER, now=NOW)
    both = _sign([SECRET, OTHER])
    assert len(both["webhook-signature"].split(" ")) == 2
    for secret in (SECRET, OTHER):
        assert verify_webhook(both, BODY, secret, now=NOW)
    assert verify_webhook(both, BODY, [OTHER, SECRET], now=NOW)
    odd = {**both, "webhook-signature": "v2," + "A" * 43 + " " + both["webhook-signature"]}
    assert verify_webhook(odd, BODY, SECRET, now=NOW)


def test_a_body_that_is_not_a_json_object_is_refused_after_the_signature() -> None:
    for text in ("not json", "[1,2]", '"x"', "null"):
        with pytest.raises(WebhookSignatureError) as error:
            verify_webhook(_sign([SECRET], body=text), text, SECRET, now=NOW)
        assert error.value.reason == "bad_body"


def test_the_replay_guard_refuses_a_repeat_only_for_a_genuine_message() -> None:
    guard = ReplayGuard()
    headers = _sign([SECRET])
    assert verify_webhook(headers, BODY, SECRET, now=NOW, replay_guard=guard)
    with pytest.raises(WebhookSignatureError) as error:
        verify_webhook(headers, BODY, SECRET, now=NOW + 5, replay_guard=guard)
    assert error.value.reason == "replayed"
    fresh = ReplayGuard()
    with pytest.raises(WebhookSignatureError):
        verify_webhook({**headers, "webhook-signature": "v1,AAAA"}, BODY, SECRET, now=NOW, replay_guard=fresh)
    assert verify_webhook(headers, BODY, SECRET, now=NOW, replay_guard=fresh)
    # After a delivery that could not be handled the id is given back, so the retry is handled.
    fresh.forget(ID)
    assert verify_webhook(headers, BODY, SECRET, now=NOW + 1, replay_guard=fresh)


def test_the_replay_guard_forgets_an_id_after_its_window_and_bounds_its_memory() -> None:
    guard = ReplayGuard(ttl_seconds=10, max_entries=2)
    assert guard.first_seen("a", 0)
    assert not guard.first_seen("a", 5)
    assert guard.first_seen("a", 10.001)
    assert guard.first_seen("b", 10.002)
    assert guard.first_seen("c", 10.003)  # makes room by dropping the oldest
    assert guard.first_seen("a", 10.004)


def test_a_secret_from_before_the_scheme_is_read_as_the_libraries_read_it() -> None:
    headers = {"webhook-id": ID, "webhook-timestamp": str(NOW), "webhook-signature": TS_SIGNATURE_LEGACY}
    assert verify_webhook(headers, BODY, LEGACY, now=NOW)
    # A 64-character hexadecimal string is valid base64: its key is the 48 bytes it decodes to.
    assert webhook_secret_key(LEGACY) == base64.b64decode(LEGACY)
    assert len(webhook_secret_key(LEGACY)) == 48
    # A value the owner chose that is not base64 is read by its UTF-8 bytes.
    assert webhook_secret_key(CHOSEN) == CHOSEN.encode()
    assert verify_webhook(_sign([CHOSEN]), BODY, CHOSEN, now=NOW)


def test_a_malformed_secret_is_a_setup_error_not_an_attack() -> None:
    headers = _sign([SECRET])
    with pytest.raises(ValueError, match="16 bytes"):
        verify_webhook(headers, BODY, "short", now=NOW)
    with pytest.raises(ValueError, match="16 bytes"):
        verify_webhook(headers, BODY, "whsec_AAAA", now=NOW)
    with pytest.raises(ValueError, match="secret"):
        verify_webhook(headers, BODY, [], now=NOW)


def test_the_older_helpers_still_work_and_raise_their_own_errors() -> None:
    headers = _sign([SECRET])
    assert verify_control_request(headers, BODY, SECRET, now=NOW)["id"] == ID
    with pytest.raises(ControlSignatureError) as error:
        verify_control_request(headers, BODY, OTHER, now=NOW)
    assert error.value.reason == "bad_signature"
    # They are webhook errors too, so one handler can catch every kind.
    assert issubclass(ControlSignatureError, WebhookSignatureError)
    assert issubclass(WakeSignatureError, WebhookSignatureError)
    # The control helpers keep refusing a secret that is not whsec_.
    with pytest.raises(ValueError, match="whsec_"):
        verify_control_request(headers, BODY, LEGACY, now=NOW)
