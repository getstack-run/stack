"""Verify any webhook STACK signs: ``verify_webhook``.

Wake-ups, notification delivery methods, inbound-webhook forwards (partner tenants included), network
revocation pushes and both directions of the control socket are all signed as Standard Webhooks
(https://www.standardwebhooks.com), written out in ``spec/webhooks/SPEC.md``:

- ``webhook-id``: the message id, the same on every retry of one message.
- ``webhook-timestamp``: unix seconds.
- ``webhook-signature``: space-separated ``v1,<base64>`` signatures, each an HMAC-SHA256 over
  ``<id>.<timestamp>.<body>`` keyed with the bytes of your secret (``whsec_<base64>``). During a rotation
  there are two, one per live secret, and any one of them is enough.

Verify the raw body exactly as received; re-serialised JSON does not match. A message is fresh for
``tolerance_seconds`` (300) either side of your clock. Keep the ids you have handled
(``ReplayGuard``) and acknowledge a repeat without handling it again.

Example (Flask)::

    @app.post("/stack/webhook")
    def webhook():
        try:
            payload = verify_webhook(request.headers, request.get_data(), SECRET, replay_guard=GUARD)
        except WebhookSignatureError:
            return "", 401
        handle(payload)
        return "", 204
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from typing import Any, cast

WEBHOOK_SECRET_PREFIX = "whsec_"
WEBHOOK_ID_HEADER = "webhook-id"
WEBHOOK_TIMESTAMP_HEADER = "webhook-timestamp"
WEBHOOK_SIGNATURE_HEADER = "webhook-signature"

# STACK's receivers refuse a message outside this window, in either direction; so does this module by default.
DEFAULT_TOLERANCE_SECONDS = 300

_SECRET_MIN_BYTES = 16
_TIMESTAMP = re.compile(r"^\d{1,12}$")
_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")


class WebhookSignatureError(ValueError):
    """A received message failed verification. ``reason`` says why; answer 401 and do nothing else.

    ``reason`` is one of ``missing_headers``, ``bad_timestamp``, ``stale``, ``bad_signature``, ``bad_body``
    (the signature is good but the body is not a JSON object) or ``replayed`` (this ``webhook-id`` was
    already seen by the ``replay_guard``).
    """

    def __init__(self, reason: str):
        super().__init__(f"webhook refused: {reason}")
        self.reason = reason


class ReplayGuard:
    """Remembers the ids it is given for a while, so a repeat inside the tolerance is noticed.

    One process only; share the ids through your own store when you run several. ``ttl_seconds`` is twice
    the tolerance by default, so an id outlives the window in which its signature is fresh.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_TOLERANCE_SECONDS * 2, max_entries: int = 100_000):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def first_seen(self, message_id: str, now: float | None = None) -> bool:
        """True the first time an id is offered inside the window, False on a repeat."""
        clock = time.time() if now is None else now
        with self._lock:
            while self._seen:
                oldest = next(iter(self._seen))
                if self._seen[oldest] > clock:
                    break
                del self._seen[oldest]
            if message_id in self._seen:
                return False
            if len(self._seen) >= self._max:
                self._seen.popitem(last=False)
            self._seen[message_id] = clock + self._ttl
            return True

    def forget(self, message_id: str) -> None:
        """Take an id back, after a delivery you could not handle, so STACK's retry is not taken for a replay."""
        with self._lock:
            self._seen.pop(message_id, None)


def webhook_secret_key(secret: str) -> bytes:
    """The HMAC key of a secret.

    A secret STACK issues is ``whsec_`` and base64: its key is the decoded bytes. A secret issued before
    this scheme (a hexadecimal string, or a value you chose) has no prefix and is read the same way when
    it is base64, and by its UTF-8 bytes when it is not, which is what every published Standard Webhooks
    library computes from that string.
    """
    if not isinstance(secret, str):
        raise ValueError("a webhook secret is a string")
    prefixed = secret.startswith(WEBHOOK_SECRET_PREFIX)
    text = secret[len(WEBHOOK_SECRET_PREFIX) :] if prefixed else secret
    if prefixed or _BASE64.match(text):
        try:
            key = base64.b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError) as error:
            raise ValueError("a webhook secret is whsec_ followed by base64") from error
    else:
        key = text.encode()
    if len(key) < _SECRET_MIN_BYTES:
        raise ValueError("a webhook secret (whsec_ followed by base64) holds at least 16 bytes")
    return key


def sign_webhook_body(secret: str, message_id: str, timestamp: str, body: bytes) -> bytes:
    """The raw HMAC-SHA256 over ``<id>.<timestamp>.<body>`` under a secret's key."""
    mac = hmac.new(webhook_secret_key(secret), digestmod=hashlib.sha256)
    mac.update(f"{message_id}.{timestamp}.".encode())
    mac.update(body)
    return mac.digest()


def header_value(headers: Mapping[str, Any], name: str) -> str | None:
    """A header by name, matched case-insensitively, from any mapping (a list value gives its first)."""
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            if isinstance(value, (list, tuple)):
                value = value[0] if value else None
            return value if isinstance(value, str) else None
    return None


def _secrets(secret: str | Sequence[str]) -> list[str]:
    secrets = [secret] if isinstance(secret, str) else list(secret)
    if not secrets:
        raise ValueError("at least one secret is needed")
    return secrets


def verify_webhook(
    headers: Mapping[str, Any],
    body: str | bytes | bytearray,
    secret: str | Sequence[str],
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
    replay_guard: ReplayGuard | None = None,
) -> dict[str, Any]:
    """Check a message from STACK and return its parsed JSON body (an object).

    ``headers`` is any mapping of header names to values (names are matched case-insensitively); ``body``
    is the raw request body, unparsed. ``secret`` is your secret, or a list of them while a rotation is
    live; any one matching signature is enough. ``now`` is unix seconds, the clock when omitted.
    Comparison is constant-time. The message id is ``header_value(headers, "webhook-id")``.

    Raises ``WebhookSignatureError`` when the message is not acceptable and ``ValueError`` when a secret
    is malformed (a setup error, not an attack).
    """
    secrets = _secrets(secret)
    for candidate_secret in secrets:
        webhook_secret_key(candidate_secret)

    message_id = header_value(headers, WEBHOOK_ID_HEADER)
    timestamp = header_value(headers, WEBHOOK_TIMESTAMP_HEADER)
    signatures = header_value(headers, WEBHOOK_SIGNATURE_HEADER)
    if not message_id or not timestamp or not signatures:
        raise WebhookSignatureError("missing_headers")
    if not _TIMESTAMP.match(timestamp):
        raise WebhookSignatureError("bad_timestamp")
    clock = time.time() if now is None else now
    if abs(clock - int(timestamp)) > tolerance_seconds:
        raise WebhookSignatureError("stale")

    raw = body.encode() if isinstance(body, str) else bytes(body)
    offered: list[bytes] = []
    for part in signatures.split(" "):
        part = part.strip()
        if part.startswith("v1,"):
            try:
                offered.append(base64.b64decode(part[3:] + "=" * (-len(part[3:]) % 4)))
            except (binascii.Error, ValueError):
                continue
    matched = False
    for candidate_secret in secrets:
        expected = sign_webhook_body(candidate_secret, message_id, timestamp, raw)
        for candidate in offered:
            # Every candidate is compared, so the time taken does not reveal which one matched.
            if hmac.compare_digest(candidate, expected):
                matched = True
    if not matched:
        raise WebhookSignatureError("bad_signature")

    try:
        parsed = json.loads(raw)
    except ValueError as error:
        raise WebhookSignatureError("bad_body") from error
    if not isinstance(parsed, dict):
        raise WebhookSignatureError("bad_body")
    # Last, so only a message that is genuine and fresh takes a place in the guard's memory.
    if replay_guard is not None and not replay_guard.first_seen(message_id, clock):
        raise WebhookSignatureError("replayed")
    return cast("dict[str, Any]", parsed)
