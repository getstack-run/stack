"""Helpers for your own decision server: verify what STACK sends, sign what you answer.

STACK signs every request to your decision and events addresses with Standard Webhooks
(https://www.standardwebhooks.com), and your answer to a decision request is signed the same way:

- ``webhook-id``: the message id. For a request, the decision or batch id; for your answer, the
  ``decision_id`` of the request it answers.
- ``webhook-timestamp``: unix seconds.
- ``webhook-signature``: space-separated ``v1,<base64>`` signatures, each an HMAC-SHA256 over
  ``<id>.<timestamp>.<body>`` keyed with the secret's bytes (the secret is ``whsec_<base64>``). During a
  rotation there are two, one per live secret, and any one of them is enough.

Sign and verify the exact body bytes: parse it only after ``verify_control_request`` has accepted it,
and send the body ``sign_control_answer`` returns without re-serialising it.

Example (Flask)::

    @app.post("/stack/decide")
    def decide():
        try:
            request_body = verify_control_request(request.headers, request.get_data(), SECRET)
        except ControlSignatureError:
            return "", 401
        verdict = "deny" if request_body["action"]["type"] == "card.checkout" else "allow"
        answer = sign_control_answer(
            request_body["decision_id"], request_body["request_digest"], verdict, SECRET,
            reason={"code": "card_checkout_needs_review"} if verdict == "deny" else None,
        )
        return Response(answer.body, headers=answer.headers, content_type="application/json")
"""

from __future__ import annotations

import base64
import json
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

from .webhook import (
    DEFAULT_TOLERANCE_SECONDS,
    WEBHOOK_ID_HEADER,
    WEBHOOK_SECRET_PREFIX,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_TIMESTAMP_HEADER,
    WebhookSignatureError,
    header_value,
    sign_webhook_body,
    verify_webhook,
    webhook_secret_key,
)

__all__ = [
    "DEFAULT_TOLERANCE_SECONDS",
    "WEBHOOK_ID_HEADER",
    "WEBHOOK_SECRET_PREFIX",
    "WEBHOOK_SIGNATURE_HEADER",
    "WEBHOOK_TIMESTAMP_HEADER",
    "ControlSignatureError",
    "SignedControlAnswer",
    "sign_control_answer",
    "verify_control_request",
]

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON_CODE = re.compile(r"^[a-z0-9_]{1,64}$")
_REASON_MESSAGE_MAX = 200
_REF_MAX = 200
_AFTER_SECONDS_MAX = 86_400
_POLICY_REF_MAX = 200


class ControlSignatureError(WebhookSignatureError):
    """A received message failed verification. ``reason`` says why; answer 401 and do nothing else.

    ``reason`` is one of ``missing_headers``, ``bad_timestamp``, ``stale``, ``bad_signature`` or
    ``bad_body`` (the signature is good but the body is not a JSON object).
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.args = (f"control message refused: {reason}",)


class SignedControlAnswer(NamedTuple):
    """What to return from the decision address: send ``body`` as it is, with ``headers``."""

    headers: dict[str, str]
    body: str


def _secret_key(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret.startswith(WEBHOOK_SECRET_PREFIX):
        raise ValueError("a webhook secret starts with whsec_")
    return webhook_secret_key(secret)


def _secrets(secret: str | Sequence[str]) -> list[str]:
    secrets = [secret] if isinstance(secret, str) else list(secret)
    if not secrets:
        raise ValueError("at least one secret is needed")
    for candidate in secrets:
        _secret_key(candidate)
    return secrets


def _signature(secret: str, message_id: str, timestamp: str, body: bytes) -> bytes:
    _secret_key(secret)
    return sign_webhook_body(secret, message_id, timestamp, body)


def _header(headers: Mapping[str, Any], name: str) -> str | None:
    return header_value(headers, name)


def verify_control_request(
    headers: Mapping[str, Any],
    body: str | bytes | bytearray,
    secret: str | Sequence[str],
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    """Check a message from STACK and return its parsed JSON body.

    Works for a decision request (``type`` ``stack.decision.request``) and an events batch
    (``stack.events.batch``) alike. ``headers`` is any mapping of header names to values (names are
    matched case-insensitively); ``body`` is the raw request body, unparsed. ``secret`` is your
    ``whsec_...`` secret, or a list of them while a rotation is live; any one matching signature is
    enough. ``now`` is unix seconds, the clock when omitted. Comparison is constant-time.

    Raises ``ControlSignatureError`` when the message is not acceptable and ``ValueError`` when a secret
    is malformed (a setup error, not an attack).
    """
    try:
        return verify_webhook(headers, body, _secrets(secret), tolerance_seconds, now)
    except WebhookSignatureError as error:
        raise ControlSignatureError(error.reason) from error


def sign_control_answer(
    decision_id: str,
    request_digest: str,
    verdict: str,
    secrets: str | Sequence[str],
    reason: Mapping[str, Any] | None = None,
    retry: Mapping[str, Any] | None = None,
    policy_ref: str | None = None,
    timestamp: int | None = None,
) -> SignedControlAnswer:
    """Build your answer to a decision request, signed: ``SignedControlAnswer(headers, body)``.

    ``decision_id`` and ``request_digest`` are echoed from the request; a missing or different one
    counts as no answer. ``verdict`` is ``"allow"`` or ``"deny"``. ``reason`` is
    ``{"code": "lower_snake_case", "message": "up to 200 characters"}``. ``retry`` marks a pending
    approval: ``{"ref": "...", "after_seconds": 30}``; the agent sends ``ref`` back as ``X-Control-Ref``
    on its retry. ``policy_ref`` names the rule that decided. ``secrets`` is the secret you verify with,
    or a list of two while a rotation is live (STACK accepts any one signature). ``timestamp`` is unix
    seconds, the clock when omitted.

    ``headers`` has ``webhook-id`` (the ``decision_id``), ``webhook-timestamp`` and ``webhook-signature``;
    ``body`` is compact JSON, and the signature covers exactly those bytes.
    """
    if not isinstance(decision_id, str) or not decision_id:
        raise ValueError("decision_id is required")
    if not isinstance(request_digest, str) or not _DIGEST.match(request_digest):
        raise ValueError("request_digest is the sha256:<64 hex> digest from the request")
    if verdict not in ("allow", "deny"):
        raise ValueError("verdict must be 'allow' or 'deny'")

    answer: dict[str, Any] = {"decision_id": decision_id, "request_digest": request_digest, "verdict": verdict}
    if reason is not None:
        answer["reason"] = _reason(reason)
    if retry is not None:
        answer["retry"] = _retry(retry)
    if policy_ref is not None:
        if not isinstance(policy_ref, str) or len(policy_ref) > _POLICY_REF_MAX:
            raise ValueError(f"policy_ref is a string of at most {_POLICY_REF_MAX} characters")
        answer["policy_ref"] = policy_ref

    body = json.dumps(answer, separators=(",", ":"))
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    signed = [
        f"v1,{base64.b64encode(_signature(secret, decision_id, stamp, body.encode())).decode()}"
        for secret in _secrets(secrets)
    ]
    return SignedControlAnswer(
        headers={
            WEBHOOK_ID_HEADER: decision_id,
            WEBHOOK_TIMESTAMP_HEADER: stamp,
            WEBHOOK_SIGNATURE_HEADER: " ".join(signed),
        },
        body=body,
    )


def _reason(reason: Mapping[str, Any]) -> dict[str, Any]:
    code = reason.get("code")
    if not isinstance(code, str) or not _REASON_CODE.match(code):
        raise ValueError("reason.code is 1 to 64 characters of a-z, 0-9 and underscore")
    out: dict[str, Any] = {"code": code}
    message = reason.get("message")
    if message is not None:
        if not isinstance(message, str) or len(message) > _REASON_MESSAGE_MAX:
            raise ValueError(f"reason.message is a string of at most {_REASON_MESSAGE_MAX} characters")
        out["message"] = message
    return out


def _retry(retry: Mapping[str, Any]) -> dict[str, Any]:
    ref = retry.get("ref")
    if not isinstance(ref, str) or not 1 <= len(ref) <= _REF_MAX:
        raise ValueError(f"retry.ref is a string of 1 to {_REF_MAX} characters")
    out: dict[str, Any] = {"ref": ref}
    after = retry.get("after_seconds")
    if after is not None:
        if isinstance(after, bool) or not isinstance(after, int) or not 0 <= after <= _AFTER_SECONDS_MAX:
            raise ValueError(f"retry.after_seconds is a whole number from 0 to {_AFTER_SECONDS_MAX}")
        out["after_seconds"] = after
    return out
