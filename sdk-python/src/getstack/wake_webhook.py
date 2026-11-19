"""The receiving end of a wake: what your agent's endpoint does with a request from STACK.

A wake is delivered as a Standard Webhooks signed POST (https://www.standardwebhooks.com):
``webhook-id`` (the wake's id, the same on every retry, so you can ignore one you have seen),
``webhook-timestamp`` and ``webhook-signature``, an HMAC-SHA256 over ``<id>.<timestamp>.<body>`` keyed
with your ``whsec_<base64>`` secret. It is the same signing the control socket uses, so any published
Standard Webhooks library verifies it too.

``task`` is the owner's own text, and ``event`` carries facts, never what a stranger wrote: read a message,
with the detectors' verdict, from the account's messages. ``account_id`` is ``None`` for an agent with no
account. Verify the raw body exactly as received.

For the source ``incoming_call`` the ``event`` carries ``call_id`` and ``answer_by`` (when the ring runs out
and the call goes to voicemail) and ``sender_tags`` holds STACK's checks of the number calling, which the agent
reads from the call. For the source ``decision`` the ``event`` names a pending item the agent waited on and how
it ended: ``item_kind``, ``item_id`` and ``result``.

Example (Flask)::

    @app.post("/stack/wake")
    def wake():
        try:
            wake = verify_wake_webhook(request.headers, request.get_data(), SECRET)
        except WakeSignatureError:
            return "", 401
        queue.put(wake["wake_id"], wake["task"], wake["event"])
        return "", 204
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .control_server import DEFAULT_TOLERANCE_SECONDS, ControlSignatureError, _header, verify_control_request


class WakeSignatureError(ControlSignatureError):
    """A received wake failed verification. ``reason`` says why; answer 401 and do nothing else.

    ``reason`` is one of ``missing_headers``, ``bad_timestamp``, ``stale``, ``bad_signature``, ``bad_body``
    (the signature is good but the body is not a wake) or ``id_mismatch`` (it is signed as another wake).
    """


def verify_wake_webhook(
    headers: Mapping[str, Any],
    body: str | bytes | bytearray,
    secret: str | Sequence[str],
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    """Check a wake from STACK and return its parsed body (``type`` ``stack.wake``).

    ``secret`` is your ``whsec_...`` secret, or a list of them while a rotation is live. Raises
    ``WakeSignatureError`` when the message is not acceptable and ``ValueError`` when a secret is
    malformed (a setup error, not an attack).
    """
    try:
        parsed = verify_control_request(headers, body, secret, tolerance_seconds, now)
    except ControlSignatureError as error:
        raise WakeSignatureError(error.reason) from error
    wake_id = parsed.get("wake_id")
    if parsed.get("type") != "stack.wake" or parsed.get("version") != "2" or not isinstance(wake_id, str):
        raise WakeSignatureError("bad_body")
    if not isinstance(parsed.get("task"), str) or not isinstance(parsed.get("source"), str):
        raise WakeSignatureError("bad_body")
    # STACK signs a wake with its own id as the message id.
    if wake_id != _header(headers, "webhook-id"):
        raise WakeSignatureError("id_mismatch")
    return parsed
