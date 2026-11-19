"""PassportSession helper (sync).

Wraps a passport token + expiry; auto-refreshes via /v1/passports/refresh
when within `grace_seconds` of expiry. Lets operators write LLM-call
loops without manual passport bookkeeping. Refresh never extends a
passport past its Mission: once the Mission is completed, revoked or
expired, `get_token` raises `MissionEndedError`; open a new Mission.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from .client import HttpClient
from .errors import StackError, mission_ended_error


class PassportSession:
    def __init__(
        self,
        client: HttpClient,
        issued: dict[str, Any],
        issue_input: dict[str, Any],
    ):
        self._client = client
        self._current_token: str = issued["token"]
        self._exp_seconds: int = _decode_jwt_exp(self._current_token)
        self._issue_input = issue_input

    def get_token(self, grace_seconds: int = 60) -> str:
        """Return the current token; auto-refresh if within grace."""
        now_sec = int(time.time())
        if self._exp_seconds - now_sec > grace_seconds:
            return self._current_token
        # Refresh — errors propagate (caller would have failed anyway with an
        # expired token; surfacing here is the clearer signal). A refusal
        # because the Mission ended becomes MissionEndedError.
        try:
            refreshed = self._client.post(
                "/v1/passports/refresh",
                json={
                    "token": self._current_token,
                    "ttl_seconds": self._issue_input.get("ttl_seconds"),
                },
            )
        except StackError as exc:
            ended = mission_ended_error(exc)
            if ended is not None:
                raise ended from exc
            raise
        self._current_token = refreshed["token"]
        self._exp_seconds = _decode_jwt_exp(self._current_token)
        return self._current_token

    @property
    def token(self) -> str:
        """Current token (no refresh trigger)."""
        return self._current_token

    @property
    def expires_at_seconds(self) -> int:
        """Unix seconds since epoch."""
        return self._exp_seconds


def _decode_jwt_exp(token: str) -> int:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("PassportSession: token is not a JWT (expected 3 dot-separated segments)")
    payload_b64 = parts[1]
    # base64url → padding
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    payload = json.loads(decoded)
    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise ValueError("PassportSession: token payload missing numeric `exp` claim")
    return exp
