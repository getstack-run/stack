"""async PassportSession mirror."""

from __future__ import annotations

import time
from typing import Any

from ..client import AsyncHttpClient
from ..errors import StackError, mission_ended_error
from ..passport_session import _decode_jwt_exp


class AsyncPassportSession:
    def __init__(
        self,
        client: AsyncHttpClient,
        issued: dict[str, Any],
        issue_input: dict[str, Any],
    ):
        self._client = client
        self._current_token: str = issued["token"]
        self._exp_seconds: int = _decode_jwt_exp(self._current_token)
        self._issue_input = issue_input

    async def get_token(self, grace_seconds: int = 60) -> str:
        now_sec = int(time.time())
        if self._exp_seconds - now_sec > grace_seconds:
            return self._current_token
        try:
            refreshed = await self._client.post(
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
        return self._current_token

    @property
    def expires_at_seconds(self) -> int:
        return self._exp_seconds
