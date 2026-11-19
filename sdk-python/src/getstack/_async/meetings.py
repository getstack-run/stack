"""Async mirror of MeetingsService: the agent in the room of one of its own calendar events."""

from __future__ import annotations

import builtins
import json as _json
from collections.abc import AsyncIterator
from typing import Any, cast

from ..client import AsyncHttpClient
from ..meetings import _base, _join_body, _passport, _query, _say_body, _seg, stream_message, stream_target


class AsyncMeetingsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def join(
        self, account_id: str, event: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Join the room of a calendar event as the agent; see ``MeetingsService.join``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", _base(account_id), json=_join_body(event), extra_headers=_passport(passport_token)
            ),
        )

    async def say(
        self,
        account_id: str,
        meeting_id: str,
        *,
        text: str | None = None,
        wait_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Speak and wait for what a participant says or writes next. Not metered."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/{_seg(meeting_id)}/say",
                json=_say_body(text, wait_seconds),
                extra_headers=_passport(passport_token),
            ),
        )

    async def chat(
        self, account_id: str, meeting_id: str, text: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Write a line in the room's chat. Not metered."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/{_seg(meeting_id)}/chat",
                json={"text": text},
                extra_headers=_passport(passport_token),
            ),
        )

    async def leave(self, account_id: str, meeting_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Leave the meeting."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/{_seg(meeting_id)}/leave",
                json={},
                extra_headers=_passport(passport_token),
            ),
        )

    async def list(
        self,
        account_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The account's meetings, newest first."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET",
                _base(account_id),
                params=_query(status=status, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    async def get_voice(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The account's meeting voice: ``{"voice", "language"}``, each ``None`` when not set."""
        return cast(
            "dict[str, Any]",
            await self._client.request("GET", f"{_base(account_id)}/voice", extra_headers=_passport(passport_token)),
        )

    async def set_voice(
        self, account_id: str, voice: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Set the voice and language of the agent in meetings; a field left out is cleared. Not metered."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT", f"{_base(account_id)}/voice", json=voice, extra_headers=_passport(passport_token)
            ),
        )

    async def get(self, account_id: str, meeting_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One meeting and its transcript so far."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET", f"{_base(account_id)}/{_seg(meeting_id)}", extra_headers=_passport(passport_token)
            ),
        )

    async def live(self, account_id: str, meeting_id: str, *, passport_token: str | None = None) -> AsyncMeetingStream:
        """The live stream of a meeting; see ``MeetingsService.live``. Needs the ``websockets`` package."""
        try:
            from websockets.asyncio.client import connect
        except ImportError as error:  # pragma: no cover - depends on the environment
            raise ImportError('The live stream needs the websockets package: pip install "getstack[live]"') from error
        url, headers = stream_target(
            self._client.base_url, self._client.auth.get_headers(), account_id, meeting_id, passport_token
        )
        return AsyncMeetingStream(await connect(url, additional_headers=headers))


class AsyncMeetingStream:
    """A meeting's live stream, async: ``async for`` it for the meeting's events until it ends."""

    def __init__(self, socket: Any):
        self._socket = socket
        self.errors: builtins.list[dict[str, Any]] = []

    def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return self._events()

    async def _events(self) -> AsyncIterator[dict[str, Any]]:
        async for raw in self._socket:
            message = _json.loads(raw)
            if message.get("type") == "error":
                self.errors.append(message)
                continue
            yield message

    async def text(self, token: str, last: bool = False) -> None:
        await self._socket.send(stream_message("text", token=token, last=last))

    async def chat(self, text: str) -> None:
        await self._socket.send(stream_message("chat", text=text))

    async def leave(self) -> None:
        await self._socket.send(stream_message("leave"))

    async def close(self) -> None:
        await self._socket.close()
