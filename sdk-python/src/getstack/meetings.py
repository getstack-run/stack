"""Meetings: the agent in the room of one of its own calendar events, with STACK as plumbing.

STACK runs no model and says nothing of its own in a meeting. The agent hears each participant by the name they gave,
speaks, writes in the room's chat and leaves. Make an event with ``meeting: True`` (``stack.calendar.create_event``) to
get a room whose link goes in the invite; ``join`` puts the agent in it (one action; events made with ``attend: True``
are joined for the agent at their start and wake it). Any agent of the customer (passing its Passport as
``passport_token``, sent as ``X-Passport-Token``) and the owner use these calls.

What the meeting uses (Daily's participant-minutes, Soniox's speech-to-text for each participant and Soniox's speech) is
charged at cost, ten minutes at a time. What a participant says, writes or is called is a stranger's text.

Example::

    turn = stack.meetings.join(account_id, {"event_id": event_id}, passport_token=passport)
    turn = stack.meetings.say(account_id, turn["meeting"]["id"], text="Hello.", passport_token=passport)
    for event in turn["events"]:
        ...
"""

from __future__ import annotations

import builtins
import json as _json
from collections.abc import Iterator
from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


def _seg(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("an id is required")
    return quote(value, safe="")


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _base(account_id: str) -> str:
    return f"/v1/accounts/{_seg(account_id)}/meetings"


def _query(**values: Any) -> dict[str, Any] | None:
    present = {key: value for key, value in values.items() if value is not None}
    return present or None


def _join_body(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict) or not isinstance(event.get("event_id"), str):
        raise ValueError("join needs a dict with an event_id")
    return event


def _say_body(text: str | None, wait_seconds: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if text is not None:
        body["text"] = text
    if wait_seconds is not None:
        body["wait_seconds"] = wait_seconds
    return body


def stream_target(
    base_url: str, auth_headers: dict[str, str], account_id: str, meeting_id: str, passport_token: str | None
) -> tuple[str, dict[str, str]]:
    """Where a meeting's live stream is, and the headers it is opened with: the client's credential and the Passport."""
    url = f"{base_url.replace('http', 'ws', 1)}{_base(account_id)}/{_seg(meeting_id)}/live"
    headers = dict(auth_headers)
    if passport_token:
        headers["X-Passport-Token"] = passport_token
    return url, headers


def stream_message(kind: str, **fields: Any) -> str:
    """One message the agent sends on a meeting's live stream."""
    return _json.dumps({"type": kind, **fields})


class MeetingsService:
    """An account's meetings. Each method returns the API's JSON as a dict."""

    def __init__(self, client: HttpClient):
        self._client = client

    def join(self, account_id: str, event: dict[str, Any], *, passport_token: str | None = None) -> dict[str, Any]:
        """Join the room of a calendar event as the agent. ``event``: ``event_id``, and optionally ``max_seconds``
        (1 or more) and ``wait_seconds`` (0 to 60). One metered action. Returns ``{"meeting", "events"}`` once the
        agent is in the room. The first ten minutes are held on the account's credit."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST", _base(account_id), json=_join_body(event), extra_headers=_passport(passport_token)
            ),
        )

    def say(
        self,
        account_id: str,
        meeting_id: str,
        *,
        text: str | None = None,
        wait_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Speak ``text`` (as written; leave it out to only wait), then wait for what a participant says or writes next.
        Returns every event since your last action on the meeting. Not metered."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/{_seg(meeting_id)}/say",
                json=_say_body(text, wait_seconds),
                extra_headers=_passport(passport_token),
            ),
        )

    def chat(self, account_id: str, meeting_id: str, text: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Write a line in the room's chat. Not metered."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/{_seg(meeting_id)}/chat",
                json={"text": text},
                extra_headers=_passport(passport_token),
            ),
        )

    def leave(self, account_id: str, meeting_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Leave the meeting: the agent's part ends at once, the transcript is stored as a message and the account's
        agent is woken."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/{_seg(meeting_id)}/leave",
                json={},
                extra_headers=_passport(passport_token),
            ),
        )

    def list(
        self,
        account_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The account's meetings, newest first: ``{"meetings": [...], "next_cursor"}``."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET",
                _base(account_id),
                params=_query(status=status, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    def get_voice(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The account's meeting voice: ``{"voice", "language"}``, each ``None`` when not set (Soniox's default voice,
        English speech, speech recognition that finds the language itself). The owner, an admin or the account's own
        agent. Free."""
        return cast(
            "dict[str, Any]",
            self._client.request("GET", f"{_base(account_id)}/voice", extra_headers=_passport(passport_token)),
        )

    def set_voice(self, account_id: str, voice: dict[str, Any], *, passport_token: str | None = None) -> dict[str, Any]:
        """Set the voice and language the agent speaks in during meetings and listens for: ``voice`` (any voice Soniox
        takes) and ``language`` (a language code such as ``fr``). A field left out is cleared. STACK keeps no list of
        either and does not check them: Soniox's refusal is what comes back. An event can set its own
        (``meeting_voice`` on ``stack.calendar.create_event``). Not metered, no approval."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT", f"{_base(account_id)}/voice", json=voice, extra_headers=_passport(passport_token)
            ),
        )

    def get(self, account_id: str, meeting_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One meeting and its transcript so far: ``{"meeting", "lines"}``."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET", f"{_base(account_id)}/{_seg(meeting_id)}", extra_headers=_passport(passport_token)
            ),
        )

    def live(self, account_id: str, meeting_id: str, *, passport_token: str | None = None) -> MeetingStream:
        """The live stream of a meeting (a WebSocket): iterate it for every event as it happens, until the meeting
        ends, and send your words with ``text(token, last)`` as they come. Needs the ``websockets`` package
        (``pip install "getstack[live]"``)."""
        try:
            from websockets.sync.client import connect
        except ImportError as error:  # pragma: no cover - depends on the environment
            raise ImportError('The live stream needs the websockets package: pip install "getstack[live]"') from error
        url, headers = stream_target(
            self._client.base_url, self._client.auth.get_headers(), account_id, meeting_id, passport_token
        )
        return MeetingStream(connect(url, additional_headers=headers))


class MeetingStream:
    """A meeting's live stream: iterate it for the meeting's events, oldest first, until it ends. Messages the stream
    could not use are kept in ``errors``."""

    def __init__(self, socket: Any):
        self._socket = socket
        self.errors: builtins.list[dict[str, Any]] = []

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for raw in self._socket:
            message = _json.loads(raw)
            if message.get("type") == "error":
                self.errors.append(message)
                continue
            yield message

    def text(self, token: str, last: bool = False) -> None:
        """Words to speak, streamed as they come; ``last`` on the final token of what the agent says."""
        self._socket.send(stream_message("text", token=token, last=last))

    def chat(self, text: str) -> None:
        self._socket.send(stream_message("chat", text=text))

    def leave(self) -> None:
        self._socket.send(stream_message("leave"))

    def close(self) -> None:
        self._socket.close()
