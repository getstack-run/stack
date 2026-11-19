"""The agent's calendar: its own events, the invites sent to its address, the agenda and the private feed.

An event is stored once, with its time zone and repeat rule (RFC 5545 RRULE, EXDATE, RDATE); the occurrences of a
repeating event are worked out when you read the agenda. The account's own agent (passing its Passport as
``passport_token``, sent as ``X-Passport-Token``) and the owner or an admin use these calls.

Times are written the way people write them: ``2026-11-03`` is a date (an all-day event), ``2026-11-03T10:00`` is a
local time in ``time_zone`` (a floating time with none), and a time with ``Z`` or an offset is an instant.

Making, changing and cancelling an event, and answering an invite, are one action each; reading the agenda, the list
and the feed is free. What goes to guests is an email like any other: put to your decider as ``email.send`` for exactly
the people it reaches, read by the data-flow rule, counted against the shared domain's daily recipients and charged as
an email. A change is stored whether or not its mail could go: ``notices`` says which left.

Example::

    change = stack.calendar.create_event(
        account_id,
        {"title": "Review", "start": "2026-11-10T10:00", "time_zone": "Europe/Stockholm",
         "guests": ["olivia@example.com"], "meeting": True, "attend": True},
        passport_token=passport,
    )
    agenda = stack.calendar.agenda(account_id, "2026-11-01", "2026-11-30")
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

INVITE_RESPONSES = ("accept", "tentative", "decline")
CHANGE_SCOPES = ("series", "occurrence", "following")


def _seg(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("an id is required")
    return quote(value, safe="")


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _base(account_id: str) -> str:
    return f"/v1/accounts/{_seg(account_id)}/calendar"


def _query(**values: Any) -> dict[str, Any] | None:
    present = {key: value for key, value in values.items() if value is not None}
    return present or None


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be a dict")
    return value


def _scope(body: dict[str, Any]) -> dict[str, Any]:
    scope = body.get("scope")
    if scope is not None and scope not in CHANGE_SCOPES:
        raise ValueError(f"scope must be one of {', '.join(CHANGE_SCOPES)}")
    return body


def _respond_body(response: str, notify_organizer: bool | None) -> dict[str, Any]:
    if response not in INVITE_RESPONSES:
        raise ValueError(f"response must be one of {', '.join(INVITE_RESPONSES)}")
    body: dict[str, Any] = {"response": response}
    if notify_organizer is not None:
        body["notify_organizer"] = notify_organizer
    return body


class CalendarService:
    """An account agent's calendar. Each method returns the API's JSON as a dict."""

    def __init__(self, client: HttpClient):
        self._client = client

    def list_events(
        self,
        account_id: str,
        *,
        role: str | None = None,
        response: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The events and invites on the calendar, soonest first: ``{"events": [...], "next_cursor"}``.

        ``role`` is ``organizer`` (the agent's own) or ``attendee`` (an invite sent to it). A repeating event is
        listed once; read its occurrences with :meth:`agenda`.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET",
                f"{_base(account_id)}/events",
                params=_query(role=role, response=response, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    def get_event(self, account_id: str, event_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET", f"{_base(account_id)}/events/{_seg(event_id)}", extra_headers=_passport(passport_token)
            ),
        )

    def agenda(
        self,
        account_id: str,
        from_: str,
        to: str,
        *,
        time_zone: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Occurrences between two times with repeats expanded, changes and cancellations applied, in ``time_zone``."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET",
                f"{_base(account_id)}/agenda",
                params=_query(**{"from": from_}, to=to, time_zone=time_zone, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    def create_event(
        self, account_id: str, event: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Make an event: ``{"event", "following", "notices"}``. One action; each guest is mailed the invite.

        ``title`` and ``start`` are required; ``end``, ``time_zone``, ``repeat`` (``rule``, ``except``, ``also``),
        ``location``, ``meeting_link``, ``description``, ``guests``, ``wake_minutes_before``, ``meeting`` (a room of
        STACK's), ``attend`` (STACK's meeting worker joins it as the agent; the customer's controls are asked once,
        and a refusal makes the event without ``attend``), ``max_seconds`` and ``meeting_voice`` (``{"voice",
        "language"}`` of the agent in this event's meetings, replacing the account's) are optional.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/events",
                json=_object(event, "event"),
                extra_headers=_passport(passport_token),
            ),
        )

    def update_event(
        self, account_id: str, event_id: str, change: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Change an event, one occurrence (``occurrence``), or that and the following (``scope="following"``).

        ``meeting_voice`` sets the voice and language of the agent in the event's meetings; ``None`` clears it."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PATCH",
                f"{_base(account_id)}/events/{_seg(event_id)}",
                json=_scope(_object(change, "change")),
                extra_headers=_passport(passport_token),
            ),
        )

    def cancel_event(
        self,
        account_id: str,
        event_id: str,
        *,
        occurrence: str | None = None,
        scope: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Cancel an event, one occurrence, or that and the following. One action; guests are mailed it."""
        body = _scope({k: v for k, v in {"occurrence": occurrence, "scope": scope}.items() if v is not None})
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/events/{_seg(event_id)}/cancel",
                json=body,
                extra_headers=_passport(passport_token),
            ),
        )

    def respond(
        self,
        account_id: str,
        event_id: str,
        response: str,
        *,
        notify_organizer: bool | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Accept, decline or mark an invite tentative: ``{"event", "reply"}``.

        One action. It mails the organizer an iCalendar reply from the account's own address (put to your decider
        as ``email.send``), only when the organizer is who sent the invite; ``notify_organizer=False`` records the
        answer without telling anyone. An accepted invite still to come wakes the agent before each occurrence,
        less ``invite_lead_minutes``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/events/{_seg(event_id)}/respond",
                json=_respond_body(response, notify_organizer),
                extra_headers=_passport(passport_token),
            ),
        )

    def decline_proposal(
        self,
        account_id: str,
        event_id: str,
        counter_id: str,
        *,
        comment: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Turn down a guest's proposed other time. To accept one, update the event with ``counter_id``."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/events/{_seg(event_id)}/counters/{_seg(counter_id)}/decline",
                json={} if comment is None else {"comment": comment},
                extra_headers=_passport(passport_token),
            ),
        )

    def feed(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Whether the account has a private read-only iCalendar feed; the URL is shown only when it is made."""
        return cast(
            "dict[str, Any]",
            self._client.request("GET", f"{_base(account_id)}/feed", extra_headers=_passport(passport_token)),
        )

    def rotate_feed(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Make the feed, or give it a new URL (the old one stops at once). The URL is returned once.

        Whoever holds the URL sees every event and the guests' addresses until it is rotated or ended.
        """
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"{_base(account_id)}/feed", json={}, extra_headers=_passport(passport_token)),
        )

    def revoke_feed(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """End the feed: its URL stops working at once."""
        return cast(
            "dict[str, Any]",
            self._client.request("DELETE", f"{_base(account_id)}/feed", extra_headers=_passport(passport_token)),
        )
