"""Async mirror of CalendarService: the agent's calendar (events, invites, the agenda and the private feed)."""

from __future__ import annotations

from typing import Any, cast

from ..calendar import _base, _object, _passport, _query, _respond_body, _scope, _seg
from ..client import AsyncHttpClient


class AsyncCalendarService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list_events(
        self,
        account_id: str,
        *,
        role: str | None = None,
        response: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The events and invites on the calendar, soonest first: ``{"events": [...], "next_cursor"}``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET",
                f"{_base(account_id)}/events",
                params=_query(role=role, response=response, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    async def get_event(self, account_id: str, event_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET", f"{_base(account_id)}/events/{_seg(event_id)}", extra_headers=_passport(passport_token)
            ),
        )

    async def agenda(
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
            await self._client.request(
                "GET",
                f"{_base(account_id)}/agenda",
                params=_query(**{"from": from_}, to=to, time_zone=time_zone, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    async def create_event(
        self, account_id: str, event: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Make an event: ``{"event", "following", "notices"}``. One action; see the sync service."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/events",
                json=_object(event, "event"),
                extra_headers=_passport(passport_token),
            ),
        )

    async def update_event(
        self, account_id: str, event_id: str, change: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PATCH",
                f"{_base(account_id)}/events/{_seg(event_id)}",
                json=_scope(_object(change, "change")),
                extra_headers=_passport(passport_token),
            ),
        )

    async def cancel_event(
        self,
        account_id: str,
        event_id: str,
        *,
        occurrence: str | None = None,
        scope: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        body = _scope({k: v for k, v in {"occurrence": occurrence, "scope": scope}.items() if v is not None})
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/events/{_seg(event_id)}/cancel",
                json=body,
                extra_headers=_passport(passport_token),
            ),
        )

    async def respond(
        self,
        account_id: str,
        event_id: str,
        response: str,
        *,
        notify_organizer: bool | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Accept, decline or mark an invite tentative: ``{"event", "reply"}``. One action; see the sync service."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/events/{_seg(event_id)}/respond",
                json=_respond_body(response, notify_organizer),
                extra_headers=_passport(passport_token),
            ),
        )

    async def decline_proposal(
        self,
        account_id: str,
        event_id: str,
        counter_id: str,
        *,
        comment: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/events/{_seg(event_id)}/counters/{_seg(counter_id)}/decline",
                json={} if comment is None else {"comment": comment},
                extra_headers=_passport(passport_token),
            ),
        )

    async def feed(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("GET", f"{_base(account_id)}/feed", extra_headers=_passport(passport_token)),
        )

    async def rotate_feed(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"{_base(account_id)}/feed", json={}, extra_headers=_passport(passport_token)
            ),
        )

    async def revoke_feed(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("DELETE", f"{_base(account_id)}/feed", extra_headers=_passport(passport_token)),
        )
