"""Async mirror of DropoffService."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..dropoffs import _passport_header


class AsyncDropoffService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create(
        self,
        from_agent_id: str,
        to_agent_id: str | list[str],
        schema: dict[str, Any],
        ttl_seconds: int | None = None,
        on_expire: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Create a drop-off. An agent caller passes the producer's Mission Passport as passport_token.

        ``to_agent_id`` is the one agent it is for, or a list of 1 to 10 of the customer's agents (not the
        depositor): each can see it and is woken when it is deposited, and the first to collect it takes it. The
        others get a ``DROPOFF_ALREADY_COLLECTED`` error that names who did.
        """
        body: dict[str, Any] = {
            "from_agent": from_agent_id,
            **({"to_agents": to_agent_id} if isinstance(to_agent_id, list) else {"to_agent": to_agent_id}),
            "schema": schema,
        }
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        if on_expire:
            body["on_expire"] = on_expire
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/dropoffs", json=body, extra_headers=_passport_header(passport_token)),
        )

    async def deposit(
        self,
        dropoff_id: str,
        data: dict[str, Any],
        agent_id: str,
        passport_jti: str | None = None,
        mission_id: str | None = None,
        passport_token: str | None = None,
        drive_files: list[str] | None = None,
    ) -> dict[str, Any]:
        """Deposit as the producer. An agent caller passes its Mission Passport as passport_token (or passport_jti).

        ``drive_files`` are drive file ids (1 to 10) the drop-off hands over: they open to the collector when it
        collects, and the depositor must be able to read each.
        """
        body: dict[str, Any] = {"agent_id": agent_id, "payload": data}
        if passport_jti is not None:
            body["passport_jti"] = passport_jti
        if mission_id is not None:
            body["mission_id"] = mission_id
        if drive_files is not None:
            body["drive_files"] = drive_files
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/dropoffs/{dropoff_id}/deposit",
                json=body,
                extra_headers=_passport_header(passport_token),
            ),
        )

    async def collect(self, dropoff_id: str, agent_id: str, passport_token: str | None = None) -> dict[str, Any]:
        """Collect as the consumer. An agent caller passes its Mission Passport as passport_token."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/dropoffs/{dropoff_id}/collect",
                json={"agent_id": agent_id},
                extra_headers=_passport_header(passport_token),
            ),
        )

    async def expire(self, dropoff_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/dropoffs/{dropoff_id}/expire"))

    async def get(self, dropoff_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/dropoffs/{dropoff_id}"))

    async def list(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", await self._client.get("/v1/dropoffs"))
