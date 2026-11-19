"""Drop-off management."""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


def _passport_header(passport_token: str | None) -> dict[str, str] | None:
    """Drop-off create, deposit and collect read the Mission Passport from X-Passport-Token."""
    return {"X-Passport-Token": passport_token} if passport_token else None


class DropoffService:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(
        self,
        from_agent_id: str,
        to_agent_id: str | list[str],
        schema: dict[str, Any],
        ttl_seconds: int | None = None,
        on_expire: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Create a drop-off. An agent caller passes the producer's Mission Passport as passport_token.

        ``to_agent_id`` is the one agent it is for, or a list of the customer's agents (not the
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
            self._client.post("/v1/dropoffs", json=body, extra_headers=_passport_header(passport_token)),
        )

    def deposit(
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

        ``drive_files`` are drive file ids the drop-off hands over: they open to the collector when it
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
            self._client.post(
                f"/v1/dropoffs/{dropoff_id}/deposit",
                json=body,
                extra_headers=_passport_header(passport_token),
            ),
        )

    def collect(self, dropoff_id: str, agent_id: str, passport_token: str | None = None) -> dict[str, Any]:
        """Collect as the consumer. An agent caller passes its Mission Passport as passport_token.

        ``{"payload": ..., "drive_files": [...]}``: ``drive_files`` is present only when the depositor handed
        files over; they are now readable by the collector, and their content is untrusted.
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/dropoffs/{dropoff_id}/collect",
                json={"agent_id": agent_id},
                extra_headers=_passport_header(passport_token),
            ),
        )

    def expire(self, dropoff_id: str) -> dict[str, Any]:
        """Force-expire a drop-off before its TTL."""
        return cast("dict[str, Any]", self._client.post(f"/v1/dropoffs/{dropoff_id}/expire"))

    def get(self, dropoff_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/dropoffs/{dropoff_id}"))

    def list(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/dropoffs"))
