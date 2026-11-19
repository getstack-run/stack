"""Async mirror of WakesService: wake-ups."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..wake import _agent, _object, _passport, _query, _rules_path, _seg, _settings_path


class AsyncWakesService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(
        self,
        agent_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The agent's wakes, newest first; ``status="open"`` is the agent's queue, oldest first."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET",
                f"{_agent(agent_id)}/wakes",
                params=_query(status=status, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    async def get(self, agent_id: str, wake_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET", f"{_agent(agent_id)}/wakes/{_seg(wake_id)}", extra_headers=_passport(passport_token)
            ),
        )

    async def acknowledge(self, agent_id: str, wake_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The agent has picked the wake up. Only a delivered wake of its own; saying it twice is fine."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_agent(agent_id)}/wakes/{_seg(wake_id)}/acknowledge",
                json={},
                extra_headers=_passport(passport_token),
            ),
        )

    async def get_settings(self, agent_id: str | None = None) -> dict[str, Any]:
        """One agent's settings and what is in force; without an agent, the customer's default."""
        return cast("dict[str, Any]", await self._client.request("GET", _settings_path(agent_id)))

    async def set_settings(self, settings: dict[str, Any], agent_id: str | None = None) -> dict[str, Any]:
        """Change settings, for one agent or (without an agent) the customer's default."""
        return cast(
            "dict[str, Any]",
            await self._client.request("PUT", _settings_path(agent_id), json=_object(settings, "settings")),
        )

    async def rotate_webhook_secret(self, agent_id: str) -> dict[str, Any]:
        """A new webhook signing secret, shown once; the old one keeps verifying for 24 hours."""
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"{_agent(agent_id)}/wake/webhook/rotate-secret", json={}),
        )

    async def test_webhook(self, agent_id: str) -> dict[str, Any]:
        """Send a signed test to the agent's webhook: ``{"delivered": bool, "code": str | None}``."""
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"{_agent(agent_id)}/wake/webhook/test", json={}),
        )

    async def list_rules(self, agent_id: str | None = None) -> dict[str, Any]:
        """One agent's own rules; without an agent, the customer's default rules."""
        return cast("dict[str, Any]", await self._client.request("GET", _rules_path(agent_id)))

    async def create_rule(self, rule: dict[str, Any], agent_id: str | None = None) -> dict[str, Any]:
        """Add a rule: ``name``, ``source`` and optionally ``task``, ``filters`` and ``enabled``."""
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", _rules_path(agent_id), json=_object(rule, "rule")),
        )

    async def update_rule(self, rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("PUT", f"/v1/wake/rules/{_seg(rule_id)}", json=_object(rule, "rule")),
        )

    async def delete_rule(self, rule_id: str) -> None:
        await self._client.request("DELETE", f"/v1/wake/rules/{_seg(rule_id)}")

    async def list_schedules(self, agent_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", f"{_agent(agent_id)}/wake/schedules"))

    async def create_schedule(self, agent_id: str, schedule: dict[str, Any]) -> dict[str, Any]:
        """``name``, ``cron`` (five fields, no more often than every 5 minutes), ``task``, optional ``time_zone``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"{_agent(agent_id)}/wake/schedules", json=_object(schedule, "schedule")
            ),
        )

    async def update_schedule(self, agent_id: str, schedule_id: str, schedule: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                f"{_agent(agent_id)}/wake/schedules/{_seg(schedule_id)}",
                json=_object(schedule, "schedule"),
            ),
        )

    async def delete_schedule(self, agent_id: str, schedule_id: str) -> None:
        await self._client.request("DELETE", f"{_agent(agent_id)}/wake/schedules/{_seg(schedule_id)}")
