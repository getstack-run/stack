"""Async mirror of SecurityEventService."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncSecurityEventService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self, agent_id: str | None = None, page: int = 1, limit: int = 50) -> dict[str, Any]:
        params: dict[str, str] = {"page": str(page), "limit": str(limit)}
        if agent_id:
            params["agent_id"] = agent_id
        return cast("dict[str, Any]", await self._client.get("/v1/security-events", params=params))

    async def get(self, event_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/security-events/{event_id}"))

    async def resolve(self, event_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/security-events/{event_id}/resolve"))
