"""Async mirror of AuditService."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncAuditService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(
        self,
        limit: int = 20,
        since: int | None = None,
        agent_id: str | None = None,
        passport_jti: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {"limit": str(limit)}
        if since is not None:
            params["since"] = str(since)
        if agent_id is not None:
            params["agent_id"] = agent_id
        if passport_jti is not None:
            params["passport_jti"] = passport_jti
        return cast("dict[str, Any]", await self._client.get("/v1/audit", params=params))

    async def chain_head(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get("/v1/audit/chain-head"))

    async def verify_chain(
        self,
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if from_date is not None:
            params["from"] = from_date
        if to_date is not None:
            params["to"] = to_date
        if limit is not None:
            params["limit"] = str(limit)
        return cast("dict[str, Any]", await self._client.get("/v1/audit/verify-chain", params=params))
