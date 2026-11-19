"""Async GovernanceService mirror: read one governance approval."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from ..client import AsyncHttpClient


class AsyncGovernanceService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get_approval(self, approval_id: str) -> dict[str, Any]:
        """One approval: ``{approval, payload_hash, approval_url}``; see ``GovernanceService.get_approval``."""
        path = f"/v1/governance/approvals/{quote(approval_id, safe='')}"
        return cast("dict[str, Any]", await self._client.get(path))

    async def list_approvals(self) -> dict[str, Any]:
        """The account's approvals as ``{approvals: [...]}``; see ``GovernanceService.list_approvals``."""
        return cast("dict[str, Any]", await self._client.get("/v1/governance/approvals"))
