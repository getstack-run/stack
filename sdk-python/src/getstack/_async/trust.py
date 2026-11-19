"""Async TrustService mirror: whether the account's agents ask first or are trusted to act."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..trust import _approval, trust_body, trust_path


class AsyncTrustService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self, agent_id: str | None = None) -> dict[str, Any]:
        """See ``TrustService.get``."""
        return cast("dict[str, Any]", await self._client.get(trust_path(agent_id)))

    async def set(
        self, trust: str, agent_id: str | None = None, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """See ``TrustService.set``."""
        return cast(
            "dict[str, Any]",
            await self._client.put(
                trust_path(agent_id), json=trust_body(trust, agent_id), extra_headers=_approval(governance_approval_id)
            ),
        )

    async def clear(self, agent_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """See ``TrustService.clear``."""
        return cast(
            "dict[str, Any]",
            await self._client.put(
                trust_path(agent_id), json=trust_body(None, agent_id), extra_headers=_approval(governance_approval_id)
            ),
        )
