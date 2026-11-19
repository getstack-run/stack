"""Async FlaggedContentService mirror: what the customer's controls do with flagged content."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..flagged_content import flagged_content_body


class AsyncFlaggedContentService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self) -> dict[str, Any]:
        """The setting in force: ``{warning, critical, controls}``; see ``FlaggedContentService.get``."""
        return cast("dict[str, Any]", await self._client.get("/v1/flagged-content/settings"))

    async def set(self, *, warning: str | None = None, critical: str | None = None) -> dict[str, Any]:
        """Change one severity or both; see ``FlaggedContentService.set``."""
        return cast(
            "dict[str, Any]",
            await self._client.put("/v1/flagged-content/settings", json=flagged_content_body(warning, critical)),
        )
