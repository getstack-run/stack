"""Async brain: the awaitable mirror of ``getstack.brain``."""

from __future__ import annotations

import builtins
from typing import Any, cast

from ..brain import _passport, list_params, selection_body
from ..client import AsyncHttpClient


class AsyncBrainService:
    """The drive files a customer chose to make searchable. See ``BrainService``."""

    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def add(
        self,
        *,
        file_id: str | None = None,
        file_ids: builtins.list[str] | None = None,
        name_prefix: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Make drive files searchable. One metered action. One row per file with its status and cost estimate."""
        body = selection_body(file_id, file_ids, name_prefix)
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/brain/files", json=body, extra_headers=_passport(passport_token)),
        )

    async def remove(
        self,
        *,
        file_id: str | None = None,
        file_ids: builtins.list[str] | None = None,
        name_prefix: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Take files out of the brain; they stay in the drive, only no longer searchable. Free."""
        body = selection_body(file_id, file_ids, name_prefix)
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/brain/remove", json=body, extra_headers=_passport(passport_token)),
        )

    async def search(self, query: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Ask the brain a question and get the passages that answer it, each untrusted content. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/brain/search", json={"query": query}, extra_headers=_passport(passport_token)),
        )

    async def list(
        self,
        *,
        status: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The files in the brain the caller may see, each with its state, and the month's usage. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.get(
                "/v1/brain/files",
                params=list_params(status, cursor, limit),
                extra_headers=_passport(passport_token),
            ),
        )
