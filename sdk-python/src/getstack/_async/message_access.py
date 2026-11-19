"""Async MessageAccessService mirror: what the account's agents may do with the customer's messages."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..message_access import message_access_body, message_access_path


class AsyncMessageAccessService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self, agent_id: str | None = None) -> dict[str, Any]:
        """See ``MessageAccessService.get``."""
        return cast("dict[str, Any]", await self._client.get(message_access_path(agent_id)))

    async def set(
        self,
        agent_id: str | None = None,
        *,
        read_teammates: bool | None = None,
        messages_read_only: bool | None = None,
    ) -> dict[str, Any]:
        """See ``MessageAccessService.set``."""
        values: dict[str, bool | None] = {}
        if read_teammates is not None:
            values["read_teammates"] = read_teammates
        if messages_read_only is not None:
            values["messages_read_only"] = messages_read_only
        return cast(
            "dict[str, Any]", await self._client.put(message_access_path(agent_id), json=message_access_body(values))
        )

    async def clear(self, agent_id: str, keys: list[str] | tuple[str, ...]) -> dict[str, Any]:
        """See ``MessageAccessService.clear``."""
        body = message_access_body(dict.fromkeys(keys))
        return cast("dict[str, Any]", await self._client.put(message_access_path(agent_id), json=body))
