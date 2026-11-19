"""Async UsageService mirror.

The action meter includes allowance_coverage and allowance_plan.
An old unknown month never borrows the current plan.
"""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncUsageService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        return cast("dict[str, Any]", await self._client.get("/v1/usage", params=params or None))
