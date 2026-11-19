"""Async parity with the JS SDK's PiiConfigService.

Docstrings live on the sync mirror in ``getstack/pii_config.py``.
"""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncPiiConfigService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get("/v1/pii/config"))

    async def update(self, **config: Any) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.put("/v1/pii/config", json=config))

    async def reset(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete("/v1/pii/config"))
