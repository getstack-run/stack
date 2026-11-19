"""Async mirror of ScanService."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncScanService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def scan(
        self,
        content: str | dict[str, Any],
        *,
        context: str | None = None,
        source: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"content": content}
        if context is not None:
            payload["context"] = context
        if source is not None:
            payload["source"] = source

        extra_headers = None
        if passport_token:
            extra_headers = {"X-Passport-Token": passport_token}

        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                "/v1/scan",
                json=payload,
                extra_headers=extra_headers,
            ),
        )

    async def usage(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", "/v1/scan/usage"))
