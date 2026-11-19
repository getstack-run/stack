"""Async mirror of NotificationService."""

from __future__ import annotations

import builtins
from typing import Any, cast

from ..client import AsyncHttpClient
from ..notifications import _to_channel
from ..types import NotificationChannel


class AsyncNotificationService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self) -> list[NotificationChannel]:
        data = await self._client.get("/v1/notifications/channels")
        return [_to_channel(ch) for ch in data]

    async def create(
        self,
        channel_type: str,
        destination: str,
        events: builtins.list[str] | None = None,
        min_severity: str = "warning",
    ) -> NotificationChannel:
        body: dict[str, Any] = {
            "channel_type": channel_type,
            "destination": destination,
            "min_severity": min_severity,
        }
        if events:
            body["events"] = events
        return _to_channel(await self._client.post("/v1/notifications/channels", json=body))

    async def send_verification_code(self, channel_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/notifications/channels/{channel_id}/send-code"))

    async def verify(self, channel_id: str, code: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/notifications/channels/{channel_id}/verify",
                json={"code": code},
            ),
        )

    async def test(self, channel_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/notifications/channels/{channel_id}/test"))

    async def update(self, channel_id: str, **fields: Any) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.patch(f"/v1/notifications/channels/{channel_id}", json=fields))

    async def delete(self, channel_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete(f"/v1/notifications/channels/{channel_id}"))
