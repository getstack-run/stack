"""Notification channel management."""

from __future__ import annotations

import builtins
from typing import Any, cast

from .client import HttpClient
from .types import NotificationChannel


def _to_channel(data: dict[str, Any]) -> NotificationChannel:
    return NotificationChannel(
        id=data["id"],
        channel_type=data["channel_type"],
        destination=data["destination"],
        events=data.get("events", []),
        min_severity=data.get("min_severity", "warning"),
        active=data.get("active", True),
        verified=data.get("verified", False),
    )


class NotificationService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(self) -> list[NotificationChannel]:
        data = self._client.get("/v1/notifications/channels")
        return [_to_channel(ch) for ch in data]

    def create(
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
        return _to_channel(self._client.post("/v1/notifications/channels", json=body))

    def send_verification_code(self, channel_id: str) -> dict[str, Any]:
        """Send a verification code to the channel."""
        return cast("dict[str, Any]", self._client.post(f"/v1/notifications/channels/{channel_id}/send-code"))

    def verify(self, channel_id: str, code: str) -> dict[str, Any]:
        """Submit a verification code."""
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/notifications/channels/{channel_id}/verify",
                json={"code": code},
            ),
        )

    def test(self, channel_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.post(f"/v1/notifications/channels/{channel_id}/test"))

    def update(self, channel_id: str, **fields: Any) -> dict[str, Any]:
        """Update a notification channel's events / min_severity / etc."""
        return cast("dict[str, Any]", self._client.patch(f"/v1/notifications/channels/{channel_id}", json=fields))

    def delete(self, channel_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.delete(f"/v1/notifications/channels/{channel_id}"))
