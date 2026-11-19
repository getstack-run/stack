"""Security event management."""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


class SecurityEventService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(self, agent_id: str | None = None, page: int = 1, limit: int = 50) -> dict[str, Any]:
        """List unresolved security events."""
        params: dict[str, str] = {"page": str(page), "limit": str(limit)}
        if agent_id:
            params["agent_id"] = agent_id
        return cast("dict[str, Any]", self._client.get("/v1/security-events", params=params))

    def get(self, event_id: str) -> dict[str, Any]:
        """Get a specific security event."""
        return cast("dict[str, Any]", self._client.get(f"/v1/security-events/{event_id}"))

    def resolve(self, event_id: str) -> dict[str, Any]:
        """Mark a security event as resolved."""
        return cast("dict[str, Any]", self._client.post(f"/v1/security-events/{event_id}/resolve"))
