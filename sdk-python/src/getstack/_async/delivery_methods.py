"""Notification delivery methods (async parity with the JS SDK's
DeliveryMethodService).
"""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncDeliveryMethodService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def add(
        self,
        kind: str,
        destination: str,
        governance_approval_id: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "channel_type": kind,
            "destination": destination,
            **fields,
        }
        headers = self._approval_headers(governance_approval_id)
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/notifications/destinations", json=body, extra_headers=headers),
        )

    async def list(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", await self._client.get("/v1/notifications/destinations"))

    async def delete(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.delete(
                f"/v1/notifications/destinations/{destination_id}",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    async def rotate_secret(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Rotate a webhook secret. The replacement is returned once in this response."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/notifications/destinations/{destination_id}/rotate-secret",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    async def send_verification_code(
        self, destination_id: str, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/notifications/destinations/{destination_id}/send-code",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    async def verify(
        self,
        destination_id: str,
        code: str,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/notifications/destinations/{destination_id}/verify",
                json={"code": code},
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    async def test(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/notifications/destinations/{destination_id}/test",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    @staticmethod
    def _approval_headers(governance_approval_id: str | None) -> dict[str, str] | None:
        if not governance_approval_id:
            return None
        return {"X-Governance-Approval": governance_approval_id}
