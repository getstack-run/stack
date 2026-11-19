"""Notification delivery methods (parity with the JS SDK's
DeliveryMethodService — the newer /v1/notifications/destinations surface).
"""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


class DeliveryMethodService:
    def __init__(self, client: HttpClient):
        self._client = client

    def add(
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
            "dict[str, Any]", self._client.post("/v1/notifications/destinations", json=body, extra_headers=headers)
        )

    def list(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/notifications/destinations"))

    def delete(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.delete(
                f"/v1/notifications/destinations/{destination_id}",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    def rotate_secret(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Rotate a webhook secret. The replacement is returned once in this response."""
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/notifications/destinations/{destination_id}/rotate-secret",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    def send_verification_code(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/notifications/destinations/{destination_id}/send-code",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    def verify(
        self,
        destination_id: str,
        code: str,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/notifications/destinations/{destination_id}/verify",
                json={"code": code},
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    def test(self, destination_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/notifications/destinations/{destination_id}/test",
                extra_headers=self._approval_headers(governance_approval_id),
            ),
        )

    @staticmethod
    def _approval_headers(governance_approval_id: str | None) -> dict[str, str] | None:
        if not governance_approval_id:
            return None
        return {"X-Governance-Approval": governance_approval_id}
