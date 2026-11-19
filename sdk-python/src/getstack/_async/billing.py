"""Async BillingService mirror: the platform and controls subscriptions of agent accounts."""

from __future__ import annotations

from typing import Any, cast

from ..billing import _approval
from ..client import AsyncHttpClient


class AsyncBillingService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def _post(self, path: str, governance_approval_id: str | None) -> dict[str, Any]:
        # An empty JSON object, not no body: the API refuses a JSON request with an empty body.
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", path, json={}, extra_headers=_approval(governance_approval_id)),
        )

    async def subscriptions(self) -> dict[str, Any]:
        """The platform and controls state and this month's usage."""
        return cast("dict[str, Any]", await self._client.request("GET", "/v1/billing/subscriptions"))

    async def subscribe_platform(self, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Start the platform subscription: ``{checkout_url, session_id, trial}``. A governance action."""
        return await self._post("/v1/billing/platform/subscribe", governance_approval_id)

    async def subscribe_controls(self, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Switch on hosted controls: ``{checkout_url, session_id, trial}``. A governance action."""
        return await self._post("/v1/billing/controls/subscribe", governance_approval_id)
