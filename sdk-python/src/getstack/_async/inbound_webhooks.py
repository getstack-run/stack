"""Async mirror of InboundWebhookService."""

from __future__ import annotations

from typing import Any, Literal, cast

from ..client import AsyncHttpClient

Provider = Literal["agentmail", "generic"]


class AsyncInboundWebhookService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create(
        self,
        provider: Provider,
        agent_id: str,
        forward_url: str | None = None,
        generic_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"provider": provider, "agent_id": agent_id}
        if forward_url is not None:
            body["forward_url"] = forward_url
        if generic_config is not None:
            body["generic_config"] = generic_config
        return cast("dict[str, Any]", await self._client.post("/v1/operator/inbound-webhooks", json=body))

    async def list(self) -> list[dict[str, Any]]:
        res = await self._client.get("/v1/operator/inbound-webhooks")
        return list(res.get("webhooks", []))

    async def rotate_secret(self, webhook_id: str) -> dict[str, Any]:
        """A fresh downstream signing secret, returned once; the old one keeps signing for 24 hours."""
        from urllib.parse import quote

        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/operator/inbound-webhooks/{quote(webhook_id, safe='')}/rotate-secret", json={}
            ),
        )

    async def set_provider_signing_secret(
        self, webhook_id: str, signing_secret: str, downstream_signing_secret: str | None = None
    ) -> dict[str, Any]:
        """Configure the incoming provider key. If a generic downstream key is omitted,
        STACK generates and returns its replacement once."""
        from urllib.parse import quote

        return cast(
            "dict[str, Any]",
            await self._client.put(
                f"/v1/operator/inbound-webhooks/{quote(webhook_id, safe='')}/provider-signing-secret",
                json={
                    "signing_secret": signing_secret,
                    **(
                        {"downstream_signing_secret": downstream_signing_secret}
                        if downstream_signing_secret is not None
                        else {}
                    ),
                },
            ),
        )

    async def get(self, webhook_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/operator/inbound-webhooks/{webhook_id}"))

    async def revoke(self, webhook_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete(f"/v1/operator/inbound-webhooks/{webhook_id}"))
