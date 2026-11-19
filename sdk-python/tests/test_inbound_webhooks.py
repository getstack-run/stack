"""Inbound webhook directional-key wire contract."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.inbound_webhooks import AsyncInboundWebhookService
from getstack.inbound_webhooks import InboundWebhookService


class CaptureClient:
    def __init__(self) -> None:
        self.path: str | None = None
        self.body: dict | None = None

    def put(self, path: str, json: dict | None = None):
        self.path = path
        self.body = json
        return {"configured": True, "webhook_secret": "synthetic-generated-downstream"}


class AsyncCaptureClient(CaptureClient):
    async def put(self, path: str, json: dict | None = None):
        return super().put(path, json=json)


def test_sync_signing_setup_keeps_directional_keys_in_the_body() -> None:
    client = CaptureClient()
    result = InboundWebhookService(client).set_provider_signing_secret(  # type: ignore[arg-type]
        "iwh fixture", "synthetic-incoming", "synthetic-downstream"
    )
    assert client.path == "/v1/operator/inbound-webhooks/iwh%20fixture/provider-signing-secret"
    assert client.body == {
        "signing_secret": "synthetic-incoming",
        "downstream_signing_secret": "synthetic-downstream",
    }
    assert result == {"configured": True, "webhook_secret": "synthetic-generated-downstream"}


def test_async_signing_setup_matches_sync() -> None:
    client = AsyncCaptureClient()
    result = asyncio.run(
        AsyncInboundWebhookService(client).set_provider_signing_secret(  # type: ignore[arg-type]
            "iwh fixture", "synthetic-incoming"
        )
    )
    assert client.path == "/v1/operator/inbound-webhooks/iwh%20fixture/provider-signing-secret"
    assert client.body == {"signing_secret": "synthetic-incoming"}
    assert result == {"configured": True, "webhook_secret": "synthetic-generated-downstream"}
