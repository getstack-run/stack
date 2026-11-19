"""Hosted inbound webhook surface.

Operator creates a webhook row + receives a STACK-hosted URL and distinct
incoming/downstream HMAC secrets. Generic providers sign with the incoming secret. AgentMail endpoints
require their provider signing secret through set_provider_signing_secret.
STACK runs the prompt-injection detector on inbound content
before forwarding to a downstream URL.
"""

from __future__ import annotations

from typing import Any, Literal, cast

from .client import HttpClient

Provider = Literal["agentmail", "generic"]
SignatureAlgorithm = Literal["hmac-sha256", "hmac-sha1"]


class InboundWebhookService:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(
        self,
        provider: Provider,
        agent_id: str,
        forward_url: str | None = None,
        generic_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a hosted inbound webhook.

        Returns a dict with keys: id, provider, slug, webhook_url,
        webhook_secret (downstream verification key, returned ONLY at create),
        incoming_signing_secret (generic only, returned ONLY at create), agent_id,
        forward_url, created_at. Capture both immediately. STACK never returns
        them through list/get. If lost, revoke + recreate.
        """
        body: dict[str, Any] = {"provider": provider, "agent_id": agent_id}
        if forward_url is not None:
            body["forward_url"] = forward_url
        if generic_config is not None:
            body["generic_config"] = generic_config
        return cast("dict[str, Any]", self._client.post("/v1/operator/inbound-webhooks", json=body))

    def list(self) -> list[dict[str, Any]]:
        """List all inbound webhooks for the operator (active + revoked)."""
        res = self._client.get("/v1/operator/inbound-webhooks")
        return list(res.get("webhooks", []))

    def rotate_secret(self, webhook_id: str) -> dict[str, Any]:
        """A fresh downstream signing secret, returned once, for an API key or a dashboard session. The
        one it replaces keeps signing the forwards beside it for 24 hours."""
        from urllib.parse import quote

        return cast(
            "dict[str, Any]",
            self._client.post(f"/v1/operator/inbound-webhooks/{quote(webhook_id, safe='')}/rotate-secret", json={}),
        )

    def set_provider_signing_secret(
        self, webhook_id: str, signing_secret: str, downstream_signing_secret: str | None = None
    ) -> dict[str, Any]:
        """Configure the incoming provider key. If a generic downstream key is omitted,
        STACK generates and returns its replacement once."""
        from urllib.parse import quote

        return cast(
            "dict[str, Any]",
            self._client.put(
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

    def get(self, webhook_id: str) -> dict[str, Any]:
        """Get a single inbound webhook by id. Never returns the plaintext secret."""
        return cast("dict[str, Any]", self._client.get(f"/v1/operator/inbound-webhooks/{webhook_id}"))

    def revoke(self, webhook_id: str) -> dict[str, Any]:
        """Soft-delete an inbound webhook. Idempotent on repeat calls."""
        return cast("dict[str, Any]", self._client.delete(f"/v1/operator/inbound-webhooks/{webhook_id}"))
