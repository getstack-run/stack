"""Content-scanning service — `/v1/scan` (L1+L2 prompt-injection detector).

Scan retrieved content (emails, documents, web pages, API responses)
for prompt-injection markers BEFORE feeding it into your LLM. Reuses
the same detector chain that runs on `/v1/proxy` and
`/v1/skills/:id/invoke` — L1 regex catalog + L2 encoding-aware
normalization.

Example::

    result = stack.scan.scan(
        content=email_body,
        context="email",
        source=sender_address,
    )
    if result["verdict"] == "critical":
        raise RuntimeError(f"Indirect injection caught: {result['match']['pattern_id']}")
"""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


class ScanService:
    def __init__(self, client: HttpClient):
        self._client = client

    def scan(
        self,
        content: str | dict[str, Any],
        *,
        context: str | None = None,
        source: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Scan retrieved content for prompt-injection markers.

        Args:
            content: The content to scan. Strings are scanned directly;
                dicts are walked one level deep, same as proxy bodies.
            context: Optional context tag — one of "email", "document",
                "webpage", "chat_log", "api_response", "calendar", "other".
            source: Optional source identifier (URL / sender / filename).
            passport_token: Optional passport JWT for attribution to a
                specific agent context.

        Returns:
            Dict with keys: verdict ("clean" | "suspicious" | "critical"),
            scan_id, duration_ms, match (or None).
        """
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
            self._client.request(
                "POST",
                "/v1/scan",
                json=payload,
                extra_headers=extra_headers,
            ),
        )

    def usage(self) -> dict[str, Any]:
        """Get monthly scan usage stats.

        Returns:
            Dict with keys: plan (platform, internal, contract or none: the plan the account is on), limit,
            used, remaining, period, and pooled=True on the accounts of a
            partner on a negotiated hard cap, whose counts are the partner's shared pool.
        """
        return cast("dict[str, Any]", self._client.request("GET", "/v1/scan/usage"))
