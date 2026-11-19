"""Per-operator PII redaction config for the LLM gateway."""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


class PiiConfigService:
    """Two dials over the gateway's scored PII scanner.

    ``threshold``
        Confidence needed before redacting, 0 to 1. HIGHER redacts LESS.
        The built-in default is 0.4.
    ``countries``
        Which countries' identifier schemes to run, as ISO 3166-1 alpha-2
        codes. ``None`` means every country: safe, and noisy. Email, card,
        IBAN and IP addresses are country-neutral and always scan.

    Use them together. Scoping to the countries you actually operate in is
    what makes a lower threshold safe -- bare-format personal numbers start
    redacting without taking every order number with them.

    Every change applies at once and asks no one, loosening included
    (redaction off, a higher threshold, a narrower country list).
    """

    def __init__(self, client: HttpClient):
        self._client = client

    def get(self) -> dict[str, Any]:
        """Read the config in force.

        Never 404s: an operator who has configured nothing gets the built-in
        defaults with ``configured: False``.
        """
        return cast("dict[str, Any]", self._client.get("/v1/pii/config"))

    def update(self, **config: Any) -> dict[str, Any]:
        """Partial update of ``enabled`` / ``threshold`` / ``countries``.

        Omit a field to leave it untouched; pass ``None`` for ``threshold`` or
        ``countries`` to clear it back to the built-in default.
        """
        return cast("dict[str, Any]", self._client.put("/v1/pii/config", json=config))

    def reset(self) -> dict[str, Any]:
        """Drop the row and fall back to built-in defaults. Applies at once."""
        return cast("dict[str, Any]", self._client.delete("/v1/pii/config"))
