"""Per-operator detector customization (parity with the JS SDK's
DetectorConfigService — L7 of the prompt-injection defense stack).

Reads are open (404 = the detector is on built-in defaults). Writes
(upsert/reset) are a controls feature: they apply at once with no approval,
and without controls they raise a StackError with code CONTROLS_REQUIRED
(402). A self-managed install has every controls feature.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


class DetectorConfigService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(self) -> dict[str, Any]:
        """List every detector config row this operator has set. Empty =
        every detector on built-in defaults."""
        return cast("dict[str, Any]", self._client.get("/v1/detectors/config"))

    def get(self, detector_key: str) -> dict[str, Any]:
        """Get one detector's config. 404 when no row exists (running on
        built-in defaults)."""
        return cast("dict[str, Any]", self._client.get(f"/v1/detectors/{quote(detector_key)}/config"))

    def upsert(self, detector_key: str, governance_approval_id: str | None = None, **config: Any) -> dict[str, Any]:
        """Upsert this operator's customization for the named detector.

        Accepts custom_patterns / whitelist_patterns / severity_overrides / enabled. Needs controls
        (CONTROLS_REQUIRED otherwise). ``governance_approval_id`` is no longer needed (a change asks no
        approval); it is still accepted so existing calls keep working."""
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]",
            self._client.put(f"/v1/detectors/{quote(detector_key)}/config", json=config, extra_headers=_gov_headers),
        )

    def reset(self, detector_key: str, governance_approval_id: str | None = None) -> None:
        """Reset a detector to built-in defaults (deletes the row).

        Needs controls (CONTROLS_REQUIRED otherwise). ``governance_approval_id`` is no longer needed (a
        reset asks no approval); it is still accepted so existing calls keep working."""
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        self._client.delete(f"/v1/detectors/{quote(detector_key)}/config", extra_headers=_gov_headers)
