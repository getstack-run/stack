"""Per-operator detector customization (async parity with the JS SDK's
DetectorConfigService).
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from ..client import AsyncHttpClient


class AsyncDetectorConfigService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get("/v1/detectors/config"))

    async def get(self, detector_key: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/detectors/{quote(detector_key)}/config"))

    async def upsert(
        self, detector_key: str, governance_approval_id: str | None = None, **config: Any
    ) -> dict[str, Any]:
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]",
            await self._client.put(
                f"/v1/detectors/{quote(detector_key)}/config", json=config, extra_headers=_gov_headers
            ),
        )

    async def reset(self, detector_key: str, governance_approval_id: str | None = None) -> None:
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        await self._client.delete(f"/v1/detectors/{quote(detector_key)}/config", extra_headers=_gov_headers)
