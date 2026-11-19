"""Evidence packs — export, get, download, list."""

from __future__ import annotations

import json
from typing import Any, cast
from urllib.parse import quote

from ..client import AsyncHttpClient


class AsyncEvidencePacksService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def export(
        self,
        *,
        scope_kind: str,
        scope_ref: str,
        supersedes: str | None = None,
        air_gap: bool | None = None,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"scope": {"kind": scope_kind, "ref": scope_ref}}
        if supersedes is not None:
            body["supersedes"] = supersedes
        if air_gap is not None:
            body["air_gap"] = air_gap
        result = await self._client.request("POST", "/v1/evidence-packs", json=body)
        if output_path is not None and "manifest" in result:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result["manifest"], f, indent=2)
        return cast("dict[str, Any]", result)

    async def get(self, pack_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", await self._client.request("GET", f"/v1/evidence-packs/{quote(pack_id, safe='')}")
        )

    async def download(self, pack_id: str) -> bytes:
        """Fetch the exact stored final manifest bytes."""
        return await self._client.request_bytes("GET", f"/v1/evidence-packs/{quote(pack_id, safe='')}/download")

    async def list(self, *, scope: str | None = None) -> dict[str, Any]:
        path = "/v1/evidence-packs"
        if scope is not None:
            from urllib.parse import urlencode

            path = f"{path}?{urlencode({'scope': scope})}"
        return cast("dict[str, Any]", await self._client.request("GET", path))
