"""Evidence packs — export, get, download, list.

Portable cryptographic bundles. Verifiable offline by any third party
via the open-source `@getstackrun/verify` package.

  export()  Export a pack for a mission / session / incident / period
            scope. Returns the pack_id + the full canonical manifest
            JSON inline. Persist the manifest to disk and hand it to
            an auditor / insurer / regulator.
  get()     Fetch one pack by id. Returns the signed claim envelope
            bytes alongside the parsed pack_claim.
  download() Fetch the exact stored final manifest bytes.
  list()    List packs for the calling operator. Filter by scope.

Signed records are a controls feature: every call raises ControlsRequiredError
(402 CONTROLS_REQUIRED) without controls, and a self-managed install also
needs its licence to export (LICENCE_REQUIRED).

"""

from __future__ import annotations

import json
from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


class EvidencePacksService:
    def __init__(self, client: HttpClient):
        self._client = client

    def export(
        self,
        *,
        scope_kind: str,
        scope_ref: str,
        supersedes: str | None = None,
        air_gap: bool | None = None,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Export an evidence pack.

        `scope_kind` is one of `mission` | `session` | `incident` | `period`.
        `scope_ref` is the matching reference (ms_* / ses_* / period:YYYY-Qn /
        incident:<id>). The pack manifest is returned inline; pass
        `output_path` to also write it to disk in one step.

        Returns a dict with `pack_id`, `claim_id`, `pack_claim`, `manifest`.
        """
        body: dict[str, Any] = {
            "scope": {"kind": scope_kind, "ref": scope_ref},
        }
        if supersedes is not None:
            body["supersedes"] = supersedes
        if air_gap is not None:
            body["air_gap"] = air_gap
        result = self._client.request("POST", "/v1/evidence-packs", json=body)
        if output_path is not None and "manifest" in result:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result["manifest"], f, indent=2)
        return cast("dict[str, Any]", result)

    def get(self, pack_id: str) -> dict[str, Any]:
        """Fetch one pack by id. Returns the signed envelope_cose bytes and
        the parsed `pack_claim` for convenient introspection."""
        return cast("dict[str, Any]", self._client.request("GET", f"/v1/evidence-packs/{quote(pack_id, safe='')}"))

    def download(self, pack_id: str) -> bytes:
        """Fetch the exact stored final manifest bytes."""
        return self._client.request_bytes("GET", f"/v1/evidence-packs/{quote(pack_id, safe='')}/download")

    def list(self, *, scope: str | None = None) -> dict[str, Any]:
        """List packs for the calling operator.

        `scope` filter is `<kind>:<ref>` (e.g. `mission:ms_abc`,
        `period:2026-Q1`). Omit to list every pack. Newest first.
        """
        path = "/v1/evidence-packs"
        if scope is not None:
            from urllib.parse import urlencode

            path = f"{path}?{urlencode({'scope': scope})}"
        return cast("dict[str, Any]", self._client.request("GET", path))
