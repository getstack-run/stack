"""Sync and async contracts for atomic service-requirement replacement."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.identity import AsyncIdentityService
from getstack.identity import IdentityService
from getstack.types import SetServiceRequirementInput

REQUIREMENT: SetServiceRequirementInput = {
    "layer": "identity",
    "requires_claim": "verified_identity",
    "minimum_assurance": "substantial",
    "accepted_providers": ["stripe_identity"],
    "requires_pii": True,
    "lawful_basis": "contract",
}


class _SyncClient:
    def __init__(self) -> None:
        self.path: str | None = None
        self.json: Any = None
        self.headers: dict[str, str] | None = None

    def put(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        self.path = path
        self.json = json
        self.headers = extra_headers
        return {"requirements": [] if json["requirement"] is None else [json["requirement"]]}


class _AsyncClient:
    def __init__(self) -> None:
        self.path: str | None = None
        self.json: Any = None
        self.headers: dict[str, str] | None = None

    async def put(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        self.path = path
        self.json = json
        self.headers = extra_headers
        return {"requirements": [] if json["requirement"] is None else [json["requirement"]]}


def test_sync_replace_service_requirement_wraps_the_canonical_shape() -> None:
    client = _SyncClient()
    service = IdentityService(client)  # type: ignore[arg-type]

    result = service.replace_service_requirement("svc_agent/mail", REQUIREMENT)

    assert result == {"requirements": [REQUIREMENT]}
    assert client.path == "/v1/services/svc_agent%2Fmail/requirements"
    assert client.json == {"requirement": REQUIREMENT}


def test_async_replace_service_requirement_sends_null_for_removal() -> None:
    client = _AsyncClient()
    service = AsyncIdentityService(client)  # type: ignore[arg-type]

    result = asyncio.run(service.replace_service_requirement("svc_agentmail", None))

    assert result == {"requirements": []}
    assert client.path == "/v1/services/svc_agentmail/requirements"
    assert client.json == {"requirement": None}


def test_replace_service_requirement_carries_the_approval_a_person_gave() -> None:
    sync_client = _SyncClient()
    IdentityService(sync_client).replace_service_requirement(  # type: ignore[arg-type]
        "svc_agentmail", None, governance_approval_id="gvr_ok"
    )
    assert sync_client.headers == {"X-Governance-Approval": "gvr_ok"}
    async_client = _AsyncClient()
    asyncio.run(
        AsyncIdentityService(async_client).replace_service_requirement(  # type: ignore[arg-type]
            "svc_agentmail", None, governance_approval_id="gvr_ok"
        )
    )
    assert async_client.headers == {"X-Governance-Approval": "gvr_ok"}
