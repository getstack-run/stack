"""Notification destination request-shape and approval-header regression tests."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.delivery_methods import AsyncDeliveryMethodService
from getstack.delivery_methods import DeliveryMethodService


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any, dict[str, str] | None]] = []

    def post(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, bool]:
        self.calls.append(("POST", path, json, extra_headers))
        return {"ok": True}


class AsyncRecordingClient(RecordingClient):
    async def post(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, bool]:
        self.calls.append(("POST", path, json, extra_headers))
        return {"ok": True}


def test_add_uses_rest_channel_type_and_governance_header() -> None:
    client = RecordingClient()
    service = DeliveryMethodService(client)  # type: ignore[arg-type]

    service.add(
        "webhook",
        "https://hooks.example.test/stack",
        governance_approval_id="gvr_1",
    )

    assert client.calls == [
        (
            "POST",
            "/v1/notifications/destinations",
            {
                "channel_type": "webhook",
                "destination": "https://hooks.example.test/stack",
            },
            {"X-Governance-Approval": "gvr_1"},
        )
    ]


def test_async_add_uses_the_same_request_shape() -> None:
    client = AsyncRecordingClient()
    service = AsyncDeliveryMethodService(client)  # type: ignore[arg-type]

    asyncio.run(service.add("email", "ops@example.test"))

    assert client.calls == [
        (
            "POST",
            "/v1/notifications/destinations",
            {"channel_type": "email", "destination": "ops@example.test"},
            None,
        )
    ]
