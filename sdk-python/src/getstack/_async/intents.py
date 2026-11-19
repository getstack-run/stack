"""Async mirror of IntentsService. asyncio.sleep for the poll loop."""

from __future__ import annotations

import asyncio
from typing import Any, cast

from ..client import AsyncHttpClient


class AsyncIntentsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def simulate(
        self,
        intent: dict[str, Any],
        passport_token: str,
        *,
        intent_claim_ref: str | None = None,
        persist: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"intent": intent}
        if intent_claim_ref is not None:
            body["intent_claim_ref"] = intent_claim_ref
        if persist is not None:
            body["persist"] = persist
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                "/v1/intents/simulate",
                json=body,
                extra_headers={"X-Passport-Token": passport_token},
            ),
        )

    async def submit(
        self,
        intent: dict[str, Any],
        passport_token: str,
        *,
        expires_in_seconds: int | None = None,
        skip_simulation: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"intent": intent}
        if expires_in_seconds is not None:
            body["expires_in_seconds"] = expires_in_seconds
        if skip_simulation:
            body["skip_simulation"] = True
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                "/v1/intents/submit",
                json=body,
                extra_headers={"X-Passport-Token": passport_token},
            ),
        )

    async def submit_and_wait(
        self,
        intent: dict[str, Any],
        passport_token: str,
        *,
        expires_in_seconds: int | None = None,
        skip_simulation: bool = False,
        timeout_seconds: float = 60.0,
        poll_interval_seconds: float = 1.0,
    ) -> dict[str, Any]:
        """Async submit + poll. Uses asyncio.sleep instead of time.sleep
        so the event loop stays free during the wait."""
        initial = await self.submit(
            intent,
            passport_token,
            expires_in_seconds=expires_in_seconds,
            skip_simulation=skip_simulation,
        )
        approval_id = initial["approval_id"]
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout_seconds
        last_row: dict[str, Any] | None = None
        while loop.time() < deadline:
            row = await self.get(approval_id)
            last_row = row
            if row.get("status") != "pending":
                return {"initial": initial, "final": row, "timed_out": False}
            await asyncio.sleep(poll_interval_seconds)
        return {
            "initial": initial,
            "final": last_row or {"id": approval_id, "status": "pending"},
            "timed_out": True,
        }

    async def get(self, approval_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", f"/v1/intents/{approval_id}"))

    async def list_pending(self, *, page: int | None = None, limit: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit
        return cast("dict[str, Any]", await self._client.request("GET", "/v1/intents/pending", params=params or None))

    async def approve(
        self,
        approval_id: str,
        *,
        notes: str | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = notes
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/intents/{approval_id}/approve",
                json=body,
                extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
            ),
        )

    async def reject(
        self,
        approval_id: str,
        *,
        notes: str | None = None,
        block_future: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = notes
        if block_future:
            body["block_future"] = True
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/intents/{approval_id}/reject",
                json=body,
            ),
        )
