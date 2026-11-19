"""Async mirror of ReviewService."""

from __future__ import annotations

from typing import Any

from ..client import AsyncHttpClient
from ..types import ReviewDecisionResult, ReviewQueue, ReviewQueueItem


class AsyncReviewService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self, status: str = "flagged", page: int = 1, limit: int = 20) -> ReviewQueue:
        data = await self._client.get(
            "/v1/passports/reviews",
            params={"status": status, "page": str(page), "limit": str(limit)},
        )
        items = [
            ReviewQueueItem(
                checkout_id=item["checkout_id"],
                passport_jti=item["passport_jti"],
                agent_id=item["agent_id"],
                agent_name=item["agent_name"],
                intent_summary=item["intent_summary"],
                review_status=item["review_status"],
                flags=item.get("flags", []),
                submitted_at=item["submitted_at"],
            )
            for item in data["items"]
        ]
        return ReviewQueue(items=items, total=data["total"])

    async def decide(
        self,
        checkout_id: str,
        decision: str,
        notes: str | None = None,
        block_future: bool = False,
        governance_approval_id: str | None = None,
    ) -> ReviewDecisionResult:
        body: dict[str, Any] = {"decision": decision}
        if notes:
            body["notes"] = notes
        if block_future:
            body["block_future"] = True
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        data = await self._client.post(
            f"/v1/passports/reviews/{checkout_id}/decide", json=body, extra_headers=_gov_headers
        )
        return ReviewDecisionResult(
            review_id=data["review_id"],
            agent_id=data["agent_id"],
            decision=data["decision"],
            passport_blocked=data["passport_blocked"],
        )
