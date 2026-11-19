"""Async mirror of SkillService."""

from __future__ import annotations

import asyncio
from typing import Any, cast

from .._authority_request import authority_request_headers
from ..client import AsyncHttpClient
from ..skills import _to_invocation, _to_request, _to_skill
from ..types import Skill, SkillInvocation, SkillRequest


class AsyncSkillService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    # ── Publishing ──────────────────────────────────────────────────

    async def publish(self, **kwargs: Any) -> Skill:
        return _to_skill(await self._client.post("/v1/skills", json=kwargs))

    async def get(self, skill_id: str) -> Skill:
        return _to_skill(await self._client.get(f"/v1/skills/{skill_id}"))

    async def browse(
        self,
        *,
        query: str | None = None,
        tags: str | None = None,
        trust_level: str | None = None,
        status: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Skill]:
        params: dict[str, str] = {}
        if query:
            params["query"] = query
        if tags:
            params["tags"] = tags
        if trust_level:
            params["trust_level"] = trust_level
        if status:
            params["status"] = status
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        data = await self._client.get("/v1/skills", params=params)
        return [_to_skill(s) for s in data]

    async def list_owned(self) -> list[Skill]:
        data = await self._client.get("/v1/skills/mine")
        return [_to_skill(s) for s in data]

    async def update(self, skill_id: str, **kwargs: Any) -> Skill:
        return _to_skill(await self._client.patch(f"/v1/skills/{skill_id}", json=kwargs))

    async def suspend(self, skill_id: str) -> Skill:
        return _to_skill(await self._client.post(f"/v1/skills/{skill_id}/suspend"))

    async def activate(self, skill_id: str) -> Skill:
        return _to_skill(await self._client.post(f"/v1/skills/{skill_id}/activate"))

    async def check_trust(self, skill_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/skills/{skill_id}/check-trust", json={}))

    # ── Invocations ─────────────────────────────────────────────────

    async def invoke(
        self,
        skill_id: str,
        *,
        agent_id: str | None = None,
        input: dict[str, Any],
        passport_id: str | None = None,
        approval_id: str | None = None,
        authority_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> SkillInvocation:
        body: dict[str, Any] = {"input": input}
        if agent_id:
            body["agent_id"] = agent_id
        if passport_id:
            body["passport_id"] = passport_id
        extra_headers: dict[str, str] = {}
        if approval_id:
            extra_headers["X-Intent-Approval-Id"] = approval_id
        extra_headers.update(authority_request_headers(authority_request_id))
        if idempotency_key:
            extra_headers["Idempotency-Key"] = idempotency_key
        return _to_invocation(
            await self._client.request(
                "POST",
                f"/v1/skills/{skill_id}/invoke",
                json=body,
                extra_headers=extra_headers if extra_headers else None,
            )
        )

    async def get_invocation(self, invocation_id: str) -> SkillInvocation:
        return _to_invocation(await self._client.get(f"/v1/skills/invocations/{invocation_id}"))

    async def list_invocations(self) -> list[SkillInvocation]:
        data = await self._client.get("/v1/skills/invocations/mine")
        return [_to_invocation(i) for i in data]

    async def list_pending_invocations(self, skill_id: str | None = None) -> list[SkillInvocation]:
        params = {"skill_id": skill_id} if skill_id else {}
        data = await self._client.get("/v1/skills/invocations/pending", params=params)
        return [_to_invocation(i) for i in data]

    async def claim_invocation(self, invocation_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/skills/invocations/{invocation_id}/claim"))

    async def complete_invocation(self, invocation_id: str, output: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/skills/invocations/{invocation_id}/complete",
                json={"output": output},
            ),
        )

    async def fail_invocation(
        self,
        invocation_id: str,
        *,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/skills/invocations/{invocation_id}/fail",
                json={"error": {"code": code, "message": message}},
            ),
        )

    async def poll(
        self,
        invocation_id: str,
        *,
        interval_seconds: float = 1.0,
        timeout_seconds: float = 60.0,
    ) -> SkillInvocation:
        """Async poll using asyncio.sleep."""
        loop = asyncio.get_event_loop()
        start = loop.time()
        while loop.time() - start < timeout_seconds:
            result = await self.get_invocation(invocation_id)
            if result.status in ("completed", "failed", "expired"):
                return result
            await asyncio.sleep(interval_seconds)
        raise TimeoutError(f"Invocation {invocation_id} timed out after {timeout_seconds}s")

    # ── Requests ────────────────────────────────────────────────────

    async def post_request(self, **kwargs: Any) -> SkillRequest:
        return _to_request(await self._client.post("/v1/skill-requests", json=kwargs))

    async def list_requests(
        self,
        *,
        status: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[SkillRequest]:
        params: dict[str, str] = {}
        if status:
            params["status"] = status
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        data = await self._client.get("/v1/skill-requests", params=params)
        return [_to_request(r) for r in data]

    async def get_request(self, request_id: str) -> SkillRequest:
        return _to_request(await self._client.get(f"/v1/skill-requests/{request_id}"))

    async def get_request_matches(self, request_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/skill-requests/{request_id}/matches"))

    async def suggest_composition(self, request_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/skill-requests/{request_id}/suggest"))
