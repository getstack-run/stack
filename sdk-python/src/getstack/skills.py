"""Skills marketplace — publish, invoke, browse, and manage skills."""

from __future__ import annotations

import time
from typing import Any, cast

from ._authority_request import authority_request_headers
from .client import HttpClient
from .types import Skill, SkillInvocation, SkillRequest


def _to_skill(data: dict[str, Any]) -> Skill:
    return Skill(
        id=data["id"],
        operator_id=data["operator_id"],
        name=data["name"],
        description=data["description"],
        version=data.get("version", "1.0.0"),
        tags=data.get("tags", []),
        trust_level_required=data.get("trust_level_required", "L0"),
        status=data.get("status", "active"),
        execution_mode=data.get("execution_mode", "open"),
        price_per_invocation=data.get("price_per_invocation", 0),
        invocation_count=data.get("invocation_count", 0),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


def _to_invocation(data: dict[str, Any]) -> SkillInvocation:
    return SkillInvocation(
        id=data["id"],
        skill_id=data["skill_id"],
        status=data["status"],
        output=data.get("output"),
        error=data.get("error"),
        expires_at=data.get("expires_at", ""),
        created_at=data.get("created_at", ""),
        started_at=data.get("started_at"),
        completed_at=data.get("completed_at"),
        llm_tokens_input=data.get("llm_tokens_input"),
        llm_tokens_output=data.get("llm_tokens_output"),
        execution_duration_ms=data.get("execution_duration_ms"),
    )


def _to_request(data: dict[str, Any]) -> SkillRequest:
    return SkillRequest(
        id=data["id"],
        operator_id=data["operator_id"],
        description=data["description"],
        desired_input_schema=data.get("desired_input_schema"),
        desired_output_schema=data.get("desired_output_schema"),
        max_price_cents=data.get("max_price_cents"),
        tags=data.get("tags", []),
        status=data.get("status", "open"),
        created_at=data["created_at"],
    )


class SkillService:
    def __init__(self, client: HttpClient):
        self._client = client

    # ─── Publishing ──────────────────────────────────────────────────

    def publish(self, **kwargs: Any) -> Skill:
        """Publish a new skill to the marketplace."""
        return _to_skill(self._client.post("/v1/skills", json=kwargs))

    def get(self, skill_id: str) -> Skill:
        return _to_skill(self._client.get(f"/v1/skills/{skill_id}"))

    def browse(
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
        data = self._client.get("/v1/skills", params=params)
        return [_to_skill(s) for s in data]

    def list_owned(self) -> list[Skill]:
        data = self._client.get("/v1/skills/mine")
        return [_to_skill(s) for s in data]

    def update(self, skill_id: str, **kwargs: Any) -> Skill:
        return _to_skill(self._client.patch(f"/v1/skills/{skill_id}", json=kwargs))

    def suspend(self, skill_id: str) -> Skill:
        return _to_skill(self._client.post(f"/v1/skills/{skill_id}/suspend"))

    def activate(self, skill_id: str) -> Skill:
        return _to_skill(self._client.post(f"/v1/skills/{skill_id}/activate"))

    def check_trust(self, skill_id: str) -> dict[str, Any]:
        # Trust claims are resolved server-side from the caller's DB-stored
        # identity claims; callers no longer pass them in.
        return cast("dict[str, Any]", self._client.post(f"/v1/skills/{skill_id}/check-trust", json={}))

    # ─── Invocations ─────────────────────────────────────────────────

    def invoke(
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
        """Invoke a skill.

        Args:
            skill_id: Target skill id (skl_*).
            agent_id: Invoking agent. May be omitted when the authenticated
                Passport already binds the agent.
            input: Skill input (validated server-side).
            passport_id: Optional passport jti for accountability.
            approval_id: Approval id from ``intents.submit_and_wait``
                Required when the calling agent is
                in enforced mode. Sent as ``X-Intent-Approval-Id``.
            authority_request_id: Stable, high-entropy request identifier for
                authority-bound replay and idempotency checks.
            idempotency_key: Stable, high-entropy key for exact paid retries.
                May be omitted when authority_request_id is supplied.
        """
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
            self._client.request(
                "POST",
                f"/v1/skills/{skill_id}/invoke",
                json=body,
                extra_headers=extra_headers if extra_headers else None,
            )
        )

    def get_invocation(self, invocation_id: str) -> SkillInvocation:
        return _to_invocation(self._client.get(f"/v1/skills/invocations/{invocation_id}"))

    def list_invocations(self) -> list[SkillInvocation]:
        data = self._client.get("/v1/skills/invocations/mine")
        return [_to_invocation(i) for i in data]

    def list_pending_invocations(self, skill_id: str | None = None) -> list[SkillInvocation]:
        params = {"skill_id": skill_id} if skill_id else {}
        data = self._client.get("/v1/skills/invocations/pending", params=params)
        return [_to_invocation(i) for i in data]

    def claim_invocation(self, invocation_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.post(f"/v1/skills/invocations/{invocation_id}/claim"))

    def complete_invocation(self, invocation_id: str, output: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/skills/invocations/{invocation_id}/complete",
                json={"output": output},
            ),
        )

    def fail_invocation(
        self,
        invocation_id: str,
        *,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/skills/invocations/{invocation_id}/fail",
                json={"error": {"code": code, "message": message}},
            ),
        )

    def poll(
        self,
        invocation_id: str,
        *,
        interval_seconds: float = 1.0,
        timeout_seconds: float = 60.0,
    ) -> SkillInvocation:
        """Poll an invocation until it reaches a terminal state."""
        start = time.time()
        while time.time() - start < timeout_seconds:
            result = self.get_invocation(invocation_id)
            if result.status in ("completed", "failed", "expired"):
                return result
            time.sleep(interval_seconds)
        raise TimeoutError(f"Invocation {invocation_id} timed out after {timeout_seconds}s")

    # ─── Requests ────────────────────────────────────────────────────

    def post_request(self, **kwargs: Any) -> SkillRequest:
        return _to_request(self._client.post("/v1/skill-requests", json=kwargs))

    def list_requests(
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
        data = self._client.get("/v1/skill-requests", params=params)
        return [_to_request(r) for r in data]

    def get_request(self, request_id: str) -> SkillRequest:
        return _to_request(self._client.get(f"/v1/skill-requests/{request_id}"))

    def get_request_matches(self, request_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/skill-requests/{request_id}/matches"))

    def suggest_composition(self, request_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/skill-requests/{request_id}/suggest"))
