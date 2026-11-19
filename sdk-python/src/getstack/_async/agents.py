"""Async mirror of AgentService."""

from __future__ import annotations

import builtins
from typing import Any, cast

from ..agents import _to_agent
from ..client import AsyncHttpClient
from ..types import Agent


class AsyncAgentService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def register(
        self,
        name: str,
        description: str | None = None,
        profile: str | None = None,
        accountability_mode: str | None = None,
        credential_access: str | None = None,
        key_mode: str | None = None,
        on_warning: str = "notify",
        on_critical: str = "notify",
        llm_inject_system_prompt: bool | None = None,
        llm_redact_pii: bool | None = None,
        eval_traffic: bool | None = None,
    ) -> Agent:
        """Register an agent. See the sync :meth:`AgentService.register`
               docstring — pass ``profile="proxied-llm-bot"`` for a bot that just
               runs. Unset fields are not sent, so they never clobber a preset.
        The LLM gateway toggles both default True server-side;
               ``llm_redact_pii=False`` sends user PII to the LLM provider
               unredacted (explicit operator decision) and False IS sent."""
        body: dict[str, Any] = {"name": name}
        if description:
            body["description"] = description
        if profile is not None:
            body["profile"] = profile
        if accountability_mode is not None:
            body["accountability_mode"] = accountability_mode
        if credential_access is not None:
            body["credential_access"] = credential_access
        if key_mode is not None:
            body["key_mode"] = key_mode
        if on_warning != "notify":
            body["on_warning"] = on_warning
        if on_critical != "notify":
            body["on_critical"] = on_critical
        # is-not-None (not truthiness) so an explicit False reaches the wire.
        if llm_inject_system_prompt is not None:
            body["llm_inject_system_prompt"] = llm_inject_system_prompt
        if llm_redact_pii is not None:
            body["llm_redact_pii"] = llm_redact_pii
        if eval_traffic is not None:
            body["eval_traffic"] = eval_traffic
        return _to_agent(await self._client.post("/v1/agents/register", json=body))

    async def setup(
        self,
        agent: dict[str, Any],
        grants: builtins.list[dict[str, Any]] | None = None,
        allowed_hosts: builtins.list[dict[str, Any]] | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Register an agent with its first grants and host lists as one
        approval. See the sync :meth:`AgentService.setup`."""
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]",
            await self._client.post(
                "/v1/agents/setup",
                json={"agent": agent, "grants": grants or [], "allowed_hosts": allowed_hosts or []},
                extra_headers=_gov_headers,
            ),
        )

    async def dismiss_warnings(self, agent_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Resolve every open warning of one agent. See the sync
        :meth:`AgentService.dismiss_warnings`."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/agents/{agent_id}/dismiss-warnings",
                json={},
                extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
            ),
        )

    async def get(self, agent_id: str) -> Agent:
        return _to_agent(await self._client.get(f"/v1/agents/{agent_id}"))

    async def list(self) -> list[Agent]:
        data = await self._client.get("/v1/agents")
        return [_to_agent(a) for a in data]

    async def overview(self, *, limit: int | None = None, cursor: str | None = None) -> dict[str, Any]:
        """One page of every agent of the account with what the Console's Agents table shows. See the sync
        :meth:`AgentService.overview`."""
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if cursor is not None:
            params["cursor"] = cursor
        return cast("dict[str, Any]", await self._client.get("/v1/agents/overview", params=params or None))

    async def update(self, agent_id: str, **kwargs: Any) -> Agent:
        """PATCH mutable agent fields, passed through as-is — including
        the LLM gateway toggles; see the sync
               :meth:`AgentService.update`."""
        return _to_agent(await self._client.patch(f"/v1/agents/{agent_id}", json=kwargs))

    async def suspend(self, agent_id: str) -> Agent:
        return await self.update(agent_id, status="suspended")

    async def activate(self, agent_id: str) -> Agent:
        return await self.update(agent_id, status="active")

    async def delete(self, agent_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete(f"/v1/agents/{agent_id}"))

    async def unblock(self, agent_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]", await self._client.post(f"/v1/agents/{agent_id}/unblock", extra_headers=_gov_headers)
        )
