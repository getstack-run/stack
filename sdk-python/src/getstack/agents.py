"""Agent management."""

from __future__ import annotations

import builtins
from typing import Any, cast

from .client import HttpClient
from .types import Agent


def _to_agent(data: dict[str, Any]) -> Agent:
    return Agent(
        id=data["id"],
        operator_id=data["operator_id"],
        name=data["name"],
        description=data.get("description"),
        status=data["status"],
        # A new agent starts "logged" (matches the API), not "standard" —
        # the old fallback misreported the mode when the field was absent
        # from a response.
        accountability_mode=data.get("accountability_mode", "logged"),
        on_warning=data.get("on_warning", "notify"),
        on_critical=data.get("on_critical", "notify"),
        passport_blocked=data.get("passport_blocked", False),
        passport_blocked_reason=data.get("passport_blocked_reason"),
        passport_blocked_at=data.get("passport_blocked_at"),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        credential_access=data.get("credential_access", "direct"),
        key_mode=data.get("key_mode", "stack_managed"),
        # LLM gateway toggles; True mirrors the DB default
        # (fail-closed) when an older API omits them.
        llm_inject_system_prompt=data.get("llm_inject_system_prompt", True),
        llm_redact_pii=data.get("llm_redact_pii", True),
    )


class AgentService:
    def __init__(self, client: HttpClient):
        self._client = client

    def register(
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
        """Register an agent.

        For a bot that just runs (calls an LLM through STACK, no provider
        key on its box), pass ``profile="proxied-llm-bot"`` — it expands
        server-side to ``credential_access="proxy_only"`` +
        ``accountability_mode="logged"`` + ``key_mode="stack_managed"`` so
        the first call works with no approval-header dance. Any field you
        also pass explicitly overrides the preset.

        Omitting ``accountability_mode``/``credential_access`` leaves the
        server default (``logged`` + ``proxy_only``) OR the profile value
        — they are only sent when provided, so an unset value never
        clobbers a preset. A new agent starts ``logged``: calls are recorded
        and need no per-call approval; ``accountability_mode="enforced"``
        is the owner's choice. ``eval_traffic=True`` marks the agent as test
        or benchmark traffic (warnings arrive already resolved, criticals
        stay live) and is part of the one registration approval. ``proxy_only`` means the agent never receives a
        raw secret: credentials are injected at the proxy boundary, so
        ``credentials.get()`` is refused. Pass
        ``credential_access="direct"`` to opt back into raw retrieval.

        ``llm_inject_system_prompt`` / ``llm_redact_pii`` tune the
        ``/v1/llm/*`` gateway per agent (both default True server-side):
        inject has no effect (it is accepted and ignored; STACK adds no
        system prompt to gateway calls); redact replaces PII in user
        messages before forwarding.
        ``llm_redact_pii=False`` means user PII flows to the LLM provider
        unredacted — an explicit operator decision. ``False`` is sent on
        the wire; only ``None`` (unset) is omitted.
        """
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
        return _to_agent(self._client.post("/v1/agents/register", json=body))

    def setup(
        self,
        agent: dict[str, Any],
        grants: builtins.list[dict[str, Any]] | None = None,
        allowed_hosts: builtins.list[dict[str, Any]] | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Register an agent, give it its first grants and declare the hosts
        its connections' credentials may be sent to, as one human approval
        whose card lists all of it. ``agent`` is the register body (``name``
        and any posture fields), each grant is ``{service_connection_id,
        scopes, constraints?, intents?, alternatives?, allow_data_from?}`` (``alternatives`` are rules that each
        allow their own calls) and each host list ``{service_connection_id, allowed_hosts}``. From API-key
        sessions this 403s with GOVERNANCE_APPROVAL_REQUIRED: retry with
        ``governance_approval_id`` once a person approved it, in the chat or on the approval page.
        """
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]",
            self._client.post(
                "/v1/agents/setup",
                json={"agent": agent, "grants": grants or [], "allowed_hosts": allowed_hosts or []},
                extra_headers=_gov_headers,
            ),
        )

    def dismiss_warnings(self, agent_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Resolve every open warning of one agent and keep new ones of the
        same kinds from coming back for a day. Criticals are never
        dismissed. It needs no approval; ``governance_approval_id`` is accepted for callers written before and
        has no effect."""
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/agents/{agent_id}/dismiss-warnings",
                json={},
                extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
            ),
        )

    def get(self, agent_id: str) -> Agent:
        return _to_agent(self._client.get(f"/v1/agents/{agent_id}"))

    def list(self) -> list[Agent]:
        data = self._client.get("/v1/agents")
        return [_to_agent(a) for a in data]

    def overview(self, *, limit: int | None = None, cursor: str | None = None) -> dict[str, Any]:
        """One page of every agent of the account with what the Console's Agents table shows.

        Each row has ``agent_id``, ``name``, ``status`` (``active``, ``paused``, ``blocked`` or ``revoked``), ``trust``
        (``value`` and ``source``: ``agent`` is its own, ``account`` follows the account, ``default``), ``account`` (id
        and status, or None), ``pieces`` (kind and state), ``held`` (items waiting on a person for it), ``wakes``
        (queued
        and running), ``last_passport_at``, ``handoffs_this_month`` (``sent`` and ``received``, each the other agent's
        id
        and name and a count) and ``spend_this_month_cents`` (None for an agent with no account). Owner, admin or
        read-only; an agent is refused. Nothing from the audit record. Up to 200 agents a page; pass ``next_cursor``
        back as ``cursor`` for the next.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if cursor is not None:
            params["cursor"] = cursor
        return cast("dict[str, Any]", self._client.get("/v1/agents/overview", params=params or None))

    def update(self, agent_id: str, **kwargs: Any) -> Agent:
        """PATCH mutable agent fields, passed through as-is. The
        LLM gateway toggles (``llm_inject_system_prompt``,
        ``llm_redact_pii``) ride here too — see :meth:`register` for
        semantics (``llm_inject_system_prompt`` has no effect); ``llm_redact_pii=False`` sends user PII to the LLM
        provider unredacted."""
        return _to_agent(self._client.patch(f"/v1/agents/{agent_id}", json=kwargs))

    def suspend(self, agent_id: str) -> Agent:
        return self.update(agent_id, status="suspended")

    def activate(self, agent_id: str) -> Agent:
        return self.update(agent_id, status="active")

    def delete(self, agent_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.delete(f"/v1/agents/{agent_id}"))

    def unblock(self, agent_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """from API-key sessions this 403s with
        GOVERNANCE_APPROVAL_REQUIRED - retry with governance_approval_id
        after human approval in the dashboard."""
        _gov_headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast("dict[str, Any]", self._client.post(f"/v1/agents/{agent_id}/unblock", extra_headers=_gov_headers))
