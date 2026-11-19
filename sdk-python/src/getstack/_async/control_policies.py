"""Async mirrors of ControlPoliciesService and ControlReviewsService: policies and the actions they held."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..control_policies import (
    _approval,
    _delete_params,
    _review_params,
    _review_path,
    _revisions_path,
    _scope_path,
    _set_body,
    _simulate_body,
    _start_path,
)


class AsyncControlPoliciesService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self) -> dict[str, Any]:
        """Every policy of the customer: ``{"controls_enabled": bool, "policies": [...]}``."""
        return cast("dict[str, Any]", await self._client.request("GET", "/v1/control-policies"))

    async def get(self, scope: str) -> dict[str, Any]:
        """One policy. ``scope`` is ``"default"`` or an agent id (which also returns the policy in force)."""
        return cast("dict[str, Any]", await self._client.request("GET", _scope_path(scope)))

    async def set(
        self,
        scope: str,
        definition: dict[str, Any],
        *,
        expected_revision: int | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Create or revise a policy: ``{"change", "policy"}``. Loosening needs a person's approval."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                _scope_path(scope),
                json=_set_body(definition, expected_revision),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def delete(
        self,
        scope: str,
        *,
        expected_revision: int | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Delete a policy: ``{"change": "delete", "policy": None}``. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "DELETE",
                _scope_path(scope),
                params=_delete_params(expected_revision),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def start_from_current_access(
        self, agent_id: str, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """A policy equal to the agent's current connection grants: ``{"change", "policy"}``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", _start_path(agent_id), json={}, extra_headers=_approval(governance_approval_id)
            ),
        )

    async def simulate(
        self,
        call: dict[str, Any],
        *,
        agent_id: str | None = None,
        definition: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Try one call against a policy. Nothing is counted, held or sent."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", "/v1/control-policies/simulate", json=_simulate_body(call, agent_id, definition)
            ),
        )

    async def revisions(self, policy_id: str) -> dict[str, Any]:
        """The revisions of a policy, newest first: ``{"revisions": [...]}``."""
        return cast("dict[str, Any]", await self._client.request("GET", _revisions_path(policy_id)))


class AsyncControlReviewsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self, *, status: str | None = None, limit: int | None = None) -> dict[str, Any]:
        """Actions a policy held for a person: ``{"reviews": [...]}``. ``status`` is ``pending`` or ``all``."""
        return cast(
            "dict[str, Any]",
            await self._client.request("GET", "/v1/control-reviews", params=_review_params(status, limit)),
        )

    async def get(self, review_id: str) -> dict[str, Any]:
        """One held action."""
        return cast("dict[str, Any]", await self._client.request("GET", _review_path(review_id)))
