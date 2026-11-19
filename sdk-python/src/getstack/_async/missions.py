"""Async mirror of MissionsService. Same surface, async/await.

Completing or revoking a Mission (any reason) revokes every passport
bound to it.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from ..client import AsyncHttpClient
from ..missions import _recipient_fields, _start_body


class AsyncMissionsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def start(
        self,
        request: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
        mission: dict[str, Any] | None = None,
        passport: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Open a Mission and issue its passport in one call. Operator form:
        ``await stack.missions.start(agent_id=..., mission={...}, passport={...})``.
        Fleet form (unchanged): ``await stack.missions.start({"fleet_policy_id": ...})``."""
        body = _start_body(request, agent_id, mission, passport)
        return cast("dict[str, Any]", await self._client.request("POST", "/v1/missions/start", json=body))

    async def renew(self, mission_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/missions/{quote(mission_id, safe='')}/renew", json={}),
        )

    async def open(
        self,
        intent_summary: str,
        *,
        intent_services: list[str] | None = None,
        expected_counterparties: list[str] | None = None,
        baseline_profile: dict[str, Any] | None = None,
        expected_output_shape: dict[str, Any] | None = None,
        max_actions: int | None = None,
        max_dropoff_bytes: int | None = None,
        coverage_cap_cents: int | None = None,
        max_duration_seconds: int | None = None,
        max_concurrent_intents: int | None = None,
        max_actions_per_service: dict[str, int] | None = None,
        cap_behavior: dict[str, str] | None = None,
        coverage_cap_period: str | None = None,
        cap_time_zone: str | None = None,
        making_orders_up_to_cents: int | None = None,
        expires_in_seconds: int | None = None,
        parent_passport_services: list[str] | None = None,
        fleet_policy_id: str | None = None,
        idempotency_key: str | None = None,
        requested_access: list[dict[str, Any]] | None = None,
        requested_operations: list[dict[str, Any]] | None = None,
        limits: dict[str, Any] | None = None,
        authority_binding_ids: list[str] | None = None,
        agent_id: str | None = None,
        recipients: list[str] | None = None,
        recipient_pins: list[dict[str, Any]] | None = None,
        reply_to_message: str | None = None,
    ) -> dict[str, Any]:
        """Open a new mission. ``agent_id`` assigns it to that agent. ``recipients``, ``recipient_pins`` and
        ``reply_to_message`` say who this Mission may send to (see the sync service)."""
        body: dict[str, Any] = {"intent_summary": intent_summary}
        if agent_id is not None:
            body["agent_id"] = agent_id
        if intent_services is not None:
            body["intent_services"] = intent_services
        if expected_counterparties is not None:
            body["expected_counterparties"] = expected_counterparties
        if baseline_profile is not None:
            body["baseline_profile"] = baseline_profile
        if expected_output_shape is not None:
            body["expected_output_shape"] = expected_output_shape
        if max_actions is not None:
            body["max_actions"] = max_actions
        if max_dropoff_bytes is not None:
            body["max_dropoff_bytes"] = max_dropoff_bytes
        if coverage_cap_cents is not None:
            body["coverage_cap_cents"] = coverage_cap_cents
        if max_duration_seconds is not None:
            body["max_duration_seconds"] = max_duration_seconds
        if max_concurrent_intents is not None:
            body["max_concurrent_intents"] = max_concurrent_intents
        if max_actions_per_service is not None:
            body["max_actions_per_service"] = max_actions_per_service
        if cap_behavior is not None:
            body["cap_behavior"] = cap_behavior
        if coverage_cap_period is not None:
            body["coverage_cap_period"] = coverage_cap_period
        if cap_time_zone is not None:
            body["cap_time_zone"] = cap_time_zone
        if making_orders_up_to_cents is not None:
            body["making_orders_up_to_cents"] = making_orders_up_to_cents
        if expires_in_seconds is not None:
            body["expires_in_seconds"] = expires_in_seconds
        if parent_passport_services is not None:
            body["parent_passport_services"] = parent_passport_services
        for key, value in {
            "fleet_policy_id": fleet_policy_id,
            "idempotency_key": idempotency_key,
            "requested_access": requested_access,
            "requested_operations": requested_operations,
            "limits": limits,
            "authority_binding_ids": authority_binding_ids,
        }.items():
            if value is not None:
                body[key] = value
        body.update(_recipient_fields(recipients, recipient_pins, reply_to_message))
        return cast("dict[str, Any]", await self._client.request("POST", "/v1/missions", json=body))

    async def complete(
        self,
        mission_id: str,
        *,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if output is not None:
            body["output"] = output
        return cast(
            "dict[str, Any]", await self._client.request("POST", f"/v1/missions/{mission_id}/complete", json=body)
        )

    async def revoke(
        self,
        mission_id: str,
        *,
        reason: str,
        notes: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"reason": reason}
        if notes is not None:
            body["notes"] = notes
        return cast(
            "dict[str, Any]", await self._client.request("POST", f"/v1/missions/{mission_id}/revoke", json=body)
        )

    async def add_recipients(
        self,
        mission_id: str,
        *,
        recipients: list[str] | None = None,
        recipient_pins: list[dict[str, Any]] | None = None,
        reply_to_message: str | None = None,
    ) -> dict[str, Any]:
        body = _recipient_fields(recipients, recipient_pins, reply_to_message)
        if not body:
            raise ValueError("name recipients, recipient_pins or reply_to_message")
        path = f"/v1/missions/{quote(mission_id, safe='')}/recipients"
        return cast("dict[str, Any]", await self._client.request("POST", path, json=body))

    async def get(self, mission_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", f"/v1/missions/{mission_id}"))

    async def list(
        self,
        *,
        status: str | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if status is not None:
            params["status"] = status
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit
        path = "/v1/missions"
        if params:
            from urllib.parse import urlencode

            path = f"{path}?{urlencode(params)}"
        return cast("dict[str, Any]", await self._client.request("GET", path))

    async def review(self, mission_id: str, decision: str, *, limit: int | None = None) -> dict[str, Any]:
        """Decide a Mission one of its caps paused: ``raise`` (with ``limit``, the new limit of the cap that paused it,
        above the old one), ``continue`` (its limits as they are; a cap with no room left pauses it again) or ``close``
        (it ends). The agent the Mission was opened for is told the decision. The owner's or a member's own decision."""
        if decision not in ("raise", "continue", "close"):
            raise ValueError("decision must be raise, continue or close")
        if (decision == "raise") != (limit is not None):
            raise ValueError("raise needs the new limit, and only raise takes one")
        body: dict[str, Any] = {"decision": decision}
        if limit is not None:
            body["limit"] = limit
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/missions/{quote(mission_id, safe='')}/review", json=body),
        )

    async def set_making_allowance(self, mission_id: str, making_orders_up_to_cents: int | None) -> dict[str, Any]:
        """Set what the owner pre-approves of a running Mission's print-on-demand orders, in cents across all of them;
        ``None`` removes it. The owner or an admin only. Returns the Mission."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                f"/v1/missions/{quote(mission_id, safe='')}/making-allowance",
                json={"making_orders_up_to_cents": making_orders_up_to_cents},
            ),
        )

    async def activity(self, mission_id: str) -> dict[str, Any]:
        """Return the current recorded activity for a mission."""
        return cast(
            "dict[str, Any]", await self._client.request("GET", f"/v1/missions/{quote(mission_id, safe='')}/replay")
        )

    async def replay(self, mission_id: str) -> dict[str, Any]:
        """Compatibility alias for activity()."""
        return await self.activity(mission_id)

    async def list_operator_reviews(self, mission_id: str) -> dict[str, Any]:
        """List signed Operator review revisions for a mission."""
        return cast(
            "dict[str, Any]",
            await self._client.request("GET", f"/v1/missions/{quote(mission_id, safe='')}/operator-reviews"),
        )

    async def download_operator_review(self, mission_id: str, claim_id: str) -> bytes:
        """Download the exact signed COSE bytes for one Operator review."""
        return await self._client.request_bytes(
            "GET",
            f"/v1/missions/{quote(mission_id, safe='')}/operator-reviews/{quote(claim_id, safe='')}/download",
        )

    async def list_dossiers(self, mission_id: str) -> dict[str, Any]:
        """List old dossier claims with the pre-Operator-review response shape."""
        reviews = await self.list_operator_reviews(mission_id)
        return {
            "items": [
                {
                    "claim_id": item.get("claim_id"),
                    "operator_id": item.get("operator_id"),
                    "issued_at_ms": item.get("issued_at_ms"),
                    "body": item.get("claim", item.get("body")),
                }
                for item in reviews.get("items", [])
                if item.get("claim", item.get("body", {})).get("type") == "dossier"
            ]
        }
