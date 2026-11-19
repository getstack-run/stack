from __future__ import annotations

import builtins
from typing import Any, cast
from urllib.parse import quote

from .._fleet_key import prepare_fleet_key
from ..client import AsyncHttpClient


class AsyncFleetsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def session(self, fleet_policy_id: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", "/v1/fleets/session", json={"fleet_policy_id": fleet_policy_id} if fleet_policy_id else {}
            ),
        )

    async def workload_enrollment_challenge(self, policy_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"/v1/fleets/{quote(policy_id, safe='')}/workload/enrollment-challenges", json={}
            ),
        )

    async def enroll_workload(self, policy_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/fleets/{quote(policy_id, safe='')}/workload/enroll", json=request),
        )

    async def enroll_workload_local(self, policy_id: str, *, name: str, idempotency_key: str) -> dict[str, Any]:
        public_key, sign, persist = prepare_fleet_key(policy_id, idempotency_key)
        challenge = await self.workload_enrollment_challenge(policy_id)
        result = await self.enroll_workload(
            policy_id,
            {
                "name": name,
                "idempotency_key": idempotency_key,
                "public_key": public_key,
                "challenge_id": challenge["challenge_id"],
                "proof": sign(challenge["challenge"]),
            },
        )
        persist(result["agent_id"])
        return result

    async def enroll_local(self, policy_id: str, *, name: str, idempotency_key: str) -> dict[str, Any]:
        public_key, sign, persist = prepare_fleet_key(policy_id, idempotency_key)
        challenge = await self.enrollment_challenge(policy_id)
        result = await self.enroll(
            policy_id,
            {
                "name": name,
                "idempotency_key": idempotency_key,
                "public_key": public_key,
                "challenge_id": challenge["challenge_id"],
                "proof": sign(challenge["challenge"]),
            },
        )
        persist(result["agent_id"])
        return result

    async def list(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", await self._client.request("GET", "/v1/fleets"))

    async def list_page(self, page: int = 1, limit: int = 20) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", await self._client.request("GET", "/v1/fleets", params={"page": page, "limit": limit})
        )

    async def get(self, policy_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", f"/v1/fleets/{quote(policy_id, safe='')}"))

    async def membership(self, agent_id: str) -> dict[str, Any] | None:
        return cast(
            "dict[str, Any] | None",
            await self._client.request("GET", f"/v1/fleets/membership/{quote(agent_id, safe='')}"),
        )

    async def members_page(self, policy_id: str, page: int = 1, limit: int = 20) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET", f"/v1/fleets/{quote(policy_id, safe='')}/members", params={"page": page, "limit": limit}
            ),
        )

    async def activate(
        self, definition: dict[str, Any], *, idempotency_key: str, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        headers = {"Idempotency-Key": idempotency_key}
        if governance_approval_id is not None:
            headers["X-Governance-Approval"] = governance_approval_id
        return cast(
            "dict[str, Any]", await self._client.request("POST", "/v1/fleets", json=definition, extra_headers=headers)
        )

    async def revise(
        self,
        policy_id: str,
        definition: dict[str, Any],
        *,
        expected_revision: int,
        idempotency_key: str,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        headers = {"If-Match": str(expected_revision), "Idempotency-Key": idempotency_key}
        if governance_approval_id is not None:
            headers["X-Governance-Approval"] = governance_approval_id
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT", f"/v1/fleets/{quote(policy_id, safe='')}", json=definition, extra_headers=headers
            ),
        )

    async def members(self, policy_id: str) -> builtins.list[dict[str, Any]]:
        return cast(
            "builtins.list[dict[str, Any]]",
            await self._client.request("GET", f"/v1/fleets/{quote(policy_id, safe='')}/members"),
        )

    async def revoke_member(self, policy_id: str, agent_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"/v1/fleets/{quote(policy_id, safe='')}/members/{quote(agent_id, safe='')}/revoke", json={}
            ),
        )

    async def revoke(self, policy_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/fleets/{quote(policy_id, safe='')}/revoke", json={}),
        )

    async def enrollment_challenge(self, policy_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"/v1/fleets/{quote(policy_id, safe='')}/enrollment-challenges", json={}
            ),
        )

    async def enroll(self, policy_id: str, request: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/fleets/{quote(policy_id, safe='')}/enroll", json=request),
        )
