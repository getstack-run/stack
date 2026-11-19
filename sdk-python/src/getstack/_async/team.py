"""Team member management (async parity with the JS SDK's TeamService)."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..team import clear_sso_body


class AsyncTeamService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def invite(
        self,
        email: str,
        name: str,
        role: str | None = None,
        allowed_connections: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"email": email, "name": name}
        if role is not None:
            body["role"] = role
        if allowed_connections is not None:
            body["allowed_connections"] = allowed_connections
        return cast("dict[str, Any]", await self._client.post("/v1/team/members", json=body))

    async def list(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", await self._client.get("/v1/team/members"))

    async def update(self, member_id: str, **fields: Any) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.patch(f"/v1/team/members/{member_id}", json=fields))

    async def revoke(self, member_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete(f"/v1/team/members/{member_id}"))

    async def clear_sso_bindings(
        self,
        *,
        member_id: str | None = None,
        issuer: str | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Forget the single sign-on binding of one member (``member_id``) or of every member bound to one issuer.

        Exactly one of ``member_id`` and ``issuer`` (the ``iss`` of the provider that was replaced). The next verified
        sign-in with the provider now in use binds them again. A person approves it in a browser: without a
        dashboard session the first call raises ``GovernanceApprovalRequiredError``; retry with
        ``governance_approval_id``. Returns ``{"cleared": [{"id", "email", "sso_issuer"}]}``.
        """
        body = clear_sso_body(member_id, issuer)
        headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/team/sso-bindings/clear", json=body, extra_headers=headers),
        )
