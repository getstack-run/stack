"""Audit log access.

STACK writes the record for every account; reading it is a controls feature, so without controls every call
here raises ``ControlsRequiredError`` (402 ``CONTROLS_REQUIRED``). Switching controls on shows all of it,
including what came before. A self-managed install has every controls feature.
"""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


class AuditService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(
        self,
        limit: int = 20,
        since: int | None = None,
        agent_id: str | None = None,
        passport_jti: str | None = None,
    ) -> dict[str, Any]:
        """Tail recent audit entries (newest-first).

        Returns ``{"entries": [...], "max_timestamp": int | None}``.
        Pass ``since`` (epoch ms) to fetch only entries newer than the
        last seen timestamp — useful for incremental polling. Pass
        ``agent_id`` or ``passport_jti`` to narrow to a single agent
        or single passport.
        """
        params: dict[str, str] = {"limit": str(limit)}
        if since is not None:
            params["since"] = str(since)
        if agent_id is not None:
            params["agent_id"] = agent_id
        if passport_jti is not None:
            params["passport_jti"] = passport_jti
        return cast("dict[str, Any]", self._client.get("/v1/audit", params=params))

    def chain_head(self) -> dict[str, Any]:
        """Current chain head — latest entry hash + entry count."""
        return cast("dict[str, Any]", self._client.get("/v1/audit/chain-head"))

    def verify_chain(
        self,
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Walk the per-operator chain and report tamper status."""
        params: dict[str, str] = {}
        if from_date is not None:
            params["from"] = from_date
        if to_date is not None:
            params["to"] = to_date
        if limit is not None:
            params["limit"] = str(limit)
        return cast("dict[str, Any]", self._client.get("/v1/audit/verify-chain", params=params))
