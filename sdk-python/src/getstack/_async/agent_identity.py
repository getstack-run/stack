"""Who an agent is, answered on request by STACK (async): see ``getstack.agent_identity``."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from ..agent_identity import JWKS_PATH, agent_urls, lookup_params, verified_result
from ..client import AsyncHttpClient
from ..verify_agent_identity import verify_agent_identity


class AsyncAgentIdentityService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def lookup(
        self, *, key_id: str | None = None, site: str | None = None, agent_id: str | None = None
    ) -> dict[str, Any]:
        """Ask by the key id of a request the agent signed, the host name of its site, or its id. Returns the
        answer as served: ``statement`` (not checked: see ``verified``) and the same facts as JSON."""
        params, _ = lookup_params(key_id, site, agent_id)
        return cast("dict[str, Any]", await self._client.public_request("GET", "/v1/agent-identity", params=params))

    async def verified(
        self,
        *,
        key_id: str | None = None,
        site: str | None = None,
        agent_id: str | None = None,
        jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Ask, then check the statement against STACK's published keys (or the ``jwks`` you pin)."""
        params, expect = lookup_params(key_id, site, agent_id)
        answer = cast("dict[str, Any]", await self._client.public_request("GET", "/v1/agent-identity", params=params))
        keys = jwks if jwks is not None else await self._client.public_request("GET", JWKS_PATH)
        return verified_result(verify_agent_identity(answer["statement"], jwks=keys, now=now, expect=expect))

    def urls(self, agent_id: str) -> dict[str, str]:
        """The addresses of an agent's lookup and machine files."""
        return agent_urls(self._client.base_url, agent_id)
