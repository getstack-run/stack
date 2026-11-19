"""Async mirror of ServiceService."""

from __future__ import annotations

import builtins
from typing import Any, cast
from urllib.parse import quote

from ..client import AsyncHttpClient


class AsyncServiceService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(self) -> list[dict[str, Any]]:
        # /v1/services/connected (was wrongly /v1/services/connections → 404).
        return cast("list[dict[str, Any]]", await self._client.get("/v1/services/connected"))

    async def list_available(self) -> builtins.list[dict[str, Any]]:
        return cast("builtins.list[dict[str, Any]]", await self._client.get("/v1/services"))

    async def list_templates(self) -> builtins.list[dict[str, Any]]:
        return cast("builtins.list[dict[str, Any]]", await self._client.get("/v1/services/templates"))

    async def connect(
        self,
        service_id: str,
        oauth_token: str,
        scopes: builtins.list[str],
        mcp_url: str | None = None,
        connection_name: str | None = None,
    ) -> dict[str, Any]:
        """Connect a catalog (OAuth-family) service by supplying the OAuth
        token directly. ``scopes`` must name at least one scope. For services
        not in the catalog, use :meth:`connect_custom`.

        ``mcp_url`` is the address of the service's MCP endpoint, when it speaks MCP over HTTP: https, and on one
        of the connection's allowed hosts. It is what ``stack.proxy.service_tools`` and ``service_call_tool`` use."""
        body: dict[str, Any] = {
            "service_id": service_id,
            "oauth_token": oauth_token,
            "scopes": scopes,
        }
        if mcp_url is not None:
            body["mcp_url"] = mcp_url
        if connection_name is not None:
            body["connection_name"] = connection_name
        return cast("dict[str, Any]", await self._client.post("/v1/services/connect", json=body))

    async def connect_custom(
        self,
        name: str,
        credential: str | dict[str, str],
        description: str | None = None,
        scopes: builtins.list[str] | None = None,
        allowed_hosts: builtins.list[str] | None = None,
        mcp_url: str | None = None,
        connection_name: str | None = None,
    ) -> dict[str, Any]:
        """Connect the customer's own API with a credential.

        ``allowed_hosts`` are the hosts the credential may be sent to (needed unless the credential carries a
        ``base_url``). ``mcp_url`` is the address of its MCP endpoint, when it speaks MCP over HTTP: https, and on
        one of those hosts; ``stack.proxy.service_tools`` and ``service_call_tool`` then work for it.
        """
        body: dict[str, Any] = {"name": name, "credential": credential}
        if description:
            body["description"] = description
        if scopes:
            body["scopes"] = scopes
        if allowed_hosts:
            body["allowed_hosts"] = allowed_hosts
        if mcp_url is not None:
            body["mcp_url"] = mcp_url
        if connection_name is not None:
            body["connection_name"] = connection_name
        return cast("dict[str, Any]", await self._client.post("/v1/services/custom", json=body))

    async def create_connect_link(
        self,
        service_id: str | None = None,
        scopes: builtins.list[str] | None = None,
        custom: dict[str, Any] | None = None,
        connect: dict[str, Any] | None = None,
        connection_name: str | None = None,
    ) -> dict[str, Any]:
        """Create a one-time connect link; see ``ServiceService.create_connect_link``."""
        if sum(value is not None for value in (service_id, custom, connect)) != 1:
            raise ValueError("give exactly one of service_id, custom or connect")
        if connect is not None and connection_name is not None:
            raise ValueError(
                "connection_name does not apply to a connect link; it names a service_id or custom connection"
            )
        body: dict[str, Any] = (
            {"custom": custom}
            if custom is not None
            else {"connect": connect}
            if connect is not None
            else {"service_id": service_id}
        )
        if scopes and service_id is not None:
            body["scopes"] = scopes
        if connection_name is not None:
            if custom is not None:
                # The API takes the name inside ``custom`` for a custom link; one already there is kept.
                body["custom"] = {"connection_name": connection_name, **custom}
            else:
                body["connection_name"] = connection_name
        return cast("dict[str, Any]", await self._client.post("/v1/services/connect-links", json=body))

    async def get_connect_link(self, link_id: str) -> dict[str, Any]:
        """The state of a connect link; see ``ServiceService.get_connect_link``."""
        return cast("dict[str, Any]", await self._client.get(f"/v1/services/connect-links/{quote(link_id, safe='')}"))

    async def list_connect_links(self) -> builtins.list[dict[str, Any]]:
        """The connect links still waiting for the person; see ``ServiceService.list_connect_links``."""
        answer = cast("dict[str, Any]", await self._client.get("/v1/services/connect-links"))
        return cast("list[dict[str, Any]]", answer["links"])

    async def rename(self, connection_id: str, connection_name: str) -> dict[str, Any]:
        """Rename a connection (owner or admin). A name is 1 to 40 characters: letters, digits, space and dash, and
        unique among the service's active connections for the same principal (409 otherwise)."""
        return cast(
            "dict[str, Any]",
            await self._client.patch(
                f"/v1/services/{quote(connection_id, safe='')}", json={"connection_name": connection_name}
            ),
        )

    async def verify(self, connection_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post(f"/v1/services/{connection_id}/verify"))

    async def disconnect(self, connection_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete(f"/v1/services/{connection_id}/disconnect"))

    async def grant_agent_access(
        self,
        agent_id: str,
        service_connection_id: str,
        scopes: builtins.list[str],
        *,
        constraints: builtins.list[dict[str, Any]] | None = None,
        intents: builtins.list[dict[str, Any]] | None = None,
        alternatives: builtins.list[dict[str, Any]] | None = None,
        allow_data_from: builtins.list[str] | None = None,
    ) -> dict[str, Any]:
        """Grant an agent access to a connected service; see ``ServiceService.grant_agent_access``.

        The answer carries ``control_policy`` when the agent's policy still has to list the connection.
        """
        body: dict[str, Any] = {
            "agent_id": agent_id,
            "service_connection_id": service_connection_id,
            "scopes": scopes,
        }
        for key, value in (
            ("constraints", constraints),
            ("intents", intents),
            ("alternatives", alternatives),
            ("allow_data_from", allow_data_from),
        ):
            if value is not None:
                body[key] = value
        return cast("dict[str, Any]", await self._client.post("/v1/services/grant", json=body))

    async def revoke_agent_access(self, agent_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.delete(f"/v1/services/agents/{agent_id}/revoke"))

    async def get_agent_permissions(self, agent_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/agents/{agent_id}/permissions"))
