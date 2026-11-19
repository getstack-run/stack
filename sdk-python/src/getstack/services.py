"""Service management."""

from __future__ import annotations

import builtins
from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


class ServiceService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(self) -> list[dict[str, Any]]:
        # The connected-instances endpoint is /v1/services/connected (was
        # wrongly /v1/services/connections here → 404). Matches the JS SDK's
        # listConnected().
        return cast("list[dict[str, Any]]", self._client.get("/v1/services/connected"))

    def list_available(self) -> builtins.list[dict[str, Any]]:
        return cast("builtins.list[dict[str, Any]]", self._client.get("/v1/services"))

    def list_templates(self) -> builtins.list[dict[str, Any]]:
        return cast("builtins.list[dict[str, Any]]", self._client.get("/v1/services/templates"))

    def connect(
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
        of the connection's allowed hosts. It is what ``stack.proxy.service_tools`` and ``service_call_tool`` use.

        ``connection_name`` names the connection (1 to 40 characters: letters, digits, space, dash) when the service
        holds several; the first connection needs none and is called ``default``. A name already used by an active
        connection of the same service is refused (409)."""
        body: dict[str, Any] = {
            "service_id": service_id,
            "oauth_token": oauth_token,
            "scopes": scopes,
        }
        if mcp_url is not None:
            body["mcp_url"] = mcp_url
        if connection_name is not None:
            body["connection_name"] = connection_name
        return cast("dict[str, Any]", self._client.post("/v1/services/connect", json=body))

    def connect_custom(
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
        ``connection_name`` names the connection; see :meth:`connect`.
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
        return cast("dict[str, Any]", self._client.post("/v1/services/custom", json=body))

    def create_connect_link(
        self,
        service_id: str | None = None,
        scopes: builtins.list[str] | None = None,
        custom: dict[str, Any] | None = None,
        connect: dict[str, Any] | None = None,
        connection_name: str | None = None,
    ) -> dict[str, Any]:
        """Connect a service without the credential passing through this program or a chat.

        Creates a one-time link the person opens in their own browser, signed in to STACK. It is bound to
        this account and member, works once, expires after 10 minutes, and any number can be open at once.
        Give exactly one of ``service_id`` and ``custom``. ``service_id`` is a
        catalog service id or provider name; ``scopes`` are the OAuth scopes to ask for when the service
        connects through the provider's own sign-in (omit for the service defaults). ``custom`` is the
        customer's own API that takes a key or token: ``{"name": ..., "allowed_hosts": [...]}`` (a name of up
        to 200 characters, 1 to 100 hosts) with an optional ``description`` (up to 2,000 characters), an
        optional credential ``template`` whose fields the page asks for and an optional ``mcp_url`` (the address of
        its MCP endpoint, when it speaks MCP over HTTP: https, on one of the hosts). The hosts are where the key may be
        sent; the page shows them and the owner may correct them there. Never put a key in it. A custom
        service that signs in with OAuth is not supported. ``connect`` is a key of one of the customer's own
        supplier accounts, entered by the owner or an admin on the page: ``{"kind": "making_supplier", "supplier":
        "gelato" | "prodigi" | "printful" | "lulu"}``, ``{"kind": "telegram_bot", "account_id": ...}`` (an agent
        account's own Telegram bot) or ``{"kind": "post_address"}`` (the street address's mailbox.bot key).

        ``connection_name`` names the connection the link makes; see :meth:`connect`. It is sent beside
        ``service_id``, inside ``custom`` for a custom link, and refused with ``connect``.

        Returns the link (``link_id``, ``name``, ``provider``, ``service_id``, ``method`` ``oauth`` or ``key``,
        ``status``, ``connection_id``, ``expires_at``, ``created_at``, ``completed_at``) and ``url``, the
        only copy of the one-time URL: show it to the person, never log it. An agent context is refused.
        """
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
        return cast("dict[str, Any]", self._client.post("/v1/services/connect-links", json=body))

    def get_connect_link(self, link_id: str) -> dict[str, Any]:
        """The state of a connect link: ``pending``, ``connected`` (with ``connection_id``) or ``expired``.

        Never returns the URL.
        """
        return cast("dict[str, Any]", self._client.get(f"/v1/services/connect-links/{quote(link_id, safe='')}"))

    def list_connect_links(self) -> builtins.list[dict[str, Any]]:
        """The connect links still waiting for the person: ``pending`` and not yet expired, newest first, at most 50.

        Never returns a URL or a token.
        """
        answer = cast("dict[str, Any]", self._client.get("/v1/services/connect-links"))
        return cast("list[dict[str, Any]]", answer["links"])

    def rename(self, connection_id: str, connection_name: str) -> dict[str, Any]:
        """Rename a connection (owner or admin). A name is 1 to 40 characters: letters, digits, space and dash, and
        unique among the service's active connections for the same principal (409 otherwise)."""
        return cast(
            "dict[str, Any]",
            self._client.patch(
                f"/v1/services/{quote(connection_id, safe='')}", json={"connection_name": connection_name}
            ),
        )

    def verify(self, connection_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.post(f"/v1/services/{connection_id}/verify"))

    def disconnect(self, connection_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.delete(f"/v1/services/{connection_id}/disconnect"))

    def grant_agent_access(
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
        """Grant an agent access to a connected service.

        The GRANT is the authorization that lets an agent's passport reach
        the service (a self-declared intent can only narrow it, never grant
        it). ``service_connection_id`` is the id of the connection
        (from :meth:`list`), NOT the catalog service id. ``scopes`` is
        required by the API (min 1, subset of the connection's scopes) —
        pass the connection's own ``scopes`` for full access or a narrower
        subset.

        ``constraints`` are limits every call must meet. ``intents`` are named
        intents that expand to constraints (each ``{"name", "params"}``) and
        must all hold. ``alternatives`` are rules, each ``{"intents"?,
        "constraints"?}``, that each allow their own calls: a call must meet at
        least one, so a read rule and a post rule that names its channel can sit
        side by side. ``allow_data_from`` names the sources whose content may
        flow into this one: a service, or one connection of a service written
        ``service@<connection id>``. Content read through one connection of a
        service needs such an entry before it may go out through another
        connection of the same service.

        With hosted controls on and a policy that lists connections, the answer
        carries ``control_policy``: the connection is not callable until a
        revision of that policy lists it (``revision_needed``), a loosening a
        person approves in a browser (``stack.control_policies.set``).
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
        return cast("dict[str, Any]", self._client.post("/v1/services/grant", json=body))

    def revoke_agent_access(self, agent_id: str) -> dict[str, Any]:
        """Revoke all of an agent's service grants (and its active passports).

        A real kill switch: the agent's next passport carries no
        grant, so the credential lanes deny it regardless of declared intent.
        """
        return cast("dict[str, Any]", self._client.delete(f"/v1/services/agents/{agent_id}/revoke"))

    def get_agent_permissions(self, agent_id: str) -> dict[str, Any]:
        """List the service grants currently active for an agent."""
        return cast("dict[str, Any]", self._client.get(f"/v1/agents/{agent_id}/permissions"))
