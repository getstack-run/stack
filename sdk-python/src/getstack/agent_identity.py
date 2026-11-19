"""Who an agent is, answered on request by STACK: public, so no credential is sent or needed.

The answer says which agent it is, whether its account is in use, and three yes-or-no facts of the owner who
stands behind it (identity verified and good standing); never its Passport, and nothing else of the
owner. An agent that does not exist, is closed, or whose owner switched the answer off is a ``NotFoundError``
(``AGENT_IDENTITY_NOT_FOUND``) that never says which.

Example::

    verified = stack.agent_identity.verified(key_id=keyid_of_the_signed_request)
    if verified["claims"]["identity"]["owner"]["good_standing"]:
        ...
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient
from .verify_agent_identity import verify_agent_identity

JWKS_PATH = "/v1/.well-known/jwks.json"


def lookup_params(key_id: str | None, site: str | None, agent_id: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """The query of a lookup and what a statement must say it answers. Exactly one of the three."""
    given = [(name, value) for name, value in (("key_id", key_id), ("site", site), ("agent_id", agent_id)) if value]
    if len(given) != 1:
        raise ValueError("pass exactly one of key_id, site or agent_id")
    name, value = given[0]
    return {name: value}, {name: value.lower() if name == "site" else value}


def agent_urls(base_url: str, agent_id: str) -> dict[str, str]:
    """Where an agent's lookup and machine files are, on STACK's own domain."""
    base = base_url.rstrip("/")
    agent = quote(agent_id, safe="")
    return {
        "lookup": f"{base}/v1/agent-identity?agent_id={agent}",
        "agent_card": f"{base}/v1/agent-identity/agents/{agent}/agent-card.json",
        "mcp_server_card": f"{base}/v1/agent-identity/agents/{agent}/mcp-server-card.json",
        "key_directory": f"{base}/v1/agent-identity/agents/{agent}/http-message-signatures-directory",
    }


def verified_result(claims: dict[str, Any]) -> dict[str, Any]:
    """The facts from a signed statement, never from the plain JSON beside it."""
    identity = claims["identity"]
    return {
        "claims": claims,
        "facts": {"agent": identity["agent"], "owner": identity["owner"], "lookup": identity["lookup"]},
        "valid_until": datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc),
    }


class AgentIdentityService:
    def __init__(self, client: HttpClient):
        self._client = client

    def lookup(
        self, *, key_id: str | None = None, site: str | None = None, agent_id: str | None = None
    ) -> dict[str, Any]:
        """Ask by the key id of a request the agent signed, the host name of its site, or its id. Returns the
        answer as served: ``statement`` (not checked: see ``verified``) and the same facts as JSON."""
        params, _ = lookup_params(key_id, site, agent_id)
        return cast("dict[str, Any]", self._client.public_request("GET", "/v1/agent-identity", params=params))

    def verified(
        self,
        *,
        key_id: str | None = None,
        site: str | None = None,
        agent_id: str | None = None,
        jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Ask, then check the statement against STACK's published keys (or the ``jwks`` you pin): signature,
        type, audience, issuer, expiry, and that it answers exactly what you asked. Returns ``claims``, ``facts``
        (from the signed statement) and ``valid_until``. Raises ``AgentIdentityVerificationError`` when it does not
        check out, and the API's error (``NotFoundError`` for an agent that is not found) otherwise."""
        params, expect = lookup_params(key_id, site, agent_id)
        answer = cast("dict[str, Any]", self._client.public_request("GET", "/v1/agent-identity", params=params))
        keys = jwks if jwks is not None else self._client.public_request("GET", JWKS_PATH)
        return verified_result(verify_agent_identity(answer["statement"], jwks=keys, now=now, expect=expect))

    def urls(self, agent_id: str) -> dict[str, str]:
        """The addresses of an agent's lookup and machine files (its signed A2A card, MCP server card and key
        directory)."""
        return agent_urls(self._client.base_url, agent_id)
