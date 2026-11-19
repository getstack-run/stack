"""The trust switch: whether the account's agents ask first or are trusted to act.

``ask_first``: what needs a person waits for one. ``trust_agents``: nothing waits for a person on card purchases,
orders on the customer's own supplier account, and governance changes made with the owner's own API key. In both, a
wallet balance or spend limit, a revoked or suspended agent, a control policy's review rule and the browser-only
actions still apply. A new account starts on ``trust_agents``. Owner or admin only; an agent is refused. It is not
part of any control policy. A change that makes a scope trust where it asked first before needs a person's approval
(``trust_widen``: 403 ``GOVERNANCE_APPROVAL_REQUIRED`` with the approval link; retry with ``governance_approval_id``
once it is approved); a change to ``ask_first`` applies at once. Every change is recorded in the audit log.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

TRUST_VALUES = ("ask_first", "trust_agents")


def trust_path(agent_id: str | None) -> str:
    """The route of the account's value, or of one agent's."""
    return "/v1/trust" if agent_id is None else f"/v1/agents/{quote(agent_id, safe='')}/trust"


def trust_body(trust: str | None, agent_id: str | None) -> dict[str, str | None]:
    """The change to send; refuses an unknown value, or no value for the account, before any request."""
    if trust is None:
        if agent_id is None:
            raise ValueError("the account's trust must be ask_first or trust_agents")
    elif trust not in TRUST_VALUES:
        raise ValueError("trust must be ask_first or trust_agents")
    return {"trust": trust}


class TrustService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self, agent_id: str | None = None) -> dict[str, Any]:
        """``{agent_id, trust, effective, source}``: what is set at the scope and what is in force there."""
        return cast("dict[str, Any]", self._client.get(trust_path(agent_id)))

    def set(self, trust: str, agent_id: str | None = None, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Set the account's value, or (with ``agent_id``) one agent's, which wins over the account's."""
        return cast(
            "dict[str, Any]",
            self._client.put(
                trust_path(agent_id), json=trust_body(trust, agent_id), extra_headers=_approval(governance_approval_id)
            ),
        )

    def clear(self, agent_id: str, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Remove an agent's own value so it follows the account again."""
        return cast(
            "dict[str, Any]",
            self._client.put(
                trust_path(agent_id), json=trust_body(None, agent_id), extra_headers=_approval(governance_approval_id)
            ),
        )


def _approval(governance_approval_id: str | None) -> dict[str, str] | None:
    """The header that carries a person's approval on the retry."""
    return {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
