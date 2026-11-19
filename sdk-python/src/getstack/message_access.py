"""Message access: what the account's agents may do with the customer's messages.

``read_teammates`` (default ``True``): the agent reads the messages of every message account of the customer, search
included; ``False`` limits it to its own. ``messages_read_only`` (default ``False``): when ``True`` the agent may read
but cannot send, reply, forward, text or post from any account. An agent's own value wins over the account's, and the
account's over the default. Owner or admin only; an agent is refused. A change applies at once and needs no approval.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

MESSAGE_ACCESS_KEYS = ("read_teammates", "messages_read_only")


def message_access_path(agent_id: str | None) -> str:
    """The route of the account's values, or of one agent's."""
    return "/v1/message-access" if agent_id is None else f"/v1/agents/{quote(agent_id, safe='')}/message-access"


def message_access_body(values: dict[str, bool | None]) -> dict[str, bool | None]:
    """The change to send; refuses an unknown key, a value that is not a boolean or ``None``, and an empty change."""
    if not values:
        raise ValueError("name read_teammates, messages_read_only or both")
    for key, value in values.items():
        if key not in MESSAGE_ACCESS_KEYS:
            raise ValueError("only read_teammates and messages_read_only can be set")
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{key} must be True, False or None")
    return dict(values)


class MessageAccessService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self, agent_id: str | None = None) -> dict[str, Any]:
        """``{agent_id, read_teammates, messages_read_only, effective, source}``: what is set at the scope and what
        is in force there."""
        return cast("dict[str, Any]", self._client.get(message_access_path(agent_id)))

    def set(
        self,
        agent_id: str | None = None,
        *,
        read_teammates: bool | None = None,
        messages_read_only: bool | None = None,
    ) -> dict[str, Any]:
        """Set the account's values, or (with ``agent_id``) one agent's, which win over the account's. A value left out
        is not touched; use ``clear`` to remove an agent's own value."""
        values: dict[str, bool | None] = {}
        if read_teammates is not None:
            values["read_teammates"] = read_teammates
        if messages_read_only is not None:
            values["messages_read_only"] = messages_read_only
        return cast("dict[str, Any]", self._client.put(message_access_path(agent_id), json=message_access_body(values)))

    def clear(self, agent_id: str, keys: list[str] | tuple[str, ...]) -> dict[str, Any]:
        """Remove the named values of an agent (``read_teammates``, ``messages_read_only``) so it follows the account
        again."""
        body = message_access_body(dict.fromkeys(keys))
        return cast("dict[str, Any]", self._client.put(message_access_path(agent_id), json=body))
