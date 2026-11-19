"""Governance service: read one approval.

A governance step-up asks a person to approve one exact change. The chat or the program that raised
it reads the approval to describe the change before it asks, and to follow its status afterwards.
Reading is all this does: the decision itself is made by a person in the dashboard, or confirmed in an
MCP chat client, never by a call from here.

Example::

    try:
        stack.billing.subscribe_platform()
    except GovernanceApprovalRequiredError as error:
        detail = stack.governance.get_approval(error.approval_id)
        print(detail["approval"]["summary"], detail["approval_url"])
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


class GovernanceService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        """One approval: ``{approval, payload_hash, approval_url}``.

        ``approval`` carries ``id``, ``action``, ``resource_id``, ``summary``, ``requested_via``,
        ``status`` (pending, approved, rejected, consumed or expired), ``expires_at``, ``created_at`` and
        ``decided_at``. ``payload_hash`` is the SHA-256 of the exact change it covers, which a chat
        confirmation binds to; ``approval_url`` is the approval's own page where a person decides. An
        approval of another account is a 404, never revealed; an agent context is refused.
        """
        path = f"/v1/governance/approvals/{quote(approval_id, safe='')}"
        return cast("dict[str, Any]", self._client.get(path))

    def list_approvals(self) -> dict[str, Any]:
        """The account's approvals as ``{approvals: [...]}``, newest first, up to the 100 the API holds.

        Each item has the fields of ``get_approval``'s ``approval``; a pending approval past its expiry
        reads as ``expired``. A list carries no link: ``get_approval`` returns one approval with its page.
        An agent context is refused.
        """
        return cast("dict[str, Any]", self._client.get("/v1/governance/approvals"))
