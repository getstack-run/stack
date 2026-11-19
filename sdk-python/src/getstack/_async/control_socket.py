"""Async ControlSocketService mirror: where an account's actions are decided and its record streamed."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..control_socket import (
    _approval,
    _checked_types_body,
    _decision_address_body,
    _decision_params,
    _decision_path,
    _mode_body,
    _on_unavailable_body,
    _target,
)


class AsyncControlSocketService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self) -> dict[str, Any]:
        """The socket as configured, with who decides now."""
        return cast("dict[str, Any]", await self._client.request("GET", "/v1/control-socket"))

    async def set_decision_address(
        self, url: str, timeout_ms: int | None = None, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """Set or change the decision address: ``{socket, secret}``, the secret shown once. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                "/v1/control-socket/decision",
                json=_decision_address_body(url, timeout_ms),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def set_events_address(self, url: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Set or change the events address: ``{socket, secret}``, the secret shown once. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                "/v1/control-socket/events",
                json={"url": url},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def clear(self, target: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Clear the ``decision`` or ``events`` address and return the socket. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "DELETE",
                f"/v1/control-socket/{_target(target)}",
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def verify(self, target: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """The setup check; a passing one puts the address into use. Loosening needs an approval."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/control-socket/{_target(target)}/verify",
                json={},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def test(self, target: str) -> dict[str, Any]:
        """One test exchange with the address; nothing changes."""
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/control-socket/{_target(target)}/test", json={}),
        )

    async def rotate_secret(self, target: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """A new signing secret: ``{target, secret, previous_valid_until}``. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/control-socket/{_target(target)}/secret/rotate",
                json={},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def set_mode(self, mode: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """STACK's ``hosted`` controls, or ``none``; returns the socket. Loosening needs an approval."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT", "/v1/control-socket/mode", json=_mode_body(mode), extra_headers=_approval(governance_approval_id)
            ),
        )

    async def set_on_unavailable(
        self, on_unavailable: str, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """What happens when your own server does not answer in time (``"refuse"`` or ``"allow"``).

        ``"allow"`` needs an approval.
        """
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                "/v1/control-socket/on-unavailable",
                json=_on_unavailable_body(on_unavailable),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def set_checked_types(
        self, types: list[str] | None, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """Which action kinds are checked (``None`` for every kind); returns the socket. Loosening needs an approval."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "PUT",
                "/v1/control-socket/checked-types",
                json=_checked_types_body(types),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def list_decisions(
        self,
        *,
        limit: int | None = None,
        account_id: str | None = None,
        verdict: str | None = None,
        before: str | None = None,
    ) -> dict[str, Any]:
        """The decisions made, newest first: ``{"decisions": [...]}``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "GET", "/v1/control-decisions", params=_decision_params(limit, account_id, verdict, before)
            ),
        )

    async def get_decision(self, decision_id: str) -> dict[str, Any]:
        """One decision, with the request as sent when it was kept."""
        return cast("dict[str, Any]", await self._client.request("GET", _decision_path(decision_id)))
