"""Control socket service: who decides for your agents, and where their record is streamed.

One socket per account. The decision address is your own server: STACK sends it every checked action
of your agents and an allow or deny from it decides each one. The events address receives your agents'
whole record, signed. Both are signed with Standard Webhooks (see ``getstack.control_server`` for the
helpers that verify a request and sign an answer on your side).

Every change is an owner or admin decision and never an agent's. A new address, a secret rotation and
anything that loosens (clearing an enforcing address, unchecking an action kind, switching to no
controls or to your own server) is a governance action: outside a dashboard session the API answers
``GovernanceApprovalRequiredError``. Retry the same call with ``governance_approval_id`` once it is
approved. Tightening applies at once.

Example::

    change = stack.control_socket.set_decision_address("https://decide.example.com/stack")
    secret = change["secret"]  # shown once; store it now
    result = stack.control_socket.verify("decision")  # a passing check puts the address into use
    print(result["verdict"], result["activated"])
    for decision in stack.control_socket.list_decisions(verdict="deny")["decisions"]:
        print(decision["id"], decision["action_type"], decision["reason_code"])
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

TARGETS = ("decision", "events")
MODES = ("none", "hosted")


def _approval(governance_approval_id: str | None) -> dict[str, str] | None:
    return {"X-Governance-Approval": governance_approval_id} if governance_approval_id is not None else None


def _target(target: str) -> str:
    if target not in TARGETS:
        raise ValueError("target must be 'decision' or 'events'")
    return target


def _decision_address_body(url: str, timeout_ms: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {"url": url}
    if timeout_ms is not None:
        body["timeout_ms"] = timeout_ms
    return body


def _mode_body(mode: str) -> dict[str, str]:
    if mode not in MODES:
        raise ValueError("mode must be 'none' or 'hosted'; your own server is switched on by verifying its address")
    return {"mode": mode}


def _on_unavailable_body(on_unavailable: str) -> dict[str, Any]:
    return {"on_unavailable": on_unavailable}


def _checked_types_body(types: list[str] | None) -> dict[str, Any]:
    return {"types": None if types is None else list(types)}


def _decision_params(
    limit: int | None, account_id: str | None, verdict: str | None, before: str | None
) -> dict[str, Any] | None:
    params: dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if account_id is not None:
        params["account_id"] = account_id
    if verdict is not None:
        params["verdict"] = verdict
    if before is not None:
        params["before"] = before
    return params or None


def _decision_path(decision_id: str) -> str:
    return f"/v1/control-decisions/{quote(decision_id, safe='')}"


class ControlSocketService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self) -> dict[str, Any]:
        """The socket as configured, with who decides now.

        Carries ``socket_id``, ``mode_setting`` (auto, none, hosted, remote), ``effective_mode`` (none,
        hosted, remote: ``remote`` only while the decision address is enforcing), ``controls_enabled``,
        ``decision`` and ``events`` (each with ``url``, ``pending_url``, ``status``, ``verified_at``,
        ``secret_set``, ``secret_rotated_at``; ``decision`` adds ``timeout_ms``, ``events`` adds
        ``last_acknowledged_seq``, ``pending_events``, ``dead_events`` and ``last_error``),
        ``checked_types`` and ``checks_all_types``. Never a secret.
        """
        return cast("dict[str, Any]", self._client.request("GET", "/v1/control-socket"))

    def set_decision_address(
        self, url: str, timeout_ms: int | None = None, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """Set or change the decision address: ``{socket, secret}``.

        ``secret`` (``whsec_...``) is present only when this call created the signing secret, and is not
        shown again. A caller signed in with OAuth (a browser sign-in) is never given it: ``secret`` is
        ``None`` and ``secret_reveal`` (``{url, expires_at}``) is a single-use Console link where the
        signed-in person reads it once. A new address is unverified and decides nothing until
        ``verify("decision")`` passes.
        ``timeout_ms`` is 300 to 2000. A governance action: retry with ``governance_approval_id``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                "/v1/control-socket/decision",
                json=_decision_address_body(url, timeout_ms),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def set_events_address(self, url: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Set or change the events address: ``{socket, secret}``, the secret shown once. A governance action."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                "/v1/control-socket/events",
                json={"url": url},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def clear(self, target: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Clear the ``decision`` or ``events`` address and return the socket. A governance action."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "DELETE",
                f"/v1/control-socket/{_target(target)}",
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def verify(self, target: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """The setup check; a passing one puts the address into use.

        Returns ``{target, ok, latency_ms, verdict, cause, activated}``. Switching to your own server
        from hosted controls or none loosens, so it is a governance action: retry with
        ``governance_approval_id``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/control-socket/{_target(target)}/verify",
                json={},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def test(self, target: str) -> dict[str, Any]:
        """One test exchange with the address; nothing changes. Same result shape as ``verify``."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"/v1/control-socket/{_target(target)}/test", json={}),
        )

    def rotate_secret(self, target: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """A new signing secret: ``{target, secret, secret_reveal, previous_valid_until}``.

        The secret is shown once (an OAuth sign-in gets ``secret_reveal``, a Console link, instead); the old one
        keeps verifying until ``previous_valid_until``, 24 hours
        on. A governance action: retry with ``governance_approval_id``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/control-socket/{_target(target)}/secret/rotate",
                json={},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def set_mode(self, mode: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """STACK's ``hosted`` controls, or ``none``; returns the socket.

        Your own server is switched on by verifying its address, not here. Turning controls off, or
        leaving your own server for hosted controls, is a governance action: retry with
        ``governance_approval_id``. ``hosted`` needs a controls subscription.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT", "/v1/control-socket/mode", json=_mode_body(mode), extra_headers=_approval(governance_approval_id)
            ),
        )

    def set_on_unavailable(self, on_unavailable: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """What happens when your own decision server does not answer in time: ``"refuse"`` (default) or ``"allow"``.

        Only an answer that never came follows it (no answer in time, unreachable, a non-200 answer, a busy server, an
        open breaker); a forged or garbled answer and a server not verified or paused are refused whatever it says.
        ``"allow"`` loosens a control, so it is a governance action: retry with ``governance_approval_id``;
        ``"refuse"`` applies at once. Returns the socket.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                "/v1/control-socket/on-unavailable",
                json=_on_unavailable_body(on_unavailable),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def set_checked_types(
        self, types: list[str] | None, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """Which action kinds are checked, e.g. ``["email.send", "card.checkout"]``; returns the socket.

        ``None`` checks every kind, including kinds added later. An unchecked kind goes through with no
        decision, so removing a kind is a governance action: retry with ``governance_approval_id``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                "/v1/control-socket/checked-types",
                json=_checked_types_body(types),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def list_decisions(
        self,
        *,
        limit: int | None = None,
        account_id: str | None = None,
        verdict: str | None = None,
        before: str | None = None,
    ) -> dict[str, Any]:
        """The decisions made, newest first: ``{"decisions": [...]}``.

        ``verdict`` is allow, deny or unavailable; ``limit`` is 1 to 200 (default 50). Page back with
        ``before``, the ``created_at`` of the last decision of the previous page.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET", "/v1/control-decisions", params=_decision_params(limit, account_id, verdict, before)
            ),
        )

    def get_decision(self, decision_id: str) -> dict[str, Any]:
        """One decision. ``request`` is the request as sent, kept for a refusal or an unreachable server."""
        return cast("dict[str, Any]", self._client.request("GET", _decision_path(decision_id)))
