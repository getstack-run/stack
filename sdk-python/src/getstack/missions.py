"""Mission lifecycle — open / start / complete / revoke / get / list.

Every passport is issued for exactly one Mission and never outlives it.

  open()      Open a new mission. Returns mission_id (ms_*) + the
              signed mission_open claim_id. Pass ``agent_id`` to assign
              it to an agent; then issue with
              ``stack.passports.issue(..., mission_ids=[mission_id])``.
  start()     Open a mission and issue its agent's passport in one call
              (operator form: ``agent_id`` + ``mission`` + optional
              ``passport``). If issuance fails the API revokes the
              mission. The fleet form (a dict with ``fleet_policy_id``)
              is unchanged.
  complete()  Mark a mission complete (terminal_state='completed_successful').
              Revokes every passport bound to it. Idempotent; second call
              returns the prior terminal state.
  revoke()    Revoke a mission. Every passport bound to it is revoked,
              whatever the reason ('adversarial' or
              'operator_initiated_clean').
  get()       Fetch full mission view by id (``recipient_pins`` is who it may send to, or ``None``).
  list()      List missions for the calling operator.

Recipients: who a Mission may send to. A policy rule that leaves recipients to each Mission
(``recipients: "per_mission"``) allows a send only to these. ``open()`` takes ``recipients`` (exact addresses,
numbers or ids, applied at every recipient field a send names), ``recipient_pins`` (``[{"path", "op", "value"}]``,
``op`` ``"eq"`` or ``"in"``, one pin per path; ``path`` is ``"*"`` or a request field such as ``body.to``) and
``reply_to_message`` (the id of a message the agent's account received, or of an incoming call it answered or
declined: the Mission is pinned to its sender or caller, so the agent can answer that person and no one else). The
operator form of ``start()`` takes the same keys inside ``mission``. ``add_recipients()`` adds to the pins of a
running Mission (the owner's call).
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

# A pin on this path applies to every recipient field a send names, except one that is part of the URL.
MISSION_RECIPIENT_ANY_PATH = "*"


def _recipient_fields(
    recipients: list[str] | None,
    recipient_pins: list[dict[str, Any]] | None,
    reply_to_message: str | None,
) -> dict[str, Any]:
    """The recipient fields of a Mission open, only those given."""
    fields: dict[str, Any] = {}
    if recipients is not None:
        fields["recipients"] = recipients
    if recipient_pins is not None:
        fields["recipient_pins"] = recipient_pins
    if reply_to_message is not None:
        fields["reply_to_message"] = reply_to_message
    return fields


def _start_body(
    request: dict[str, Any] | None,
    agent_id: str | None,
    mission: dict[str, Any] | None,
    passport: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the POST /v1/missions/start body for either form."""
    if request is not None:
        if agent_id is not None or mission is not None or passport is not None:
            raise ValueError(
                "missions.start: pass either a request dict (fleet form) or "
                "agent_id + mission (operator form), not both"
            )
        return request
    if agent_id is None or mission is None:
        raise ValueError("missions.start: the operator form needs agent_id and mission (a dict with intent_summary)")
    body: dict[str, Any] = {"agent_id": agent_id, "mission": mission}
    if passport is not None:
        body["passport"] = passport
    return body


class MissionsService:
    def __init__(self, client: HttpClient):
        self._client = client

    def start(
        self,
        request: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
        mission: dict[str, Any] | None = None,
        passport: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Open a Mission and issue its passport in one call.

        Operator form::

            started = stack.missions.start(
                agent_id="agt_x",
                mission={"intent_summary": "Triage inbox", "intent_services": ["gmail"]},
                passport={"ttl_seconds": 900},  # optional issue fields
            )
            token = started["passport"]["token"]

        Returns ``mission_id``, ``claim_id``, ``expires_at`` and
        ``passport`` (``token``, ``jti``, ``expires_at``). If issuance
        fails the API revokes the Mission before returning the error.

        Fleet form (unchanged): ``stack.missions.start({"fleet_policy_id": ..., ...})``.
        """
        body = _start_body(request, agent_id, mission, passport)
        return cast("dict[str, Any]", self._client.request("POST", "/v1/missions/start", json=body))

    def renew(self, mission_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", self._client.request("POST", f"/v1/missions/{quote(mission_id, safe='')}/renew", json={})
        )

    def open(
        self,
        intent_summary: str,
        *,
        intent_services: list[str] | None = None,
        expected_counterparties: list[str] | None = None,
        baseline_profile: dict[str, Any] | None = None,
        expected_output_shape: dict[str, Any] | None = None,
        max_actions: int | None = None,
        max_dropoff_bytes: int | None = None,
        coverage_cap_cents: int | None = None,
        max_duration_seconds: int | None = None,
        max_concurrent_intents: int | None = None,
        max_actions_per_service: dict[str, int] | None = None,
        cap_behavior: dict[str, str] | None = None,
        coverage_cap_period: str | None = None,
        cap_time_zone: str | None = None,
        making_orders_up_to_cents: int | None = None,
        expires_in_seconds: int | None = None,
        parent_passport_services: list[str] | None = None,
        fleet_policy_id: str | None = None,
        idempotency_key: str | None = None,
        requested_access: list[dict[str, Any]] | None = None,
        requested_operations: list[dict[str, Any]] | None = None,
        limits: dict[str, Any] | None = None,
        authority_binding_ids: list[str] | None = None,
        agent_id: str | None = None,
        recipients: list[str] | None = None,
        recipient_pins: list[dict[str, Any]] | None = None,
        reply_to_message: str | None = None,
    ) -> dict[str, Any]:
        """Open a new mission. Returns dict with mission_id, claim_id,
        expires_at. ``agent_id`` assigns the mission to that agent (Connect
        grants must pass it).

        Recipients: who this Mission may send to. A policy rule that leaves recipients to each Mission allows a
        send only to these. ``recipients`` lists exact addresses, numbers or ids (an address may be in any case);
        ``recipient_pins`` is ``[{"path": "body.to", "op": "in", "value": [...]}]``; ``reply_to_message`` is the id
        of a message the agent's account received (an email, text or voicemail, else 404): it pins the Mission to
        the sender of that message, so the agent can answer that person and no one else.

        Caps: ``cap_behavior`` maps a cap to ``pause`` (the default for every cap: the Mission is paused, every action
        under it is refused with ``MISSION_PAUSED`` until the owner reviews it with ``review``), ``refuse_action`` or
        ``end_mission``. ``coverage_cap_period`` is ``mission`` (default) or ``day``, the day ending at midnight in
        ``cap_time_zone`` (IANA, default UTC). ``making_orders_up_to_cents`` is what the owner pre-approves of the
        Mission's print-on-demand orders, in cents across all of them; only the owner or an admin sets it.
        """
        body: dict[str, Any] = {"intent_summary": intent_summary}
        if agent_id is not None:
            body["agent_id"] = agent_id
        if intent_services is not None:
            body["intent_services"] = intent_services
        if expected_counterparties is not None:
            body["expected_counterparties"] = expected_counterparties
        if baseline_profile is not None:
            body["baseline_profile"] = baseline_profile
        if expected_output_shape is not None:
            body["expected_output_shape"] = expected_output_shape
        if max_actions is not None:
            body["max_actions"] = max_actions
        if max_dropoff_bytes is not None:
            body["max_dropoff_bytes"] = max_dropoff_bytes
        if coverage_cap_cents is not None:
            body["coverage_cap_cents"] = coverage_cap_cents
        if max_duration_seconds is not None:
            body["max_duration_seconds"] = max_duration_seconds
        if max_concurrent_intents is not None:
            body["max_concurrent_intents"] = max_concurrent_intents
        if max_actions_per_service is not None:
            body["max_actions_per_service"] = max_actions_per_service
        if cap_behavior is not None:
            body["cap_behavior"] = cap_behavior
        if coverage_cap_period is not None:
            body["coverage_cap_period"] = coverage_cap_period
        if cap_time_zone is not None:
            body["cap_time_zone"] = cap_time_zone
        if making_orders_up_to_cents is not None:
            body["making_orders_up_to_cents"] = making_orders_up_to_cents
        if expires_in_seconds is not None:
            body["expires_in_seconds"] = expires_in_seconds
        if parent_passport_services is not None:
            body["parent_passport_services"] = parent_passport_services
        for key, value in {
            "fleet_policy_id": fleet_policy_id,
            "idempotency_key": idempotency_key,
            "requested_access": requested_access,
            "requested_operations": requested_operations,
            "limits": limits,
            "authority_binding_ids": authority_binding_ids,
        }.items():
            if value is not None:
                body[key] = value
        body.update(_recipient_fields(recipients, recipient_pins, reply_to_message))
        return cast("dict[str, Any]", self._client.request("POST", "/v1/missions", json=body))

    def complete(
        self,
        mission_id: str,
        *,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Mark a mission complete and revoke every passport bound to it.
        Returns dict with mission_id, claim_id, terminal_state,
        completed_at, transitioned."""
        body: dict[str, Any] = {}
        if output is not None:
            body["output"] = output
        return cast("dict[str, Any]", self._client.request("POST", f"/v1/missions/{mission_id}/complete", json=body))

    def revoke(
        self,
        mission_id: str,
        *,
        reason: str,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Revoke a mission. reason in {'adversarial', 'operator_initiated_clean'}.
        Either reason revokes every passport bound to the mission."""
        body: dict[str, Any] = {"reason": reason}
        if notes is not None:
            body["notes"] = notes
        return cast("dict[str, Any]", self._client.request("POST", f"/v1/missions/{mission_id}/revoke", json=body))

    def add_recipients(
        self,
        mission_id: str,
        *,
        recipients: list[str] | None = None,
        recipient_pins: list[dict[str, Any]] | None = None,
        reply_to_message: str | None = None,
    ) -> dict[str, Any]:
        """Add who a running Mission may send to, merged into the pins it has (nothing pinned is taken away).

        The owner's call; an agent's own credential is refused. ``reply_to_message`` names a message the agent received,
        or an incoming call it answered or declined (``acall_*``). Returns ``mission_id`` and the ``recipient_pins`` the
        Mission holds now. 409 for a Mission that has ended."""
        body = _recipient_fields(recipients, recipient_pins, reply_to_message)
        if not body:
            raise ValueError("name recipients, recipient_pins or reply_to_message")
        return cast("dict[str, Any]", self._client.request("POST", f"/v1/missions/{mission_id}/recipients", json=body))

    def get(self, mission_id: str) -> dict[str, Any]:
        """Fetch a mission by id. 404 for unknown or cross-tenant."""
        return cast("dict[str, Any]", self._client.request("GET", f"/v1/missions/{mission_id}"))

    def list(
        self,
        *,
        status: str | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List missions for the calling operator. Returns dict with `items`."""
        params: dict[str, Any] = {}
        if status is not None:
            params["status"] = status
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit
        path = "/v1/missions"
        if params:
            from urllib.parse import urlencode

            path = f"{path}?{urlencode(params)}"
        return cast("dict[str, Any]", self._client.request("GET", path))

    def review(self, mission_id: str, decision: str, *, limit: int | None = None) -> dict[str, Any]:
        """Decide a Mission one of its caps paused: ``raise`` (with ``limit``, the new limit of the cap that paused it,
        above the old one), ``continue`` (its limits as they are; a cap with no room left pauses it again) or ``close``
        (it ends). The agent the Mission was opened for is told the decision. The owner's or a member's own decision."""
        if decision not in ("raise", "continue", "close"):
            raise ValueError("decision must be raise, continue or close")
        if (decision == "raise") != (limit is not None):
            raise ValueError("raise needs the new limit, and only raise takes one")
        body: dict[str, Any] = {"decision": decision}
        if limit is not None:
            body["limit"] = limit
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"/v1/missions/{quote(mission_id, safe='')}/review", json=body),
        )

    def set_making_allowance(self, mission_id: str, making_orders_up_to_cents: int | None) -> dict[str, Any]:
        """Set what the owner pre-approves of a running Mission's print-on-demand orders, in cents across all of them;
        ``None`` removes it. The owner or an admin only. Returns the Mission."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                f"/v1/missions/{quote(mission_id, safe='')}/making-allowance",
                json={"making_orders_up_to_cents": making_orders_up_to_cents},
            ),
        )

    # Mission activity and Operator review reads.

    def activity(self, mission_id: str) -> dict[str, Any]:
        """Return the current recorded activity for a mission."""
        return cast("dict[str, Any]", self._client.request("GET", f"/v1/missions/{quote(mission_id, safe='')}/replay"))

    def replay(self, mission_id: str) -> dict[str, Any]:
        """Compatibility alias for activity()."""
        return self.activity(mission_id)

    def list_operator_reviews(self, mission_id: str) -> dict[str, Any]:
        """List signed Operator review revisions for a mission."""
        return cast(
            "dict[str, Any]", self._client.request("GET", f"/v1/missions/{quote(mission_id, safe='')}/operator-reviews")
        )

    def download_operator_review(self, mission_id: str, claim_id: str) -> bytes:
        """Download the exact signed COSE bytes for one Operator review."""
        return self._client.request_bytes(
            "GET",
            f"/v1/missions/{quote(mission_id, safe='')}/operator-reviews/{quote(claim_id, safe='')}/download",
        )

    def list_dossiers(self, mission_id: str) -> dict[str, Any]:
        """List old dossier claims with the pre-Operator-review response shape."""
        reviews = self.list_operator_reviews(mission_id)
        return {
            "items": [
                {
                    "claim_id": item.get("claim_id"),
                    "operator_id": item.get("operator_id"),
                    "issued_at_ms": item.get("issued_at_ms"),
                    "body": item.get("claim", item.get("body")),
                }
                for item in reviews.get("items", [])
                if item.get("claim", item.get("body", {})).get("type") == "dossier"
            ]
        }
