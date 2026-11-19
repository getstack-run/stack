"""Control policies and held-action reviews: what your agents' controls refuse, hold and limit.

A policy narrows what a connection grant already allows: it refuses, holds an action for a person, or
limits spend and volume. It never opens anything. One policy per agent and one default per customer are
kept by STACK and are never bound into a Passport. Every route denies agent contexts, so an agent can
never read or change its own controls. Writing a policy needs controls to be on (``set`` and
``start_from_current_access`` answer a 409 ``CONTROLS_NOT_ENABLED`` otherwise).

Tightening a policy applies at once. Loosening it, and deleting it, is a governance action: outside a
dashboard session the API answers ``GovernanceApprovalRequiredError`` with the approval link; a person
approves it in a browser and the same call is retried with ``governance_approval_id``. A revision that
is not provably a tightening counts as a loosening.

Recipients set per job: a connection rule (``allow``, naming a send intent with a recipient field) may carry
``"recipients": "per_mission"``. Each Mission then names who it may send to
(``stack.missions.open(..., recipients=[...])``); a send is allowed only inside a Mission that pins every recipient
field, and only to those values. A Mission without the pin is refused with reason ``recipients_not_pinned``, a send
to someone it did not pin with ``recipient_not_allowed``. A delegated Passport carries the same Mission, so it
carries the same recipients; the per-job rules of the agent the Mission was opened for apply to it too. A send rule
that names no recipients and is not set per job is refused when written (``UnboundedSendRuleError``).

The account's own ``recipients.email``, ``recipients.sms`` and ``recipients.call`` take a list or ``"per_mission"``
too. Under ``"per_mission"`` an email, text or call must name the received message it answers
(``reply_to_message`` on ``accounts.send_email``, ``send_sms`` and ``calls.place``) and goes only to who wrote it
(``reply_email``: the message in the path is the pin, with ``reply_all`` also the original's own To and Cc;
``forward_email`` has none). A send that names no message is refused with reason ``recipients_not_pinned``, a
recipient other than the sender with ``recipient_not_allowed``, and an id that is not one of the account's received
messages is a ``NotFoundError``. Changing a list to ``"per_mission"``, or back, is a loosening; setting it where
there was no rule is a tightening.

A refused action raises ``ControlDeniedError`` whose ``rule`` names which rule refused (never a value the
call carried); an action held for a person carries ``retry`` (``ref`` and ``after_seconds``) and is
retried with header ``X-Control-Ref``. A spend limit reached while paying raises
``ControlLimitExceededError``. A held action shows up in ``stack.control_reviews``; it is decided through
the ordinary governance approval (the approve page), never here.

Example::

    current = stack.control_policies.start_from_current_access("agt_1")["policy"]
    definition = {**current["definition"], "spend": {"max_per_action_cents": 500}}
    stack.control_policies.set("agt_1", definition, expected_revision=current["revision"])  # tightens
    result = stack.control_policies.simulate({"action": "card.checkout", "amount_cents": 900}, agent_id="agt_1")
    print(result["verdict"], result["refusal"])
    for review in stack.control_reviews.list()["reviews"]:
        print(review["id"], review["summary"], review["approval_url"])
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

DEFAULT_SCOPE = "default"
# A rule with this value leaves who a send may go to to each Mission.
POLICY_RECIPIENTS_PER_MISSION = "per_mission"
REVIEW_STATUSES = ("pending", "all")


def _approval(governance_approval_id: str | None) -> dict[str, str] | None:
    return {"X-Governance-Approval": governance_approval_id} if governance_approval_id is not None else None


def _scope_path(scope: str) -> str:
    """``default`` for the customer's default policy, else an agent id."""
    if not isinstance(scope, str) or not scope:
        raise ValueError("scope must be 'default' or an agent id")
    return "/v1/control-policies/default" if scope == DEFAULT_SCOPE else _agent_path(scope)


def _agent_path(agent_id: str) -> str:
    if not isinstance(agent_id, str) or not agent_id or agent_id == DEFAULT_SCOPE:
        raise ValueError("agent_id must be an agent id")
    return f"/v1/control-policies/agents/{quote(agent_id, safe='')}"


def _start_path(agent_id: str) -> str:
    return f"{_agent_path(agent_id)}/start-from-current-access"


def _revisions_path(policy_id: str) -> str:
    if not isinstance(policy_id, str) or not policy_id:
        raise ValueError("policy_id must be a policy id")
    return f"/v1/control-policies/{quote(policy_id, safe='')}/revisions"


def _set_body(definition: dict[str, Any], expected_revision: int | None) -> dict[str, Any]:
    if not isinstance(definition, dict):
        raise ValueError("definition must be a policy definition (a dict)")
    body: dict[str, Any] = {"definition": definition}
    if expected_revision is not None:
        body["expected_revision"] = expected_revision
    return body


def _delete_params(expected_revision: int | None) -> dict[str, Any] | None:
    return {"expected_revision": expected_revision} if expected_revision is not None else None


def _simulate_body(call: dict[str, Any], agent_id: str | None, definition: dict[str, Any] | None) -> dict[str, Any]:
    if agent_id is None and definition is None:
        raise ValueError("Name an agent_id or give a definition to try the call against")
    if not isinstance(call, dict) or not call.get("action"):
        raise ValueError("call must be a dict with an action")
    body: dict[str, Any] = {"call": call}
    if agent_id is not None:
        body["agent_id"] = agent_id
    if definition is not None:
        body["definition"] = definition
    return body


def _review_params(status: str | None, limit: int | None) -> dict[str, Any] | None:
    if status is not None and status not in REVIEW_STATUSES:
        raise ValueError("status must be 'pending' or 'all'")
    params: dict[str, Any] = {}
    if status is not None:
        params["status"] = status
    if limit is not None:
        params["limit"] = limit
    return params or None


def _review_path(review_id: str) -> str:
    if not isinstance(review_id, str) or not review_id:
        raise ValueError("review_id must be a review id")
    return f"/v1/control-reviews/{quote(review_id, safe='')}"


class ControlPoliciesService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(self) -> dict[str, Any]:
        """Every policy of the customer: ``{"controls_enabled": bool, "policies": [...]}``.

        Each policy carries ``id``, ``agent_id`` (``None`` for the default), ``name``, ``revision``,
        ``definition``, ``last_change``, ``findings`` (sends the policy allows without naming who receives
        them), ``created_at`` and ``updated_at``.
        """
        return cast("dict[str, Any]", self._client.request("GET", "/v1/control-policies"))

    def get(self, scope: str) -> dict[str, Any]:
        """One policy. ``scope`` is ``"default"`` or an agent id.

        The default is the policy itself (a 404 ``NotFoundError`` when there is none). An agent id returns
        ``{"policy", "in_force", "controls_enabled"}``: the agent's own policy (``None`` when it has none),
        and the one in force for it (``id``, ``revision`` and ``source``: ``agent`` or ``default``).
        """
        return cast("dict[str, Any]", self._client.request("GET", _scope_path(scope)))

    def set(
        self,
        scope: str,
        definition: dict[str, Any],
        *,
        expected_revision: int | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Create or revise a policy: ``{"change", "policy"}``. ``scope`` is ``"default"`` or an agent id.

        Leave ``expected_revision`` out to create; pass the revision you read to revise (a stale one is
        refused). Tightening applies at once. A loosening, or a revision that is not provably a tightening,
        raises ``GovernanceApprovalRequiredError``: a person approves it in a browser, then retry the same
        call with ``governance_approval_id``. A policy that allows a send without naming who receives it
        raises ``UnboundedSendRuleError``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                _scope_path(scope),
                json=_set_body(definition, expected_revision),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def delete(
        self,
        scope: str,
        *,
        expected_revision: int | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Delete a policy: ``{"change": "delete", "policy": None}``. ``scope`` is ``"default"`` or an agent id.

        Deleting loosens, so it is a governance action: retry with ``governance_approval_id`` once a
        person has approved it in a browser.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "DELETE",
                _scope_path(scope),
                params=_delete_params(expected_revision),
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def start_from_current_access(self, agent_id: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """A policy equal to the agent's current connection grants: ``{"change", "policy"}``.

        It changes no outcome until you tighten it. Replacing an existing policy can loosen it, which is a
        governance action: retry with ``governance_approval_id``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST", _start_path(agent_id), json={}, extra_headers=_approval(governance_approval_id)
            ),
        )

    def simulate(
        self,
        call: dict[str, Any],
        *,
        agent_id: str | None = None,
        definition: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Try one call against a policy. Nothing is counted, held or sent.

        ``call`` is ``{"action", "target", "amount_cents", "request", "connection_id", "mission_id",
        "reply_to_message"}`` with ``action`` required (``request`` is ``{"method", "url", "body", "query"}``
        for ``proxy.call``; ``mission_id`` is a Mission (``ms_...``): the call is tried with the recipients that
        Mission pinned; ``reply_to_message`` tries the account's own ``email.send``, ``sms.send`` or
        ``call.start`` as answering that stored message, as a live send does, and needs ``agent_id``). Name an
        ``agent_id`` (its own policy, else the default) or give a draft ``definition`` to try instead.
        Returns ``verdict`` (allow, review or deny), ``policy``, ``refusal`` (which rule refused, never a
        value from the call), ``message``, ``limits`` (each with ``used`` and ``remaining``),
        ``controls_enabled`` and ``checked``.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST", "/v1/control-policies/simulate", json=_simulate_body(call, agent_id, definition)
            ),
        )

    def revisions(self, policy_id: str) -> dict[str, Any]:
        """The revisions of a policy, newest first: ``{"revisions": [...]}``.

        Each has ``revision``, ``change``, ``actor``, ``approval_id``, ``definition`` and ``created_at``.
        """
        return cast("dict[str, Any]", self._client.request("GET", _revisions_path(policy_id)))


class ControlReviewsService:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(self, *, status: str | None = None, limit: int | None = None) -> dict[str, Any]:
        """Actions a policy held for a person: ``{"reviews": [...]}``.

        ``status`` is ``"pending"`` (the default) or ``"all"``; ``limit`` is 1 to 200 (default 50). Each
        review has ``id``, ``account_id``, ``agent_id``, ``policy_id``, ``policy_revision``,
        ``action_type``, ``summary``, ``status``, ``approval_id``, ``approval_url``, ``expires_at`` and
        ``created_at``. A review is decided at its ``approval_url`` (a person, in a browser), never here.
        """
        return cast(
            "dict[str, Any]", self._client.request("GET", "/v1/control-reviews", params=_review_params(status, limit))
        )

    def get(self, review_id: str) -> dict[str, Any]:
        """One held action."""
        return cast("dict[str, Any]", self._client.request("GET", _review_path(review_id)))
