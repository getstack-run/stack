"""Wake-ups: what starts an agent with a task.

Every agent of the customer has its own wake-ups, with or without an agent account, so the wake calls take the
agent's id. An account's agent is also woken by its mail,
texts, Telegram messages to its bot, voicemail, call transcripts, a call ringing on its number (the source
``incoming_call``: answer or decline
it with ``stack.accounts.calls``), payments received, post and calendar events reaching their start; any
agent by its schedule, a drop-off another of the customer's agents left for it, and the end of a pending item it
waited on (the source ``decision``: ``event["item_kind"]``, ``event["item_id"]`` and ``event["result"]``). Nothing
wakes an agent for mail, texts, Telegram messages, voicemail, calls or payments until the owner says so (a call ringing
on its number,
a schedule, a calendar event, a drop-off and a decision need no rule): a rule per source (and optionally per
sender or amount) names the task, in the owner's own words. The event's text is never put into a task. Each wake is
one action on the meter and an account's agent's wake is put to your decider as ``wake.deliver``.

A wake reaches the agent, in the order you prefer, by an MCP notification on an open session of the agent (never
the delivery on its own: a client may not show it to the model), by a signed webhook (Standard Webhooks, see
``verify_wake_webhook``) to its own endpoint, and always by its queue: ``list(agent_id, status="open")`` is the
queue and ``acknowledge`` picks a wake up; a delivered wake nobody acknowledged ends as ``expired`` after 30 days.
Quiet hours hold wakes (or drop them; a decision is only ever held), a rate limit per agent stops a flood when the
customer sets one (none otherwise; a decision and a call ringing take no part in it), events close together become
one bundled wake that lists each (``event["bundled"]``) and drops none, and the same event twice is one wake.

Settings, rules and schedules are owner or admin calls; an agent reads its queue and picks wakes up,
passing its Passport as ``passport_token`` (sent as ``X-Passport-Token``).

Example::

    stack.wakes.create_rule({"name": "Mail", "source": "email", "task": "Answer the customer."}, agent_id)
    result = stack.wakes.set_settings({"webhook_url": "https://agent.example.com/wake"}, agent_id)
    secret = result["webhook_secret"]  # shown once; store it
    queue = stack.wakes.list(agent_id, status="open", passport_token=passport)
    for wake in queue["wakes"]:
        handle(wake["task"], wake["event"])
        stack.wakes.acknowledge(agent_id, wake["id"], passport_token=passport)
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


def _seg(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("an id is required")
    return quote(value, safe="")


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _agent(agent_id: str) -> str:
    return f"/v1/agents/{_seg(agent_id)}"


def _settings_path(agent_id: str | None) -> str:
    return f"{_agent(agent_id)}/wake/settings" if agent_id else "/v1/wake/settings"


def _rules_path(agent_id: str | None) -> str:
    return f"{_agent(agent_id)}/wake/rules" if agent_id else "/v1/wake/rules"


def _query(**values: Any) -> dict[str, Any] | None:
    present = {key: value for key, value in values.items() if value is not None}
    return present or None


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be a dict")
    return value


class WakesService:
    """The agent's queue, and the settings, rules and schedules behind it."""

    def __init__(self, client: HttpClient):
        self._client = client

    # ── The agent's queue ───────────────────────────────────────────

    def list(
        self,
        agent_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The agent's wakes, newest first; ``status="open"`` is the agent's queue, oldest first."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET",
                f"{_agent(agent_id)}/wakes",
                params=_query(status=status, limit=limit, cursor=cursor),
                extra_headers=_passport(passport_token),
            ),
        )

    def get(self, agent_id: str, wake_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.request(
                "GET", f"{_agent(agent_id)}/wakes/{_seg(wake_id)}", extra_headers=_passport(passport_token)
            ),
        )

    def acknowledge(self, agent_id: str, wake_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The agent has picked the wake up. Only a delivered wake of its own; saying it twice is fine."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_agent(agent_id)}/wakes/{_seg(wake_id)}/acknowledge",
                json={},
                extra_headers=_passport(passport_token),
            ),
        )

    # ── Settings (owner or admin) ───────────────────────────────────

    def get_settings(self, agent_id: str | None = None) -> dict[str, Any]:
        """One agent's settings and what is in force; without an agent, the customer's default."""
        return cast("dict[str, Any]", self._client.request("GET", _settings_path(agent_id)))

    def set_settings(self, settings: dict[str, Any], agent_id: str | None = None) -> dict[str, Any]:
        """Change settings, for one agent or (without an agent) the customer's default.

        A field left out stays; ``None`` clears it so the agent inherits the default. The first time a
        ``webhook_url`` is set, its signing secret comes back once as ``webhook_secret``.
        ``ring_incoming_calls`` (default true) is whether a call that comes in rings the agent; ``False`` sends
        it to voicemail, as does an agent with no live session and no webhook.
        """
        return cast(
            "dict[str, Any]",
            self._client.request("PUT", _settings_path(agent_id), json=_object(settings, "settings")),
        )

    def rotate_webhook_secret(self, agent_id: str) -> dict[str, Any]:
        """A new webhook signing secret, shown once; the old one keeps verifying for 24 hours."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"{_agent(agent_id)}/wake/webhook/rotate-secret", json={}),
        )

    def test_webhook(self, agent_id: str) -> dict[str, Any]:
        """Send a signed test to the agent's webhook: ``{"delivered": bool, "code": str | None}``."""
        return cast("dict[str, Any]", self._client.request("POST", f"{_agent(agent_id)}/wake/webhook/test", json={}))

    # ── Rules (owner or admin) ──────────────────────────────────────

    def list_rules(self, agent_id: str | None = None) -> dict[str, Any]:
        """One agent's own rules; without an agent, the customer's default rules."""
        return cast("dict[str, Any]", self._client.request("GET", _rules_path(agent_id)))

    def create_rule(self, rule: dict[str, Any], agent_id: str | None = None) -> dict[str, Any]:
        """Add a rule: ``name``, ``source`` and optionally ``task``, ``filters`` and ``enabled``."""
        return cast("dict[str, Any]", self._client.request("POST", _rules_path(agent_id), json=_object(rule, "rule")))

    def update_rule(self, rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.request("PUT", f"/v1/wake/rules/{_seg(rule_id)}", json=_object(rule, "rule")),
        )

    def delete_rule(self, rule_id: str) -> None:
        self._client.request("DELETE", f"/v1/wake/rules/{_seg(rule_id)}")

    # ── Schedules (owner or admin) ──────────────────────────────────

    def list_schedules(self, agent_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.request("GET", f"{_agent(agent_id)}/wake/schedules"))

    def create_schedule(self, agent_id: str, schedule: dict[str, Any]) -> dict[str, Any]:
        """``name``, ``cron`` (five fields, no more often than every 5 minutes), ``task``, optional ``time_zone``."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"{_agent(agent_id)}/wake/schedules", json=_object(schedule, "schedule")),
        )

    def update_schedule(self, agent_id: str, schedule_id: str, schedule: dict[str, Any]) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.request(
                "PUT",
                f"{_agent(agent_id)}/wake/schedules/{_seg(schedule_id)}",
                json=_object(schedule, "schedule"),
            ),
        )

    def delete_schedule(self, agent_id: str, schedule_id: str) -> None:
        self._client.request("DELETE", f"{_agent(agent_id)}/wake/schedules/{_seg(schedule_id)}")
