"""Passport management with mission context manager and continuous rotation."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from typing import Any, Callable, Literal, cast
from urllib.parse import quote

import jwt

from .client import HttpClient
from .errors import StackError, mission_ended_error
from .proxy import ProxyResponse, ProxyService
from .types import CheckoutResult, CheckpointResult, Passport, PassportReport, ToolCall


def _parse_duration(s: str) -> int:
    """Parse a duration string like '30m', '2h', '300' to seconds."""
    match = re.match(r"^(\d+)(s|m|h)$", s)
    if match:
        num, unit = int(match.group(1)), match.group(2)
        return num * {"s": 1, "m": 60, "h": 3600}[unit]
    return int(s)


def _to_passport(data: dict[str, Any]) -> Passport:
    return Passport(
        token=data["token"],
        jti=data["jti"],
        expires_at=data["expires_at"],
        accountability=data.get("accountability"),
    )


def _signed_accountability(token: str) -> str | None:
    """Read the accountability mode from the passport's own claims.

    POST /v1/missions/start returns token/jti/expires_at only. Request
    construction only: the API verifies the token on every use."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception:
        return None
    mode = claims.get("stk", {}).get("accountability") if isinstance(claims.get("stk"), dict) else None
    return mode if isinstance(mode, str) else None


_MISSION_REQUIRED = (
    "A Passport must be issued for exactly one Mission: pass mission_ids=[mission_id] "
    "with one ms_* id. Open one with stack.missions.open(..., agent_id=...), or open the "
    "Mission and its passport in one call with stack.missions.start(agent_id=..., mission={...})."
)


def _require_one_mission(mission_ids: list[str] | None) -> list[str]:
    """Return ``mission_ids`` when it holds exactly one id, else raise ValueError."""
    if (
        not isinstance(mission_ids, (list, tuple))
        or len(mission_ids) != 1
        or not isinstance(mission_ids[0], str)
        or not mission_ids[0]
    ):
        raise ValueError(_MISSION_REQUIRED)
    return [mission_ids[0]]


def _intent_body(
    intent: str | None,
    services: list[str] | None,
    will_delegate: bool,
    estimated_duration: str | None,
) -> dict[str, Any] | None:
    if not (intent or services):
        return None
    body: dict[str, Any] = {
        "summary": intent or "",
        "services": services or [],
        "will_delegate": will_delegate,
    }
    if estimated_duration:
        body["estimated_duration_seconds"] = _parse_duration(estimated_duration)
    return body


def _start_mission_body(
    agent_id: str,
    intent: str,
    services: list[str],
    will_delegate: bool,
    estimated_duration: str | None,
    checkpoint_interval: str | None,
    expires_in: str | None,
) -> dict[str, Any]:
    """Operator-form POST /v1/missions/start body for the mission context manager."""
    mission: dict[str, Any] = {"intent_summary": intent, "intent_services": list(services)}
    lifetime = expires_in or estimated_duration
    if lifetime:
        mission["expires_in_seconds"] = _parse_duration(lifetime)
    passport: dict[str, Any] = {}
    intent_body = _intent_body(intent, services, will_delegate, estimated_duration)
    if intent_body is not None:
        passport["intent"] = intent_body
    if checkpoint_interval:
        passport["checkpoint_interval_seconds"] = _parse_duration(checkpoint_interval)
    return {"agent_id": agent_id, "mission": mission, "passport": passport}


def _revoke_notes(error: BaseException) -> str:
    return f"Mission failed: {type(error).__name__}: {error}"[:1000]


def _delegation_scopes(token: str, scopes: list[dict[str, Any]] | list[str] | None) -> list[dict[str, Any]] | list[str]:
    if scopes is not None and all(isinstance(scope, dict) for scope in scopes):
        return scopes
    # Request construction only. The API authenticates the parent Passport.
    services = (
        jwt.decode(token, options={"verify_signature": False, "verify_aud": False}).get("stk", {}).get("services")
    )
    if not isinstance(services, list):
        raise ValueError("Invalid input")
    selected = [service for service in services if scopes is None or service.get("service_name") in scopes]
    if scopes is not None and any(
        not any(service.get("service_name") == name for service in selected) for name in scopes
    ):
        raise ValueError("Invalid input")
    result: list[dict[str, Any]] = []
    for service in selected:
        if not isinstance(service.get("connection_id"), str) or not isinstance(service.get("scopes"), list):
            raise ValueError("Invalid input")
        result.append(
            {
                "service_connection_id": service["connection_id"],
                "scopes": service["scopes"],
                **({"constraints": service["constraints"]} if "constraints" in service else {}),
                **({"allow_data_from": service["allow_data_from"]} if "allow_data_from" in service else {}),
            }
        )
    return result


class Mission:
    """A bounded accountability window for an agent mission.

    Opens a STACK Mission and its passport, tracks tool calls, submits
    checkpoints on schedule, and on exit checks out and closes the Mission
    it opened. ``mission_id`` is the bound Mission (``ms_*``).
    """

    def __init__(
        self,
        service: PassportService,
        agent_id: str,
        intent: str,
        services: list[str],
        will_delegate: bool = False,
        estimated_duration: str | None = None,
        checkpoint_interval: str | None = None,
        mission_id: str | None = None,
        expires_in: str | None = None,
    ):
        self._service = service
        self._agent_id = agent_id
        self._intent = intent
        self._declared_services = services
        self._will_delegate = will_delegate
        self._estimated_duration = estimated_duration
        self._checkpoint_interval = checkpoint_interval
        self._expires_in = expires_in

        # The bound Mission. When the caller passes none, _enter opens one
        # and this object owns it (closes it on exit).
        self.mission_id: str | None = mission_id
        self._owns_mission: bool = False

        self.passport: Passport | None = None
        self.review_status: str | None = None
        self.result: CheckoutResult | None = None
        self.rotation_count: int = 0

        self._tool_calls: list[ToolCall] = []
        self._services_used: set[str] = set()
        self._delegated_to: list[str] = []
        self._last_checkpoint_index: int = 0
        self._timer: threading.Timer | None = None
        self._timer_interval: float | None = None
        self._rotation_start: float = 0
        self._rotation_interval: float | None = None

    @property
    def should_rotate(self) -> bool:
        """True when the rotation interval has elapsed. Check at natural breakpoints."""
        if self._rotation_interval is None:
            return False
        return time.monotonic() - self._rotation_start >= self._rotation_interval

    def log(self, service: str, method: str, target: str | None = None) -> None:
        """Log a tool call. Call this for each action the agent takes."""
        self._tool_calls.append(ToolCall(service=service, method=method, target=target))
        self._services_used.add(service)

    def delegate(self, child_agent_id: str) -> None:
        """Record that delegation occurred to a child agent."""
        self._delegated_to.append(child_agent_id)

    @property
    def token(self) -> str | None:
        """Current passport token, for passing to credential retrieval."""
        return self.passport.token if self.passport else None

    def proxy(
        self,
        service: str,
        url: str,
        method: str = "GET",
        *,
        headers: dict[str, str] | None = None,
        body: Any = None,
        query: dict[str, str] | None = None,
        approval_id: str | None = None,
        authority_request_id: str | None = None,
        on_operation_id: Callable[[str], None] | None = None,
        _proxy_service: ProxyService | None = None,
    ) -> ProxyResponse:
        """Send a request through STACK's credential proxy using this mission's passport.

        Args:
            service: Provider slug (e.g. "openai", "slack").
            url: Full target URL.
            method: HTTP method.
            headers: Extra headers (auth headers will be stripped).
            body: Request body.
            query: Query parameters.
            approval_id: Approval id from ``stack.intents.submit_and_wait``
                Required when this mission's passport
                is in enforced mode. Pass the approval id returned
                from ``final.id`` after ``submit_and_wait`` reports
                ``status='approved'``.
            authority_request_id: Stable operation identifier to reuse only
                for an unchanged retry.
            on_operation_id: Called before network I/O so a durable job can
                persist the generated operation identifier.
            _proxy_service: ProxyService instance (falls back to self._proxy).
        """
        ps = _proxy_service or getattr(self, "_proxy", None)
        if ps is None:
            raise RuntimeError("No proxy service available. Set mission._proxy = stack.proxy before calling proxy().")
        resp = ps.request(
            service,
            url,
            method,
            headers=headers,
            body=body,
            query=query,
            passport_token=self.token,
            approval_id=approval_id,
            authority_request_id=authority_request_id,
            on_operation_id=on_operation_id,
        )
        self.log(service, method, url)
        return resp

    def _enter(self) -> None:
        """Open the Mission and its passport (or bind an existing Mission),
        then start the checkpoint timer."""
        if self.mission_id is None:
            # One call opens the Mission and issues its passport. If issuance
            # fails the API revokes the Mission, so no orphan is left open.
            started = self._service._start_mission(
                _start_mission_body(
                    self._agent_id,
                    self._intent,
                    self._declared_services,
                    self._will_delegate,
                    self._estimated_duration,
                    self._checkpoint_interval,
                    self._expires_in,
                )
            )
            self.mission_id = started["mission_id"]
            self._owns_mission = True
            passport = _to_passport(started["passport"])
            if passport.accountability is None:
                passport.accountability = _signed_accountability(passport.token)
            self.passport = passport
        else:
            self.passport = self._service.issue(
                agent_id=self._agent_id,
                intent=self._intent,
                services=self._declared_services,
                will_delegate=self._will_delegate,
                estimated_duration=self._estimated_duration,
                checkpoint_interval=self._checkpoint_interval,
                mission_ids=[self.mission_id],
            )
        self._rotation_start = time.monotonic()

        # Start checkpoint timer for enforced mode
        if self._checkpoint_interval:
            self._timer_interval = _parse_duration(self._checkpoint_interval)
        elif self.passport.accountability == "enforced":
            self._timer_interval = 300  # 5 min default
        else:
            self._timer_interval = None

        if self._timer_interval:
            self._schedule_checkpoint()

    def _schedule_checkpoint(self) -> None:
        """Schedule the next automatic checkpoint."""
        if self._timer_interval:
            # Submit slightly before the interval to ensure we don't miss it
            delay = max(self._timer_interval - 5, 10)
            self._timer = threading.Timer(delay, self._auto_checkpoint)
            self._timer.daemon = True
            self._timer.start()

    def _auto_checkpoint(self) -> None:
        """Submit checkpoint and reschedule."""
        # Don't crash the agent on checkpoint failure.
        with suppress(Exception):
            self._submit_checkpoint()
        self._schedule_checkpoint()

    def _submit_checkpoint(self) -> None:
        """Submit accumulated activity as a checkpoint."""
        if not self.passport:
            return

        new_calls = self._tool_calls[self._last_checkpoint_index :]
        self._service.checkpoint(
            self.passport.jti,
            services_used=list(self._services_used),
            actions_count=len(new_calls),
            tool_calls=[tc.to_dict() for tc in new_calls] if new_calls else None,
            delegated_to=self._delegated_to if self._delegated_to else None,
        )
        self._last_checkpoint_index = len(self._tool_calls)

    def _exit(self, error: BaseException | None = None) -> None:
        """Stop timer, submit checkout, then close the Mission this object
        opened. Checkout runs first because closing the Mission revokes
        its passports."""
        if self._timer:
            self._timer.cancel()
            self._timer = None

        if self.passport:
            summary = None
            if error:
                summary = f"Mission failed: {type(error).__name__}: {error}"

            try:
                self.result = self._service.checkout(
                    self.passport.jti,
                    services_used=list(self._services_used),
                    actions_count=len(self._tool_calls),
                    tool_calls=[tc.to_dict() for tc in self._tool_calls] if self._tool_calls else None,
                    summary=summary,
                    delegated_to=self._delegated_to if self._delegated_to else None,
                )
                self.review_status = self.result.review_status
            except Exception:
                pass  # Best-effort checkout

        if self._owns_mission and self.mission_id:
            self._service._finish_mission(self.mission_id, error)

    def __enter__(self) -> Mission:
        self._enter()
        return self

    def __exit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any) -> Literal[False]:
        self._exit(error=exc_val if exc_type else None)
        return False  # Don't suppress exceptions


class PassportService:
    def __init__(self, client: HttpClient):
        self._client = client

    def issue(
        self,
        agent_id: str,
        intent: str | None = None,
        services: list[str] | None = None,
        will_delegate: bool = False,
        estimated_duration: str | None = None,
        checkpoint_interval: str | None = None,
        ttl_seconds: int | None = None,
        scopes: list[dict[str, Any]] | None = None,
        authority_binding_ids: list[str] | None = None,
        mission_ids: list[str] | None = None,
    ) -> Passport:
        """Issue a signed passport for an agent, bound to one Mission.

        ``mission_ids`` must hold exactly one live Mission id (``ms_*``)
        assigned to this agent or unassigned; anything else raises
        ``ValueError`` before any request. The passport never outlives
        the Mission, and completing or revoking the Mission revokes it::

            mission = stack.missions.open(
                "Send the weekly report",
                agent_id="agt_x",
                intent_services=["resend"],
            )
            passport = stack.passports.issue(
                agent_id="agt_x",
                mission_ids=[mission["mission_id"]],
                intent="Send the weekly report",
                services=["resend"],
            )

        To open the Mission and its passport in one call use
        ``stack.missions.start(agent_id=..., mission={...})`` or the
        ``stack.passports.mission(...)`` context manager.

        ``scopes`` is a list of per-connection override dicts. Each recognises:

        - ``service_connection_id`` (str) — the connection to scope.
        - ``scopes`` (list[str]) — a subset of the grant's scopes.
        - ``constraints`` / ``intents`` — tighten-only parameter rules.
        - ``allow_data_from`` (list[str]) — the data-flow declaration: the
          sources whose content may flow INTO this one: a service, or one
          connection of a service written ``service@<connection id>``. The
          scope wall refuses cross-service movement, and movement between two
          connections of one service, unless the operator grant permits it.
          Omit to inherit that grant; pass ``[]`` to allow none. A standing
          grant wildcard is resolved to exact names before signing and is not
          accepted here. Example::

              stack.passports.issue(
                  agent_id="agt_x",
                  mission_ids=[mission_id],
                  scopes=[{
                      "service_connection_id": "scon_resend",
                      "scopes": ["email:send"],
                      "allow_data_from": ["guestbook"],
                  }],
              )
        """
        body: dict[str, Any] = {"agent_id": agent_id, "mission_ids": _require_one_mission(mission_ids)}
        if scopes:
            body["scopes"] = scopes
        if authority_binding_ids is not None:
            body["authority_binding_ids"] = authority_binding_ids
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        intent_body = _intent_body(intent, services, will_delegate, estimated_duration)
        if intent_body is not None:
            body["intent"] = intent_body
        if checkpoint_interval:
            body["checkpoint_interval_seconds"] = _parse_duration(checkpoint_interval)
        try:
            data = self._client.post("/v1/passports/issue", json=body)
        except StackError as exc:
            ended = mission_ended_error(exc)
            if ended is not None:
                raise ended from exc
            raise
        return _to_passport(data)

    # Mission lifecycle calls used by the mission context managers. They hit
    # the same routes as MissionsService; kept here so PassportService needs
    # only its HTTP client.

    def _start_mission(self, body: dict[str, Any]) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.post("/v1/missions/start", json=body))

    def _finish_mission(self, mission_id: str, error: BaseException | None) -> None:
        """Complete the Mission, or revoke it when the block raised.

        Either call revokes every passport bound to the Mission. On the
        error path a close failure is swallowed so the original exception
        propagates; on the success path it raises, because the Mission
        would otherwise stay open until it expires."""
        path_id = quote(mission_id, safe="")
        if error is None:
            self._client.post(f"/v1/missions/{path_id}/complete", json={})
            return
        with suppress(Exception):
            self._client.post(
                f"/v1/missions/{path_id}/revoke",
                json={"reason": "operator_initiated_clean", "notes": _revoke_notes(error)},
            )

    def checkpoint(
        self,
        passport_jti: str,
        services_used: list[str],
        actions_count: int,
        tool_calls: list[dict[str, Any]] | None = None,
        summary: str | None = None,
        delegated_to: list[str] | None = None,
    ) -> CheckpointResult:
        body: dict[str, Any] = {
            "services_used": services_used,
            "actions_count": actions_count,
        }
        if tool_calls:
            body["tool_calls"] = tool_calls
        if summary:
            body["summary"] = summary
        if delegated_to:
            body["delegated_to"] = delegated_to
        data = self._client.post(f"/v1/passports/{passport_jti}/checkpoint", json=body)
        return CheckpointResult(
            checkpoint_id=data["checkpoint_id"],
            passport_jti=data["passport_jti"],
            new_expires_at=data.get("new_expires_at"),
            flags=data.get("flags"),
        )

    def checkout(
        self,
        passport_jti: str,
        services_used: list[str],
        actions_count: int,
        tool_calls: list[dict[str, Any]] | None = None,
        summary: str | None = None,
        delegated_to: list[str] | None = None,
    ) -> CheckoutResult:
        body: dict[str, Any] = {
            "services_used": services_used,
            "actions_count": actions_count,
        }
        if tool_calls:
            body["tool_calls"] = tool_calls
        if summary:
            body["summary"] = summary
        if delegated_to:
            body["delegated_to"] = delegated_to
        data = self._client.post(f"/v1/passports/{passport_jti}/checkout", json=body)
        return CheckoutResult(
            checkout_id=data["checkout_id"],
            passport_jti=data["passport_jti"],
            review_status=data["review_status"],
            flags=data.get("flags"),
        )

    def report(self, passport_jti: str) -> PassportReport:
        data = self._client.get(f"/v1/passports/{passport_jti}/report")
        return PassportReport(**data)

    def verify(self, token: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.post("/v1/passports/verify", json={"token": token}))

    def revoke(self, jti: str, reason: str | None = None) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.post("/v1/passports/revoke", json={"jti": jti, "reason": reason}))

    def revoke_agent(self, agent_id: str, reason: str | None = None) -> dict[str, Any]:
        """Revoke every active passport for an agent."""
        return cast(
            "dict[str, Any]", self._client.post(f"/v1/passports/revoke-agent/{agent_id}", json={"reason": reason})
        )

    def revoke_session(self, session_id: str, reason: str | None = None) -> dict[str, Any]:
        """Revoke every active passport bound to a session."""
        return cast(
            "dict[str, Any]", self._client.post(f"/v1/passports/revoke-session/{session_id}", json={"reason": reason})
        )

    def revoke_all(self, reason: str | None = None) -> dict[str, Any]:
        """Revoke EVERY active passport for the operator (org-wide kill)."""
        return cast("dict[str, Any]", self._client.post("/v1/passports/revoke-all", json={"reason": reason}))

    def delegate(
        self,
        parent_token: str,
        child_agent_id: str,
        scopes: list[dict[str, Any]] | list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> Passport:
        """Delegate a passport to a child agent. Scope narrows only, max 4
        hops (enforced server-side)."""
        body: dict[str, Any] = {
            "parent_passport_token": parent_token,
            "child_agent_id": child_agent_id,
            "scopes": _delegation_scopes(parent_token, scopes),
        }
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return _to_passport(self._client.post("/v1/passports/delegate", json=body))

    def refresh(self, token: str, ttl_seconds: int | None = None) -> Passport:
        """Refresh a passport within its Mission. Raises MissionEndedError
        once the Mission is completed, revoked or expired."""
        body: dict[str, Any] = {"token": token}
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        try:
            data = self._client.post("/v1/passports/refresh", json=body)
        except StackError as exc:
            ended = mission_ended_error(exc)
            if ended is not None:
                raise ended from exc
            raise
        return _to_passport(data)

    def list_active(self, agent_id: str | None = None, session_id: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, str] = {}
        if agent_id:
            params["agent_id"] = agent_id
        if session_id:
            params["session_id"] = session_id
        return cast("list[dict[str, Any]]", self._client.get("/v1/passports/active", params=params or None))

    @contextmanager
    def mission(
        self,
        agent_id: str,
        intent: str,
        services: list[str],
        will_delegate: bool = False,
        estimated_duration: str | None = None,
        checkpoint_interval: str | None = None,
        mission_id: str | None = None,
        expires_in: str | None = None,
    ) -> Generator[Mission, None, None]:
        """Context manager for a single bounded Mission.

        By default it opens a Mission and its passport in one call
        (POST /v1/missions/start). On exit it checks the passport out, then
        completes the Mission; if the block raised, it revokes the Mission
        instead. Either way every passport bound to it is revoked.

        ``expires_in`` sets the Mission's lifetime (e.g. ``"2h"``; the latest end is 31 December 9999);
        it defaults to ``estimated_duration``, else the API default of
        15 minutes. The passport never outlives the Mission.

        Pass ``mission_id="ms_..."`` to bind a Mission you already opened.
        The passport is then issued for it, and the Mission is left open on
        exit: you close it with ``stack.missions.complete``.

        Usage::

            with stack.passports.mission(
                agent_id="agt_x",
                intent="Process invoices from Slack",
                services=["slack", "stripe"],
            ) as mission:
                mission.log("slack", "read_channel", "#invoices")
        """
        m = Mission(
            self,
            agent_id,
            intent,
            services,
            will_delegate=will_delegate,
            estimated_duration=estimated_duration,
            checkpoint_interval=checkpoint_interval,
            mission_id=mission_id,
            expires_in=expires_in,
        )
        m._enter()
        try:
            yield m
        except BaseException as e:
            m._exit(error=e)
            raise
        else:
            m._exit()

    def continuous_mission(
        self,
        agent_id: str,
        intent: str,
        services: list[str],
        rotation_interval: str = "4h",
        will_delegate: bool = False,
        checkpoint_interval: str | None = None,
        mission_id: str | None = None,
        expires_in: str | None = None,
    ) -> Generator[Mission, None, None]:
        """Generator yielding successive Mission objects with passport rotation.

        All rotations share one STACK Mission. The first iteration opens the
        Mission and its passport in one call (or binds ``mission_id``); each
        later iteration checks the previous passport out and issues a new
        one for the same Mission when the rotation interval elapses
        (signaled via mission.should_rotate). Closing the generator
        completes the Mission it opened.

        A Mission lives as long as ``expires_in`` says (defaulting to the
        API's 15 minutes), and no passport outlives it. Once it ends, the
        next rotation raises ``MissionEndedError``: start a new
        ``continuous_mission``.

        Usage::

            for mission in stack.passports.continuous_mission(
                agent_id="agt_...",
                intent="Monitor Slack",
                services=["slack"],
                rotation_interval="1h",
                expires_in="24h",
            ):
                while not mission.should_rotate:
                    event = wait_for_event()
                    mission.log("slack", "read_message")
                    process(event)
        """
        rotation_secs = _parse_duration(rotation_interval)
        rotation_count = 0
        bound_mission_id = mission_id
        owned_mission_id: str | None = None
        error: BaseException | None = None

        try:
            while True:
                m = Mission(
                    self,
                    agent_id,
                    intent,
                    services,
                    will_delegate=will_delegate,
                    checkpoint_interval=checkpoint_interval,
                    mission_id=bound_mission_id,
                    expires_in=expires_in,
                )
                m.rotation_count = rotation_count
                m._rotation_interval = rotation_secs

                m._enter()
                if m._owns_mission:
                    # The generator closes the Mission, not the rotation.
                    owned_mission_id = bound_mission_id = m.mission_id
                    m._owns_mission = False
                try:
                    yield m
                except GeneratorExit:
                    m._exit()
                    raise
                except BaseException as e:
                    m._exit(error=e)
                    raise
                else:
                    m._exit()

                rotation_count += 1
        except GeneratorExit:
            raise
        except BaseException as e:
            error = e
            raise
        finally:
            if owned_mission_id is not None:
                self._finish_mission(owned_mission_id, error)
