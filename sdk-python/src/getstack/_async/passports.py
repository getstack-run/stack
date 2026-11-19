"""Async mirror of PassportService + AsyncMission.

AsyncMission uses asyncio.create_task + asyncio.sleep for the
checkpoint loop (not threading.Timer) so it integrates cleanly with
event-loop-bound code. async_mission() and async_continuous_mission()
are async-context-manager / async-generator equivalents of the sync
mission() / continuous_mission().
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Awaitable
from contextlib import asynccontextmanager, suppress
from typing import Any, Callable, Literal, cast
from urllib.parse import quote

from ..client import AsyncHttpClient
from ..errors import StackError, mission_ended_error
from ..passports import (
    _delegation_scopes,
    _intent_body,
    _parse_duration,
    _require_one_mission,
    _revoke_notes,
    _signed_accountability,
    _start_mission_body,
    _to_passport,
)
from ..proxy import ProxyResponse
from ..types import CheckoutResult, CheckpointResult, Passport, PassportReport, ToolCall
from .proxy import AsyncProxyService


class AsyncMission:
    """Async mirror of Mission. Same surface (log, delegate, proxy,
    token, should_rotate) plus async_proxy + async context manager
    methods. Checkpoint scheduling uses asyncio.create_task; cancel
    on __aexit__."""

    def __init__(
        self,
        service: AsyncPassportService,
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
        self._task: asyncio.Task[None] | None = None
        self._timer_interval: float | None = None
        self._rotation_start: float = 0.0
        self._rotation_interval: float | None = None

    @property
    def should_rotate(self) -> bool:
        if self._rotation_interval is None:
            return False
        return asyncio.get_event_loop().time() - self._rotation_start >= self._rotation_interval

    def log(self, service: str, method: str, target: str | None = None) -> None:
        self._tool_calls.append(ToolCall(service=service, method=method, target=target))
        self._services_used.add(service)

    def delegate(self, child_agent_id: str) -> None:
        self._delegated_to.append(child_agent_id)

    @property
    def token(self) -> str | None:
        return self.passport.token if self.passport else None

    async def proxy(
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
        on_operation_id: Callable[[str], Awaitable[None] | None] | None = None,
        _proxy_service: AsyncProxyService | None = None,
    ) -> ProxyResponse:
        """Async proxy call using this mission's passport.

        ``approval_id`` is required when this mission's
               passport is in enforced mode. Obtain it from
               ``await stack.intents.submit_and_wait(...)``.
        """
        ps = _proxy_service or getattr(self, "_proxy", None)
        if ps is None:
            raise RuntimeError(
                "No async proxy service available. Set mission._proxy = stack.proxy before calling proxy()."
            )
        resp = await ps.request(
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

    async def _enter(self) -> None:
        if self.mission_id is None:
            # One call opens the Mission and issues its passport; the API
            # revokes the Mission if issuance fails.
            started = await self._service._start_mission(
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
            self.passport = await self._service.issue(
                agent_id=self._agent_id,
                intent=self._intent,
                services=self._declared_services,
                will_delegate=self._will_delegate,
                estimated_duration=self._estimated_duration,
                checkpoint_interval=self._checkpoint_interval,
                mission_ids=[self.mission_id],
            )
        self._rotation_start = asyncio.get_event_loop().time()

        if self._checkpoint_interval:
            self._timer_interval = float(_parse_duration(self._checkpoint_interval))
        elif self.passport.accountability == "enforced":
            self._timer_interval = 300.0
        else:
            self._timer_interval = None

        if self._timer_interval:
            self._task = asyncio.create_task(self._checkpoint_loop())

    async def _checkpoint_loop(self) -> None:
        """Run forever-ish until cancelled. Submits a checkpoint slightly
        before the interval elapses; sleeps; repeats."""
        assert self._timer_interval is not None
        delay = max(self._timer_interval - 5, 10.0)
        try:
            while True:
                await asyncio.sleep(delay)
                # Same swallow-policy as sync Mission: checkpoint failures must
                # NOT crash the agent.
                with suppress(Exception):
                    await self._submit_checkpoint()
        except asyncio.CancelledError:
            return

    async def _submit_checkpoint(self) -> None:
        if not self.passport:
            return
        new_calls = self._tool_calls[self._last_checkpoint_index :]
        await self._service.checkpoint(
            self.passport.jti,
            services_used=list(self._services_used),
            actions_count=len(new_calls),
            tool_calls=[tc.to_dict() for tc in new_calls] if new_calls else None,
            delegated_to=self._delegated_to if self._delegated_to else None,
        )
        self._last_checkpoint_index = len(self._tool_calls)

    async def _exit(self, error: BaseException | None = None) -> None:
        """Checkout first (closing the Mission revokes its passports), then
        close the Mission this object opened."""
        if self._task and not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        if self.passport:
            summary = None
            if error:
                summary = f"Mission failed: {type(error).__name__}: {error}"

            try:
                self.result = await self._service.checkout(
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
            await self._service._finish_mission(self.mission_id, error)

    async def __aenter__(self) -> AsyncMission:
        await self._enter()
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: Any) -> Literal[False]:
        await self._exit(error=exc_val if exc_type else None)
        return False


class AsyncPassportService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def issue(
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
        """Issue a signed passport for an agent (async mirror of ``Stack``).

        ``mission_ids`` must hold exactly one live Mission id (``ms_*``);
        anything else raises ``ValueError`` before any request::

            mission = await stack.missions.open("Send the weekly report", agent_id="agt_x")
            passport = await stack.passports.issue(
                agent_id="agt_x",
                mission_ids=[mission["mission_id"]],
                intent="Send the weekly report",
                services=["resend"],
            )

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

              await stack.passports.issue(
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
            data = await self._client.post("/v1/passports/issue", json=body)
        except StackError as exc:
            ended = mission_ended_error(exc)
            if ended is not None:
                raise ended from exc
            raise
        return _to_passport(data)

    async def _start_mission(self, body: dict[str, Any]) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post("/v1/missions/start", json=body))

    async def _finish_mission(self, mission_id: str, error: BaseException | None) -> None:
        """Complete the Mission, or revoke it when the block raised. Mirror of
        the sync PassportService._finish_mission."""
        path_id = quote(mission_id, safe="")
        if error is None:
            await self._client.post(f"/v1/missions/{path_id}/complete", json={})
            return
        with suppress(Exception):
            await self._client.post(
                f"/v1/missions/{path_id}/revoke",
                json={"reason": "operator_initiated_clean", "notes": _revoke_notes(error)},
            )

    async def checkpoint(
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
        data = await self._client.post(f"/v1/passports/{passport_jti}/checkpoint", json=body)
        return CheckpointResult(
            checkpoint_id=data["checkpoint_id"],
            passport_jti=data["passport_jti"],
            new_expires_at=data.get("new_expires_at"),
            flags=data.get("flags"),
        )

    async def checkout(
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
        data = await self._client.post(f"/v1/passports/{passport_jti}/checkout", json=body)
        return CheckoutResult(
            checkout_id=data["checkout_id"],
            passport_jti=data["passport_jti"],
            review_status=data["review_status"],
            flags=data.get("flags"),
        )

    async def report(self, passport_jti: str) -> PassportReport:
        data = await self._client.get(f"/v1/passports/{passport_jti}/report")
        return PassportReport(**data)

    async def verify(self, token: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post("/v1/passports/verify", json={"token": token}))

    async def revoke(self, jti: str, reason: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", await self._client.post("/v1/passports/revoke", json={"jti": jti, "reason": reason})
        )

    async def revoke_agent(self, agent_id: str, reason: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", await self._client.post(f"/v1/passports/revoke-agent/{agent_id}", json={"reason": reason})
        )

    async def revoke_session(self, session_id: str, reason: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.post(f"/v1/passports/revoke-session/{session_id}", json={"reason": reason}),
        )

    async def revoke_all(self, reason: str | None = None) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.post("/v1/passports/revoke-all", json={"reason": reason}))

    async def delegate(
        self,
        parent_token: str,
        child_agent_id: str,
        scopes: list[dict[str, Any]] | list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> Passport:
        body: dict[str, Any] = {
            "parent_passport_token": parent_token,
            "child_agent_id": child_agent_id,
            "scopes": _delegation_scopes(parent_token, scopes),
        }
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return _to_passport(await self._client.post("/v1/passports/delegate", json=body))

    async def refresh(self, token: str, ttl_seconds: int | None = None) -> Passport:
        """Refresh within the Mission; raises MissionEndedError once it ends."""
        body: dict[str, Any] = {"token": token}
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds
        try:
            data = await self._client.post("/v1/passports/refresh", json=body)
        except StackError as exc:
            ended = mission_ended_error(exc)
            if ended is not None:
                raise ended from exc
            raise
        return _to_passport(data)

    async def list_active(self, agent_id: str | None = None, session_id: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, str] = {}
        if agent_id:
            params["agent_id"] = agent_id
        if session_id:
            params["session_id"] = session_id
        return cast("list[dict[str, Any]]", await self._client.get("/v1/passports/active", params=params or None))

    @asynccontextmanager
    async def mission(
        self,
        agent_id: str,
        intent: str,
        services: list[str],
        will_delegate: bool = False,
        estimated_duration: str | None = None,
        checkpoint_interval: str | None = None,
        mission_id: str | None = None,
        expires_in: str | None = None,
    ) -> AsyncGenerator[AsyncMission, None]:
        """Async-context-manager mission. Mirror of sync mission(): opens the
        Mission and its passport in one call (POST /v1/missions/start),
        checks out, then completes the Mission on exit (revokes it if the
        block raised). ``mission_id`` binds an existing Mission, which is
        then left open on exit."""
        m = AsyncMission(
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
        await m._enter()
        try:
            yield m
        except BaseException as e:
            await m._exit(error=e)
            raise
        else:
            await m._exit()

    async def continuous_mission(
        self,
        agent_id: str,
        intent: str,
        services: list[str],
        rotation_interval: str = "4h",
        will_delegate: bool = False,
        checkpoint_interval: str | None = None,
        mission_id: str | None = None,
        expires_in: str | None = None,
    ) -> AsyncGenerator[AsyncMission, None]:
        """Async generator yielding successive AsyncMission objects. Mirror of
        sync continuous_mission(): every rotation shares one Mission, and
        closing the generator (``aclose()``) completes the Mission it opened."""
        rotation_secs = float(_parse_duration(rotation_interval))
        rotation_count = 0
        bound_mission_id = mission_id
        owned_mission_id: str | None = None
        error: BaseException | None = None
        try:
            while True:
                m = AsyncMission(
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
                await m._enter()
                if m._owns_mission:
                    owned_mission_id = bound_mission_id = m.mission_id
                    m._owns_mission = False
                try:
                    yield m
                except GeneratorExit:
                    await m._exit()
                    raise
                except BaseException as e:
                    await m._exit(error=e)
                    raise
                else:
                    await m._exit()
                rotation_count += 1
        except GeneratorExit:
            raise
        except BaseException as e:
            error = e
            raise
        finally:
            if owned_mission_id is not None:
                await self._finish_mission(owned_mission_id, error)
