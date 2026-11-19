"""every passport is issued for exactly one Mission.

Covers missions.start (operator form), missions.open(agent_id=...), the
mission context managers (sync + async), passport refresh once the Mission
ended, Stack.issue_passport and partner tenant issuance.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import jwt
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import Stack
from getstack._async.missions import AsyncMissionsService
from getstack._async.partner_accounts import AsyncPartnerAccountsService
from getstack._async.passport_session import AsyncPassportSession
from getstack._async.passports import AsyncPassportService
from getstack.errors import ForbiddenError, MissionEndedError, NotFoundError
from getstack.missions import MissionsService
from getstack.partner_accounts import PartnerAccountsService
from getstack.passport_session import PassportSession
from getstack.passports import PassportService


def _token(exp_offset: int = 900, accountability: str = "standard") -> str:
    return jwt.encode(
        {"exp": int(time.time()) + exp_offset, "stk": {"accountability": accountability}},
        "test-key-not-a-secret-padded-to-32-bytes",
        algorithm="HS256",
    )


class RouteClient:
    """Records (method, path, json) and answers by path suffix. A value that
    is an exception is raised instead of returned."""

    def __init__(self, routes: dict | None = None) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.routes = routes or {}

    def _answer(self, method: str, path: str, json):
        self.calls.append((method, path, json))
        for suffix, value in self.routes.items():
            if path.endswith(suffix):
                if isinstance(value, BaseException):
                    raise value
                return value
        return {}

    def request(self, method, path, json=None, **_kw):
        return self._answer(method, path, json)

    def post(self, path, json=None, **_kw):
        return self._answer("POST", path, json)


class AsyncRouteClient(RouteClient):
    async def request(self, method, path, json=None, **_kw):  # type: ignore[override]
        return self._answer(method, path, json)

    async def post(self, path, json=None, **_kw):  # type: ignore[override]
        return self._answer("POST", path, json)


def _start_response(token: str | None = None) -> dict:
    return {
        "mission_id": "ms_opened",
        "claim_id": "pc_open",
        "expires_at": "2026-10-01T12:00:00Z",
        "passport": {"token": token or _token(), "jti": "ppt_1", "expires_at": "2026-10-01T12:00:00Z"},
    }


_CHECKOUT = {"checkout_id": "co_1", "passport_jti": "ppt_1", "review_status": "clean"}
_ISSUED = {"token": "tok", "jti": "ppt_2", "expires_at": "2026-10-01T12:00:00Z"}


def _paths(client: RouteClient) -> list[str]:
    return [path for _method, path, _json in client.calls]


# ── missions.start / missions.open ─────────────────────────────────────


def test_start_operator_form_posts_agent_mission_and_passport():
    client = RouteClient()
    MissionsService(client).start(  # type: ignore[arg-type]
        agent_id="agt_x",
        mission={"intent_summary": "Triage inbox", "intent_services": ["gmail"]},
        passport={"ttl_seconds": 600},
    )
    assert client.calls == [
        (
            "POST",
            "/v1/missions/start",
            {
                "agent_id": "agt_x",
                "mission": {"intent_summary": "Triage inbox", "intent_services": ["gmail"]},
                "passport": {"ttl_seconds": 600},
            },
        )
    ]


def test_start_fleet_form_is_unchanged_and_forms_do_not_mix():
    client = RouteClient()
    fleet = {"fleet_policy_id": "flp_1", "idempotency_key": "k"}
    MissionsService(client).start(fleet)  # type: ignore[arg-type]
    assert client.calls == [("POST", "/v1/missions/start", fleet)]
    with pytest.raises(ValueError):
        MissionsService(client).start(fleet, agent_id="agt_x")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        MissionsService(client).start(agent_id="agt_x")  # type: ignore[arg-type]
    assert len(client.calls) == 1


def test_open_sends_agent_id():
    client = RouteClient()
    MissionsService(client).open("s", agent_id="agt_x", intent_services=["slack"])  # type: ignore[arg-type]
    assert client.calls[0][2] == {"intent_summary": "s", "intent_services": ["slack"], "agent_id": "agt_x"}


def test_async_start_operator_form_and_open_agent_id():
    async def run() -> None:
        client = AsyncRouteClient()
        service = AsyncMissionsService(client)  # type: ignore[arg-type]
        await service.start(agent_id="agt_x", mission={"intent_summary": "s"})
        await service.open("s", agent_id="agt_x")
        assert client.calls == [
            ("POST", "/v1/missions/start", {"agent_id": "agt_x", "mission": {"intent_summary": "s"}}),
            ("POST", "/v1/missions", {"intent_summary": "s", "agent_id": "agt_x"}),
        ]

    asyncio.run(run())


# ── mission context manager ────────────────────────────────────────────


def test_context_manager_opens_in_one_call_checks_out_then_completes():
    client = RouteClient(
        {"/v1/missions/start": _start_response(_token(accountability="logged")), "/checkout": _CHECKOUT}
    )
    with PassportService(client).mission(  # type: ignore[arg-type]
        agent_id="agt_x",
        intent="Process invoices",
        services=["slack"],
        expires_in="2h",
    ) as m:
        assert m.mission_id == "ms_opened"
        # start returns no accountability field; it is read from the claims.
        assert m.passport is not None and m.passport.accountability == "logged"
    assert _paths(client) == [
        "/v1/missions/start",
        "/v1/passports/ppt_1/checkout",
        "/v1/missions/ms_opened/complete",
    ]
    body = client.calls[0][2]
    assert body["agent_id"] == "agt_x"
    assert body["mission"] == {
        "intent_summary": "Process invoices",
        "intent_services": ["slack"],
        "expires_in_seconds": 7200,
    }
    assert body["passport"]["intent"]["services"] == ["slack"]
    assert "mission_ids" not in body["passport"]


def test_context_manager_revokes_the_mission_when_the_block_raises():
    client = RouteClient({"/v1/missions/start": _start_response(), "/checkout": _CHECKOUT})
    mission = PassportService(client).mission(agent_id="agt_x", intent="i", services=["slack"])  # type: ignore[arg-type]
    with pytest.raises(RuntimeError), mission:
        raise RuntimeError("boom")
    assert _paths(client) == [
        "/v1/missions/start",
        "/v1/passports/ppt_1/checkout",
        "/v1/missions/ms_opened/revoke",
    ]
    assert client.calls[-1][2]["reason"] == "operator_initiated_clean"


def test_context_manager_binds_an_existing_mission_and_leaves_it_open():
    client = RouteClient({"/v1/passports/issue": _ISSUED, "/checkout": _CHECKOUT})
    with PassportService(client).mission(  # type: ignore[arg-type]
        agent_id="agt_x",
        intent="i",
        services=["slack"],
        mission_id="ms_mine",
    ) as m:
        assert m.mission_id == "ms_mine"
    assert _paths(client) == ["/v1/passports/issue", "/v1/passports/ppt_2/checkout"]
    assert client.calls[0][2]["mission_ids"] == ["ms_mine"]


def test_context_manager_makes_no_further_calls_when_start_fails():
    client = RouteClient({"/v1/missions/start": ForbiddenError("grant does not cover slack")})
    mission = PassportService(client).mission(agent_id="agt_x", intent="i", services=["slack"])  # type: ignore[arg-type]
    with pytest.raises(ForbiddenError), mission:
        pass
    # The API revokes the Mission it opened when issuance fails.
    assert _paths(client) == ["/v1/missions/start"]


def test_continuous_mission_rotates_passports_within_one_mission():
    client = RouteClient(
        {"/v1/missions/start": _start_response(), "/v1/passports/issue": _ISSUED, "/checkout": _CHECKOUT}
    )
    gen = PassportService(client).continuous_mission(  # type: ignore[arg-type]
        agent_id="agt_x",
        intent="Monitor",
        services=["slack"],
        rotation_interval="1h",
    )
    first = next(gen)
    second = next(gen)
    assert first.mission_id == second.mission_id == "ms_opened"
    gen.close()
    assert _paths(client) == [
        "/v1/missions/start",
        "/v1/passports/ppt_1/checkout",
        "/v1/passports/issue",
        "/v1/passports/ppt_2/checkout",
        "/v1/missions/ms_opened/complete",
    ]
    assert client.calls[2][2]["mission_ids"] == ["ms_opened"]


def test_continuous_mission_rotation_after_mission_end_raises_mission_ended():
    client = RouteClient(
        {
            "/v1/missions/start": _start_response(),
            "/v1/passports/issue": ForbiddenError("Mission ms_opened has expired"),
            "/checkout": _CHECKOUT,
        }
    )
    gen = PassportService(client).continuous_mission(  # type: ignore[arg-type]
        agent_id="agt_x",
        intent="Monitor",
        services=["slack"],
    )
    next(gen)
    with pytest.raises(MissionEndedError) as info:
        next(gen)
    assert info.value.mission_state == "expired"


def test_async_context_manager_mirrors_sync_order():
    async def run() -> None:
        client = AsyncRouteClient({"/v1/missions/start": _start_response(), "/checkout": _CHECKOUT})
        async with AsyncPassportService(client).mission(  # type: ignore[arg-type]
            agent_id="agt_x",
            intent="i",
            services=["slack"],
        ) as m:
            assert m.mission_id == "ms_opened"
        assert _paths(client) == [
            "/v1/missions/start",
            "/v1/passports/ppt_1/checkout",
            "/v1/missions/ms_opened/complete",
        ]

        failing = AsyncRouteClient({"/v1/missions/start": _start_response(), "/checkout": _CHECKOUT})
        with pytest.raises(KeyError):
            async with AsyncPassportService(failing).mission(  # type: ignore[arg-type]
                agent_id="agt_x",
                intent="i",
                services=["slack"],
            ):
                raise KeyError("boom")
        assert _paths(failing)[-2:] == ["/v1/passports/ppt_1/checkout", "/v1/missions/ms_opened/revoke"]

        bound = AsyncRouteClient({"/v1/passports/issue": _ISSUED, "/checkout": _CHECKOUT})
        async with AsyncPassportService(bound).mission(  # type: ignore[arg-type]
            agent_id="agt_x",
            intent="i",
            services=["slack"],
            mission_id="ms_mine",
        ):
            pass
        assert _paths(bound) == ["/v1/passports/issue", "/v1/passports/ppt_2/checkout"]

        rotating = AsyncRouteClient(
            {"/v1/missions/start": _start_response(), "/v1/passports/issue": _ISSUED, "/checkout": _CHECKOUT}
        )
        gen = AsyncPassportService(rotating).continuous_mission(  # type: ignore[arg-type]
            agent_id="agt_x",
            intent="i",
            services=["slack"],
        )
        await gen.__anext__()
        await gen.__anext__()
        await gen.aclose()
        assert rotating.calls[2][2]["mission_ids"] == ["ms_opened"]
        assert _paths(rotating)[-1] == "/v1/missions/ms_opened/complete"

    asyncio.run(run())


# ── refresh once the Mission ended ─────────────────────────────────────


@pytest.mark.parametrize(
    "error, state",
    [
        (ForbiddenError("Mission ms_a is completed"), "completed"),
        (ForbiddenError("Mission ms_a is revoked"), "revoked"),
        (ForbiddenError("Mission ms_a has expired"), "expired"),
        (NotFoundError("Mission not found: ms_a"), "not_found"),
        (NotFoundError("Mission ms_a not found"), "not_found"),
    ],
)
def test_session_refresh_raises_mission_ended(error, state):
    client = RouteClient({"/v1/passports/refresh": error})
    session = PassportSession(client, {"token": _token(exp_offset=10)}, {"ttl_seconds": 900})  # type: ignore[arg-type]
    with pytest.raises(MissionEndedError) as info:
        session.get_token()
    assert info.value.mission_id == "ms_a"
    assert info.value.mission_state == state
    assert info.value.status_code == error.status_code
    assert "Open a new Mission" in str(info.value)

    async def run() -> None:
        aclient = AsyncRouteClient({"/v1/passports/refresh": error})
        asession = AsyncPassportSession(aclient, {"token": _token(exp_offset=10)}, {})  # type: ignore[arg-type]
        with pytest.raises(MissionEndedError):
            await asession.get_token()

    asyncio.run(run())


def test_refresh_keeps_unrelated_errors():
    client = RouteClient({"/v1/passports/refresh": ForbiddenError("Passport revoked")})
    with pytest.raises(ForbiddenError) as info:
        PassportService(client).refresh("tok")  # type: ignore[arg-type]
    assert not isinstance(info.value, MissionEndedError)
    ended = RouteClient({"/v1/passports/refresh": ForbiddenError("Mission ms_a is revoked")})
    with pytest.raises(MissionEndedError):
        PassportService(ended).refresh("tok")  # type: ignore[arg-type]


# ── Stack.issue_passport and partner tenants ───────────────────────────


def test_stack_issue_passport_sends_the_mission():
    stack = Stack(api_key="sk_test_fixture")
    stack._client = client = RouteClient({"/v1/passports/issue": {"token": _token()}})  # type: ignore[assignment]
    stack.issue_passport(agent_id="agt_x", mission_ids=["ms_a"])
    assert client.calls[0][2]["mission_ids"] == ["ms_a"]


def test_partner_account_passports_require_a_mission():
    client = RouteClient({"/passports/issue": {"token": "tok", "jti": "ppt_t", "expires_at": "x"}})
    service = PartnerAccountsService(client)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exactly one Mission"):
        service.issue_passport("op_account", "agt_t")
    service.issue_passport("op_account", "agt_t", mission_ids=["ms_t"])
    minted = service.mint_outbound_passport("op_account", "agt_t", mission_id="ms_t")
    assert minted["passport_id"] == "ppt_t"
    assert [json["mission_ids"] for _m, _p, json in client.calls] == [["ms_t"], ["ms_t"]]
    with pytest.raises(TypeError):
        service.mint_outbound_passport("op_account", "agt_t")  # type: ignore[call-arg]

    async def run() -> None:
        aclient = AsyncRouteClient({"/passports/issue": {"token": "tok", "jti": "ppt_t", "expires_at": "x"}})
        aservice = AsyncPartnerAccountsService(aclient)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await aservice.issue_passport("op_account", "agt_t")
        await aservice.mint_outbound_passport("op_account", "agt_t", mission_id="ms_t")
        assert aclient.calls[0][2]["mission_ids"] == ["ms_t"]

    asyncio.run(run())
