from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.missions import AsyncMissionsService
from getstack.missions import MissionsService


class CaptureClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.response: dict = {"items": []}

    def request(self, method: str, path: str, **_kwargs):
        self.calls.append((method, path))
        return self.response

    def request_bytes(self, method: str, path: str) -> bytes:
        self.calls.append((method, path))
        return b"\xd2\x84\x43"


class AsyncCaptureClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.response: dict = {"items": []}

    async def request(self, method: str, path: str, **_kwargs):
        self.calls.append((method, path))
        return self.response

    async def request_bytes(self, method: str, path: str) -> bytes:
        self.calls.append((method, path))
        return b"\xd2\x84\x43"


def test_sync_activity_review_list_and_download_paths():
    client = CaptureClient()
    service = MissionsService(client)  # type: ignore[arg-type]

    service.activity("ms_one/two")
    service.list_operator_reviews("ms_one/two")
    assert service.download_operator_review("ms_one/two", "pc_review/one") == b"\xd2\x84\x43"

    assert client.calls == [
        ("GET", "/v1/missions/ms_one%2Ftwo/replay"),
        ("GET", "/v1/missions/ms_one%2Ftwo/operator-reviews"),
        ("GET", "/v1/missions/ms_one%2Ftwo/operator-reviews/pc_review%2Fone/download"),
    ]


def test_async_activity_review_list_and_download_paths():
    async def run() -> None:
        client = AsyncCaptureClient()
        service = AsyncMissionsService(client)  # type: ignore[arg-type]

        await service.activity("ms_one/two")
        await service.list_operator_reviews("ms_one/two")
        assert await service.download_operator_review("ms_one/two", "pc_review/one") == b"\xd2\x84\x43"

        assert client.calls == [
            ("GET", "/v1/missions/ms_one%2Ftwo/replay"),
            ("GET", "/v1/missions/ms_one%2Ftwo/operator-reviews"),
            ("GET", "/v1/missions/ms_one%2Ftwo/operator-reviews/pc_review%2Fone/download"),
        ]

    asyncio.run(run())


def test_legacy_read_aliases_use_new_review_list_route():
    client = CaptureClient()
    service = MissionsService(client)  # type: ignore[arg-type]

    service.replay("ms_one")
    service.list_dossiers("ms_one")

    assert client.calls == [
        ("GET", "/v1/missions/ms_one/replay"),
        ("GET", "/v1/missions/ms_one/operator-reviews"),
    ]


def test_legacy_dossier_read_keeps_the_old_shape_and_filters_new_reviews():
    client = CaptureClient()
    client.response = {
        "items": [
            {
                "claim_id": "pc_old",
                "issued_at_ms": 1,
                "claim": {"type": "dossier", "narrative": "old"},
            },
            {
                "claim_id": "pc_new",
                "issued_at_ms": 2,
                "claim": {"type": "operator_review", "overall_judgment": "new"},
            },
        ]
    }

    result = MissionsService(client).list_dossiers("ms_one")  # type: ignore[arg-type]

    assert result == {
        "items": [
            {
                "claim_id": "pc_old",
                "operator_id": None,
                "issued_at_ms": 1,
                "body": {"type": "dossier", "narrative": "old"},
            }
        ]
    }


def test_async_legacy_dossier_read_keeps_the_old_shape():
    async def run() -> None:
        client = AsyncCaptureClient()
        client.response = {
            "items": [
                {
                    "claim_id": "pc_old",
                    "issued_at_ms": 1,
                    "claim": {"type": "dossier", "narrative": "old"},
                }
            ]
        }

        result = await AsyncMissionsService(client).list_dossiers("ms_one")  # type: ignore[arg-type]
        assert result["items"][0]["body"]["type"] == "dossier"

    asyncio.run(run())


class BodyClient:
    """Keeps the JSON body of each request."""

    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def request(self, method: str, path: str, **kwargs):
        self.bodies.append(kwargs.get("json"))
        return {}


class AsyncBodyClient(BodyClient):
    async def request(self, method: str, path: str, **kwargs):  # type: ignore[override]
        return super().request(method, path, **kwargs)


RECIPIENT_PINS = [{"path": "url.pathname", "op": "eq", "value": "/v1/chats/42"}]


def test_open_sends_the_recipient_fields_only_when_given():
    client = BodyClient()
    service = MissionsService(client)  # type: ignore[arg-type]

    service.open("Answer one customer", agent_id="agt_1")
    service.open(
        "Answer one customer",
        agent_id="agt_1",
        recipients=["Ana@example.com", "+14155550100"],
        recipient_pins=RECIPIENT_PINS,
        reply_to_message="msg_1",
    )

    assert client.bodies == [
        {"intent_summary": "Answer one customer", "agent_id": "agt_1"},
        {
            "intent_summary": "Answer one customer",
            "agent_id": "agt_1",
            "recipients": ["Ana@example.com", "+14155550100"],
            "recipient_pins": RECIPIENT_PINS,
            "reply_to_message": "msg_1",
        },
    ]


def test_async_open_sends_the_recipient_fields_only_when_given():
    async def run() -> None:
        client = AsyncBodyClient()
        service = AsyncMissionsService(client)  # type: ignore[arg-type]

        await service.open("Answer one customer", agent_id="agt_1")
        await service.open(
            "Answer one customer", agent_id="agt_1", recipients=["ana@example.com"], reply_to_message="msg_1"
        )

        assert client.bodies == [
            {"intent_summary": "Answer one customer", "agent_id": "agt_1"},
            {
                "intent_summary": "Answer one customer",
                "agent_id": "agt_1",
                "recipients": ["ana@example.com"],
                "reply_to_message": "msg_1",
            },
        ]

    asyncio.run(run())


def test_start_passes_the_recipient_fields_inside_the_mission():
    client = BodyClient()
    mission = {"intent_summary": "Answer one customer", "recipients": ["ana@example.com"], "reply_to_message": "msg_1"}

    MissionsService(client).start(agent_id="agt_1", mission=mission)  # type: ignore[arg-type]

    assert client.bodies == [{"agent_id": "agt_1", "mission": mission}]


def test_the_any_field_pin_path_is_a_star():
    from getstack.missions import MISSION_RECIPIENT_ANY_PATH

    assert MISSION_RECIPIENT_ANY_PATH == "*"


class CapBodyClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []

    def request(self, method: str, path: str, **kwargs):
        self.calls.append((method, path, kwargs.get("json")))
        return {"mission_id": "ms_1"}


class AsyncCapBodyClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []

    async def request(self, method: str, path: str, **kwargs):
        self.calls.append((method, path, kwargs.get("json")))
        return {"mission_id": "ms_1"}


def test_open_sends_the_cap_behaviours_the_daily_money_cap_and_the_making_allowance():
    client = CapBodyClient()
    MissionsService(client).open(  # type: ignore[arg-type]
        "Print the posters",
        coverage_cap_cents=5_000,
        cap_behavior={"coverage_cap_cents": "pause", "max_actions": "refuse_action"},
        coverage_cap_period="day",
        cap_time_zone="America/New_York",
        making_orders_up_to_cents=20_000,
    )
    method, path, body = client.calls[0]
    assert (method, path) == ("POST", "/v1/missions")
    assert body == {
        "intent_summary": "Print the posters",
        "coverage_cap_cents": 5_000,
        "cap_behavior": {"coverage_cap_cents": "pause", "max_actions": "refuse_action"},
        "coverage_cap_period": "day",
        "cap_time_zone": "America/New_York",
        "making_orders_up_to_cents": 20_000,
    }


def test_review_and_making_allowance_reach_their_routes_and_refuse_a_bad_review_first():
    client = CapBodyClient()
    service = MissionsService(client)  # type: ignore[arg-type]
    service.review("ms_1", "raise", limit=500)
    service.review("ms_1", "continue")
    service.set_making_allowance("ms_1", None)
    assert client.calls == [
        ("POST", "/v1/missions/ms_1/review", {"decision": "raise", "limit": 500}),
        ("POST", "/v1/missions/ms_1/review", {"decision": "continue"}),
        ("PUT", "/v1/missions/ms_1/making-allowance", {"making_orders_up_to_cents": None}),
    ]
    for decision, limit in (("raise", None), ("close", 5), ("pause", None)):
        try:
            service.review("ms_1", decision, limit=limit)
        except ValueError:
            continue
        raise AssertionError(f"{decision} was sent")
    assert len(client.calls) == 3


def test_async_review_and_making_allowance_match_the_sync_service():
    async def run() -> None:
        client = AsyncCapBodyClient()
        service = AsyncMissionsService(client)  # type: ignore[arg-type]
        await service.review("ms_1", "close")
        await service.set_making_allowance("ms_1", 10_000)
        assert client.calls == [
            ("POST", "/v1/missions/ms_1/review", {"decision": "close"}),
            ("PUT", "/v1/missions/ms_1/making-allowance", {"making_orders_up_to_cents": 10_000}),
        ]

    asyncio.run(run())


class BodyClient(CaptureClient):
    def __init__(self) -> None:
        super().__init__()
        self.bodies: list = []

    def request(self, method: str, path: str, **kwargs):
        self.bodies.append(kwargs.get("json"))
        return super().request(method, path)


def test_add_recipients_posts_only_the_fields_given_for_both_clients():
    client = BodyClient()
    MissionsService(client).add_recipients("ms_one", recipients=["ana@example.com"])  # type: ignore[arg-type]
    assert client.calls == [("POST", "/v1/missions/ms_one/recipients")]
    assert client.bodies == [{"recipients": ["ana@example.com"]}]
    try:
        MissionsService(client).add_recipients("ms_one")  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("an empty addition must be refused before any request")
    assert len(client.calls) == 1

    async def run() -> None:
        async_client = AsyncCaptureClient()
        await AsyncMissionsService(async_client).add_recipients("ms_one", reply_to_message="acall_1")  # type: ignore[arg-type]
        assert async_client.calls == [("POST", "/v1/missions/ms_one/recipients")]

    asyncio.run(run())
