"""Drop-off client wire-contract tests."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.dropoffs import AsyncDropoffService
from getstack.dropoffs import DropoffService


class CaptureClient:
    def __init__(self) -> None:
        self.path: str | None = None
        self.body: dict | None = None
        self.headers: dict | None = None

    def post(self, path: str, json: dict | None = None, extra_headers: dict | None = None):
        self.path = path
        self.body = json
        self.headers = extra_headers
        return {}


class AsyncCaptureClient(CaptureClient):
    async def post(self, path: str, json: dict | None = None, extra_headers: dict | None = None):
        return super().post(path, json=json, extra_headers=extra_headers)


def test_sync_deposit_threads_passport_mission_attribution() -> None:
    client = CaptureClient()
    service = DropoffService(client)  # type: ignore[arg-type]

    service.deposit(
        "dof_one",
        {"value": 1},
        "agt_producer",
        passport_jti="pas_one",
        mission_id="ms_one",
    )

    assert client.path == "/v1/dropoffs/dof_one/deposit"
    assert client.body == {
        "agent_id": "agt_producer",
        "payload": {"value": 1},
        "passport_jti": "pas_one",
        "mission_id": "ms_one",
    }


def test_async_deposit_threads_passport_mission_attribution() -> None:
    client = AsyncCaptureClient()
    service = AsyncDropoffService(client)  # type: ignore[arg-type]

    asyncio.run(
        service.deposit(
            "dof_one",
            {"value": 1},
            "agt_producer",
            passport_jti="pas_one",
            mission_id="ms_one",
        )
    )

    assert client.path == "/v1/dropoffs/dof_one/deposit"
    assert client.body == {
        "agent_id": "agt_producer",
        "payload": {"value": 1},
        "passport_jti": "pas_one",
        "mission_id": "ms_one",
    }


def test_sync_create_deposit_collect_send_the_mission_passport() -> None:
    client = CaptureClient()
    service = DropoffService(client)  # type: ignore[arg-type]
    header = {"X-Passport-Token": "jwt.passport.token"}

    service.create("agt_producer", "agt_consumer", {"type": "object"}, passport_token="jwt.passport.token")
    assert client.path == "/v1/dropoffs"
    assert client.headers == header

    service.deposit("dof_one", {"value": 1}, "agt_producer", passport_token="jwt.passport.token")
    assert client.path == "/v1/dropoffs/dof_one/deposit"
    assert client.body == {"agent_id": "agt_producer", "payload": {"value": 1}}
    assert client.headers == header

    service.collect("dof_one", "agt_consumer", passport_token="jwt.passport.token")
    assert client.path == "/v1/dropoffs/dof_one/collect"
    assert client.body == {"agent_id": "agt_consumer"}
    assert client.headers == header


def test_async_create_deposit_collect_send_the_mission_passport() -> None:
    client = AsyncCaptureClient()
    service = AsyncDropoffService(client)  # type: ignore[arg-type]
    header = {"X-Passport-Token": "jwt.passport.token"}

    asyncio.run(service.create("agt_producer", "agt_consumer", {"type": "object"}, passport_token="jwt.passport.token"))
    assert client.path == "/v1/dropoffs"
    assert client.headers == header

    asyncio.run(service.deposit("dof_one", {"value": 1}, "agt_producer", passport_token="jwt.passport.token"))
    assert client.path == "/v1/dropoffs/dof_one/deposit"
    assert client.headers == header

    asyncio.run(service.collect("dof_one", "agt_consumer", passport_token="jwt.passport.token"))
    assert client.path == "/v1/dropoffs/dof_one/collect"
    assert client.body == {"agent_id": "agt_consumer"}
    assert client.headers == header


def test_create_names_one_agent_as_to_agent_and_a_group_as_to_agents() -> None:
    client = CaptureClient()
    service = DropoffService(client)  # type: ignore[arg-type]

    service.create("agt_producer", "agt_one", {"type": "object"})
    assert client.body == {"from_agent": "agt_producer", "to_agent": "agt_one", "schema": {"type": "object"}}

    service.create("agt_producer", ["agt_one", "agt_two", "agt_three"], {"type": "object"})
    assert client.body == {
        "from_agent": "agt_producer",
        "to_agents": ["agt_one", "agt_two", "agt_three"],
        "schema": {"type": "object"},
    }


def test_async_create_names_a_group_as_to_agents() -> None:
    client = AsyncCaptureClient()
    asyncio.run(AsyncDropoffService(client).create("agt_producer", ["agt_one", "agt_two"], {"type": "object"}))  # type: ignore[arg-type]
    assert client.body == {
        "from_agent": "agt_producer",
        "to_agents": ["agt_one", "agt_two"],
        "schema": {"type": "object"},
    }


def test_collect_without_a_passport_sends_no_passport_header() -> None:
    client = CaptureClient()
    DropoffService(client).collect("dof_one", "agt_consumer")  # type: ignore[arg-type]
    assert client.headers is None
