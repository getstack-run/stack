from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.fleets import AsyncFleetsService
from getstack._async.missions import AsyncMissionsService
from getstack._async.passports import AsyncPassportService
from getstack.fleets import FleetsService
from getstack.missions import MissionsService
from getstack.passports import PassportService


@pytest.mark.parametrize("client_name", ["Stack", "AsyncStack"])
def test_enrolled_worker_needs_no_operator_credentials(monkeypatch, client_name):
    import jwt

    import getstack
    from getstack import agent_auth

    def no_operator_credentials(**kwargs):
        raise AssertionError("Enrolled worker requested operator credentials")

    monkeypatch.setattr(getstack, "_build_static_auth", no_operator_credentials)
    _, public, private = agent_auth._generate_keypair()
    monkeypatch.setattr(
        agent_auth,
        "_load_stored",
        lambda agent_id: {"agent_id": agent_id, "publicKey": public, "privateKey": private, "enrolled_at": 1},
    )
    client = getattr(getstack, client_name)(agent_id="agt_worker")
    headers = client._client.auth.get_headers()
    claims = jwt.decode(headers["Authorization"].split(" ", 1)[1], options={"verify_signature": False})
    assert claims["sub"] == "agt_worker"
    assert claims["aud"] == "stack:agent"


class Capture:
    def __init__(self):
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return {"token": "fixture", "jti": "jti_fixture", "expires_at": "2030-01-01"}

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


class AsyncCapture(Capture):
    async def request(self, method, path, **kwargs):
        return super().request(method, path, **kwargs)

    async def post(self, path, **kwargs):
        return await self.request("POST", path, **kwargs)


REQUEST = {
    "fleet_policy_id": "flp_fixture",
    "idempotency_key": "op-123",
    "intent_summary": "Support update",
    "requested_access": [
        {
            "connection_id": "scon_fixture",
            "scopes": ["chat:write"],
            "intents": [{"name": "slack.post_to_channel", "params": {"channel": "C123"}}],
            "allow_data_from": ["github"],
        }
    ],
    "requested_operations": [{"producer": "skill", "target_id": "skl_fixture", "action": "invoke"}],
    "limits": {"max_actions": 20, "max_concurrent_actions": 2, "max_duration_seconds": 900},
    "authority_binding_ids": ["abn_fixture"],
    "expected_output_shape": {"type": "object"},
}


def test_sync_async_fleet_contract_matches():
    sync = Capture()
    fleets = FleetsService(sync)
    fleets.revise(
        "flp_one/two",
        {"name": "Policy"},
        expected_revision=2,
        idempotency_key="revision-123",
        governance_approval_id="gvr_fixture",
    )
    fleets.session()
    fleets.members("flp_one/two")
    fleets.revoke_member("flp_one/two", "agt_one/two")
    MissionsService(sync).start(REQUEST)
    MissionsService(sync).renew("ms_one/two")
    PassportService(sync).issue("agt_fixture", mission_ids=["ms_fixture"])
    PassportService(sync).delegate(
        "fixture", "agt_child", scopes=[{"service_connection_id": "scon_fixture", "scopes": ["read"]}]
    )

    async def run():
        client = AsyncCapture()
        fleets = AsyncFleetsService(client)
        await fleets.revise(
            "flp_one/two",
            {"name": "Policy"},
            expected_revision=2,
            idempotency_key="revision-123",
            governance_approval_id="gvr_fixture",
        )
        await fleets.session()
        await fleets.members("flp_one/two")
        await fleets.revoke_member("flp_one/two", "agt_one/two")
        await AsyncMissionsService(client).start(REQUEST)
        await AsyncMissionsService(client).renew("ms_one/two")
        await AsyncPassportService(client).issue("agt_fixture", mission_ids=["ms_fixture"])
        await AsyncPassportService(client).delegate(
            "fixture", "agt_child", scopes=[{"service_connection_id": "scon_fixture", "scopes": ["read"]}]
        )
        return client.calls

    assert asyncio.run(run()) == sync.calls
    assert sync.calls[0] == (
        "PUT",
        "/v1/fleets/flp_one%2Ftwo",
        {
            "json": {"name": "Policy"},
            "extra_headers": {
                "If-Match": "2",
                "Idempotency-Key": "revision-123",
                "X-Governance-Approval": "gvr_fixture",
            },
        },
    )
    assert sync.calls[4] == ("POST", "/v1/missions/start", {"json": REQUEST})
    assert sync.calls[-2][2]["json"]["mission_ids"] == ["ms_fixture"]
    assert sync.calls[-1][2]["json"] == {
        "parent_passport_token": "fixture",
        "child_agent_id": "agt_child",
        "scopes": [{"service_connection_id": "scon_fixture", "scopes": ["read"]}],
    }
