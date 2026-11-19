"""Focused Python SDK authority and runtime-binding contract tests."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.authority import AsyncAuthorityService
from getstack._async.llm import AsyncLlmService
from getstack._async.passports import AsyncMission
from getstack._async.proxy import AsyncProxyService
from getstack._async.skills import AsyncSkillService
from getstack.authority import AuthorityService
from getstack.llm import LlmService
from getstack.passports import Mission
from getstack.proxy import ProxyService
from getstack.skills import SkillService


class _SyncCaptureClient:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"method": method, "path": path, **kwargs})
        if path == "/v1/authority/enterprise-oidc/requests":
            return {"request_id": "aor_1", "status": "pending", "approval_url": "https://example.test/approve"}
        if path == "/v1/authority/principals":
            return {"principal": {"id": "prn_1"}, "principals": [{"id": "prn_1"}]}
        if path.endswith("/activate"):
            return {"binding": {"id": "abn_1", "version": 2}}
        if path == "/v1/proxy":
            return {"status": 200, "headers": {}, "body": {"ok": True}}
        if path.endswith("/invoke"):
            return {"id": "sinv_1", "skill_id": "sk_1", "status": "completed"}
        return {"ok": True}

    def get(self, path: str, params: dict[str, Any] | None = None, **kwargs: Any):
        return self._call("GET", path, params=params, **kwargs)

    def post(self, path: str, json: Any = None, **kwargs: Any):
        return self._call("POST", path, json=json, **kwargs)

    def request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        return self._call(method, path, json=json, params=params, **kwargs)


class _AsyncCaptureClient(_SyncCaptureClient):
    async def get(self, path: str, params: dict[str, Any] | None = None, **kwargs: Any):
        return self._call("GET", path, params=params, **kwargs)

    async def post(self, path: str, json: Any = None, **kwargs: Any):
        return self._call("POST", path, json=json, **kwargs)

    async def request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        return self._call(method, path, json=json, params=params, **kwargs)


def test_authority_sync_routes_unwrap_and_send_idempotency_and_version():
    client = _SyncCaptureClient()
    service = AuthorityService(client)  # type: ignore[arg-type]

    assert service.create_principal(principal_kind="individual", idempotency_key="idem-create") == {"id": "prn_1"}
    assert service.list_principals() == [{"id": "prn_1"}]
    assert service.activate_binding("abn_1", version=2, idempotency_key="idem-activate") == {
        "id": "abn_1",
        "version": 2,
    }

    create_call, _, activate_call = client.calls
    assert create_call == {
        "method": "POST",
        "path": "/v1/authority/principals",
        "json": {"principal_kind": "individual"},
        "extra_headers": {"Idempotency-Key": "idem-create"},
    }
    assert activate_call["json"] == {}
    assert activate_call["params"] == {"version": 2}
    assert activate_call["extra_headers"] == {"Idempotency-Key": "idem-activate"}


def test_authority_request_sync_and_async_return_human_approval_url():
    input = {
        "organisation_name": "Example AB",
        "role_name": "CFO",
        "role_claim_path": "roles",
        "role_claim_value": "cfo",
        "agent_id": "agt_finance",
        "service_connection_id": "scon_stripe",
        "provider": "stripe",
        "purpose": "Send one approved payment",
        "http_method": "POST",
        "resource_path": "/v1/payments",
        "expires_at": "2026-08-26T12:30:00Z",
    }
    sync_client = _SyncCaptureClient()
    result = AuthorityService(sync_client).create_enterprise_oidc_request(
        idempotency_key="authority-request-1", **input
    )
    assert result["status"] == "pending"
    assert sync_client.calls[0]["extra_headers"] == {"Idempotency-Key": "authority-request-1"}

    async def run() -> None:
        async_client = _AsyncCaptureClient()
        async_result = await AsyncAuthorityService(async_client).create_enterprise_oidc_request(
            idempotency_key="authority-request-1", **input
        )
        assert async_result["approval_url"] == "https://example.test/approve"

    asyncio.run(run())


def test_authority_async_matches_sync_contract():
    async def run() -> None:
        client = _AsyncCaptureClient()
        service = AsyncAuthorityService(client)  # type: ignore[arg-type]
        assert await service.create_principal(principal_kind="organisation", idempotency_key="idem-create") == {
            "id": "prn_1"
        }
        assert await service.activate_binding("abn_1", version=2, idempotency_key="idem-activate") == {
            "id": "abn_1",
            "version": 2,
        }
        assert client.calls[0]["extra_headers"] == {"Idempotency-Key": "idem-create"}
        assert client.calls[1]["params"] == {"version": 2}

    asyncio.run(run())


def test_stack_clients_expose_authority_and_passport_binding_input():
    sync = Stack(api_key="sk_live_dummy", base_url="http://localhost:9999")
    async_client = AsyncStack(api_key="sk_live_dummy", base_url="http://localhost:9999")
    try:
        assert isinstance(sync.authority, AuthorityService)
        assert isinstance(async_client.authority, AsyncAuthorityService)
        assert "authority_binding_ids" in inspect.signature(sync.issue_passport).parameters
        assert "authority_binding_ids" in inspect.signature(async_client.issue_passport).parameters
    finally:
        sync.close()
        asyncio.run(async_client.close())


def test_passport_header_uses_deployment_jwks_and_agent_subject(monkeypatch):
    module = importlib.import_module("getstack.passport_header_verify")
    requested_urls: list[str] = []

    class FakeJwksClient:
        def get_signing_key_from_jwt(self, token: str):
            assert token == "signed.jwt.value"
            return SimpleNamespace(key="deployment-public-key")

    def get_client(url: str):
        requested_urls.append(url)
        return FakeJwksClient()

    claims = {
        "sub": "agt_1",
        "jti": "ppt_1",
        "iss": "getstack.run",
        "aud": "stack:passport",
        "exp": 4_102_444_800,
        "stk": {
            "operator_id": "op_1",
            "agent_id": "agt_1",
            "authority_refs": [
                {
                    "binding_id": "abn_1",
                    "binding_version": 1,
                    "binding_claim_id": "pc_1",
                    "binding_digest": "sha256:digest",
                    "receiver_id": "rcv_1",
                    "receiver_profile_version_id": "apv_1",
                    "expires_at": 4_102_444_800,
                }
            ],
        },
    }

    monkeypatch.setattr(module, "_get_jwks_client", get_client)
    monkeypatch.setattr(module.jwt, "decode", lambda *args, **kwargs: claims)

    verified = module.verify_passport_header("signed.jwt.value", base_url="https://api.example.test/")
    assert requested_urls == ["https://api.example.test/v1/.well-known/jwks.json"]
    assert verified["sub"] == "agt_1"
    assert verified["stk"]["operator_id"] == "op_1"
    assert verified["stk"]["authority_refs"][0]["binding_id"] == "abn_1"


def test_passport_header_rejects_subject_agent_mismatch(monkeypatch):
    module = importlib.import_module("getstack.passport_header_verify")
    monkeypatch.setattr(
        module,
        "_get_jwks_client",
        lambda _: SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key="key")),
    )
    monkeypatch.setattr(
        module.jwt,
        "decode",
        lambda *args, **kwargs: {
            "sub": "agt_1",
            "stk": {"operator_id": "op_1", "agent_id": "agt_other"},
        },
    )
    with pytest.raises(ValueError, match=r"sub does not match stk.agent_id"):
        module.verify_passport_header("signed.jwt.value")


def test_runtime_calls_thread_authority_request_id_sync():
    request_id = "0123456789abcdefghijkl"
    client = _SyncCaptureClient()

    ProxyService(client).request(  # type: ignore[arg-type]
        "stripe",
        "https://api.stripe.test/v1/charges",
        passport_token="passport",
        authority_request_id=request_id,
    )
    SkillService(client).invoke(  # type: ignore[arg-type]
        "sk_1", agent_id="agt_1", input={}, authority_request_id=request_id
    )
    llm = LlmService(client)  # type: ignore[arg-type]
    llm.anthropic.messages.create({}, passport="passport", authority_request_id=request_id)
    llm.openai.chat.completions.create({}, passport="passport", authority_request_id=request_id)
    llm.openrouter.chat.completions.create({}, passport="passport", authority_request_id=request_id)

    assert len(client.calls) == 5
    for call in client.calls:
        assert call["extra_headers"]["X-STACK-Authority-Request-Id"] == request_id


def test_proxy_generates_exposes_and_recovers_operation_id_sync():
    persisted: list[str] = []

    class PersistenceCheckingClient(_SyncCaptureClient):
        def request(self, *args: Any, **kwargs: Any):
            assert persisted
            return super().request(*args, **kwargs)

    client = PersistenceCheckingClient()
    response = ProxyService(client).request(  # type: ignore[arg-type]
        "stripe",
        "https://api.stripe.test/v1/refunds",
        method="POST",
        passport_token="passport",
        on_operation_id=persisted.append,
    )
    assert response.operation_id is not None
    assert len(response.operation_id) >= 22
    assert client.calls[0]["extra_headers"]["X-STACK-Authority-Request-Id"] == response.operation_id

    result = ProxyService(client).get_operation(  # type: ignore[arg-type]
        response.operation_id, passport_token="passport", include_response=True
    )
    assert result == {"ok": True}
    assert client.calls[1]["path"] == "/v1/proxy/operations/get"
    assert client.calls[1]["json"] == {
        "operation_id": response.operation_id,
        "include_response": True,
    }
    assert client.calls[1]["extra_headers"] == {"X-Passport-Token": "passport"}


def test_mission_proxy_persists_operation_id_before_sync_request():
    persisted: list[str] = []
    client = _SyncCaptureClient()
    mission = Mission(  # type: ignore[arg-type]
        SimpleNamespace(), "agt_1", "Create issue", ["github"]
    )
    mission.passport = SimpleNamespace(token="passport")  # type: ignore[assignment]

    response = mission.proxy(
        "github",
        "https://api.github.test/repos/acme/example/issues",
        method="POST",
        body={"title": "Typo"},
        on_operation_id=persisted.append,
        _proxy_service=ProxyService(client),  # type: ignore[arg-type]
    )

    assert persisted == [response.operation_id]
    assert client.calls[0]["extra_headers"]["X-STACK-Authority-Request-Id"] == response.operation_id


def test_proxy_preserves_generated_operation_id_on_error_sync():
    class FailingClient(_SyncCaptureClient):
        def request(self, *args: Any, **kwargs: Any):
            raise RuntimeError("response lost")

    with pytest.raises(RuntimeError) as raised:
        ProxyService(FailingClient()).request(  # type: ignore[arg-type]
            "stripe",
            "https://api.stripe.test/v1/refunds",
            method="POST",
            passport_token="passport",
        )
    assert len(raised.value.operation_id) >= 22  # type: ignore[attr-defined]


def test_runtime_calls_thread_authority_request_id_async():
    async def run() -> None:
        request_id = "0123456789abcdefghijkl"
        client = _AsyncCaptureClient()

        await AsyncProxyService(client).request(  # type: ignore[arg-type]
            "stripe",
            "https://api.stripe.test/v1/charges",
            passport_token="passport",
            authority_request_id=request_id,
        )
        await AsyncSkillService(client).invoke(  # type: ignore[arg-type]
            "sk_1", agent_id="agt_1", input={}, authority_request_id=request_id
        )
        llm = AsyncLlmService(client)  # type: ignore[arg-type]
        await llm.anthropic.messages.create({}, passport="passport", authority_request_id=request_id)
        await llm.openai.chat.completions.create({}, passport="passport", authority_request_id=request_id)
        await llm.openrouter.chat.completions.create({}, passport="passport", authority_request_id=request_id)

        assert len(client.calls) == 5
        for call in client.calls:
            assert call["extra_headers"]["X-STACK-Authority-Request-Id"] == request_id

    asyncio.run(run())


def test_proxy_generates_exposes_and_recovers_operation_id_async():
    async def run() -> None:
        persisted: list[str] = []

        class PersistenceCheckingClient(_AsyncCaptureClient):
            async def request(self, *args: Any, **kwargs: Any):
                assert persisted
                return await super().request(*args, **kwargs)

        async def persist(operation_id: str) -> None:
            await asyncio.sleep(0)
            persisted.append(operation_id)

        client = PersistenceCheckingClient()
        response = await AsyncProxyService(client).request(  # type: ignore[arg-type]
            "stripe",
            "https://api.stripe.test/v1/refunds",
            method="POST",
            passport_token="passport",
            on_operation_id=persist,
        )
        assert response.operation_id is not None
        assert len(response.operation_id) >= 22
        assert client.calls[0]["extra_headers"]["X-STACK-Authority-Request-Id"] == response.operation_id

        result = await AsyncProxyService(client).get_operation(  # type: ignore[arg-type]
            response.operation_id, passport_token="passport", include_response=True
        )
        assert result == {"ok": True}
        assert client.calls[1]["path"] == "/v1/proxy/operations/get"
        assert client.calls[1]["json"]["operation_id"] == response.operation_id

    asyncio.run(run())


def test_async_mission_proxy_persists_operation_id_before_request():
    async def run() -> None:
        persisted: list[str] = []
        client = _AsyncCaptureClient()
        mission = AsyncMission(  # type: ignore[arg-type]
            SimpleNamespace(), "agt_1", "Create issue", ["github"]
        )
        mission.passport = SimpleNamespace(token="passport")  # type: ignore[assignment]

        async def persist(operation_id: str) -> None:
            persisted.append(operation_id)

        response = await mission.proxy(
            "github",
            "https://api.github.test/repos/acme/example/issues",
            method="POST",
            body={"title": "Typo"},
            on_operation_id=persist,
            _proxy_service=AsyncProxyService(client),  # type: ignore[arg-type]
        )

        assert persisted == [response.operation_id]
        assert client.calls[0]["extra_headers"]["X-STACK-Authority-Request-Id"] == response.operation_id

    asyncio.run(run())


def test_proxy_preserves_generated_operation_id_on_error_async():
    class FailingClient(_AsyncCaptureClient):
        async def request(self, *args: Any, **kwargs: Any):
            raise RuntimeError("response lost")

    async def run() -> None:
        with pytest.raises(RuntimeError) as raised:
            await AsyncProxyService(FailingClient()).request(  # type: ignore[arg-type]
                "stripe",
                "https://api.stripe.test/v1/refunds",
                method="POST",
                passport_token="passport",
            )
        assert len(raised.value.operation_id) >= 22  # type: ignore[attr-defined]

    asyncio.run(run())


def test_runtime_calls_reject_malformed_authority_request_id_sync():
    client = _SyncCaptureClient()

    with pytest.raises(ValueError, match="22-256 base64url"):
        ProxyService(client).request(  # type: ignore[arg-type]
            "stripe",
            "https://api.stripe.test/v1/charges",
            passport_token="passport",
            authority_request_id="short",
        )
    with pytest.raises(ValueError, match="22-256 base64url"):
        SkillService(client).invoke(  # type: ignore[arg-type]
            "sk_1",
            agent_id="agt_1",
            input={},
            authority_request_id="contains spaces and !",
        )
    with pytest.raises(ValueError, match="22-256 base64url"):
        LlmService(client).anthropic.messages.create(
            {},
            passport="passport",
            authority_request_id="x" * 257,
        )

    assert client.calls == []


def test_runtime_calls_reject_malformed_authority_request_id_async():
    async def run() -> None:
        client = _AsyncCaptureClient()

        with pytest.raises(ValueError, match="22-256 base64url"):
            await AsyncProxyService(client).request(  # type: ignore[arg-type]
                "stripe",
                "https://api.stripe.test/v1/charges",
                passport_token="passport",
                authority_request_id="short",
            )
        with pytest.raises(ValueError, match="22-256 base64url"):
            await AsyncSkillService(client).invoke(  # type: ignore[arg-type]
                "sk_1",
                agent_id="agt_1",
                input={},
                authority_request_id="contains spaces and !",
            )
        with pytest.raises(ValueError, match="22-256 base64url"):
            await AsyncLlmService(client).anthropic.messages.create(
                {},
                passport="passport",
                authority_request_id="x" * 257,
            )

        assert client.calls == []

    asyncio.run(run())
