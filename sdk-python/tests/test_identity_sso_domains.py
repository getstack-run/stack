"""Identity: the verified e-mail domains of single sign-on, sync and async alike."""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.identity import AsyncIdentityService
from getstack.identity import IdentityService

DOMAIN = {
    "id": "ssod_1",
    "domain": "corp.example.com",
    "status": "pending",
    "record": {"type": "TXT", "name": "_stack-sso.corp.example.com", "value": "stack-sso-verification=abc"},
}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, path: str) -> Any:
        self.calls.append(("GET", path, {}))
        return {"domains": [DOMAIN]}

    def post(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> Any:
        self.calls.append(("POST", path, {"json": json, "extra_headers": extra_headers}))
        return DOMAIN if path.endswith("sso-domains") else {"domain": DOMAIN, "check": "missing"}

    def delete(self, path: str) -> Any:
        self.calls.append(("DELETE", path, {}))
        return None


class AsyncCapture(Capture):
    async def get(self, path: str) -> Any:  # type: ignore[override]
        return super().get(path)

    async def post(  # type: ignore[override]
        self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None
    ) -> Any:
        return super().post(path, json, extra_headers)

    async def delete(self, path: str) -> Any:  # type: ignore[override]
        return super().delete(path)


EXPECTED = [
    ("GET", "/v1/identity/sso-domains", {}),
    ("POST", "/v1/identity/sso-domains", {"json": {"domain": "corp.example.com"}, "extra_headers": None}),
    (
        "POST",
        "/v1/identity/sso-domains",
        {"json": {"domain": "corp.example.com"}, "extra_headers": {"X-Governance-Approval": "gvr_1"}},
    ),
    ("POST", "/v1/identity/sso-domains/ssod%2F1/verify", {"json": {}, "extra_headers": None}),
    ("DELETE", "/v1/identity/sso-domains/ssod%2F1", {}),
]


def test_sync_sso_domains_call_the_routes_with_the_approval_on_the_retry() -> None:
    client = Capture()
    identity = IdentityService(client)  # type: ignore[arg-type]
    assert identity.list_sso_domains() == [DOMAIN]
    assert identity.add_sso_domain("corp.example.com") == DOMAIN
    identity.add_sso_domain("corp.example.com", governance_approval_id="gvr_1")
    assert identity.verify_sso_domain("ssod/1")["check"] == "missing"
    assert identity.remove_sso_domain("ssod/1") is None
    assert client.calls == EXPECTED


def test_async_sso_domains_match_sync() -> None:
    client = AsyncCapture()
    identity = AsyncIdentityService(client)  # type: ignore[arg-type]

    async def run() -> None:
        assert await identity.list_sso_domains() == [DOMAIN]
        await identity.add_sso_domain("corp.example.com")
        await identity.add_sso_domain("corp.example.com", governance_approval_id="gvr_1")
        await identity.verify_sso_domain("ssod/1")
        await identity.remove_sso_domain("ssod/1")

    asyncio.run(run())
    assert client.calls == EXPECTED


def test_sso_domain_methods_have_the_same_signature_sync_and_async() -> None:
    for name in ("list_sso_domains", "add_sso_domain", "verify_sso_domain", "remove_sso_domain"):
        assert inspect.iscoroutinefunction(getattr(AsyncIdentityService, name)), name
        assert list(inspect.signature(getattr(IdentityService, name)).parameters) == list(
            inspect.signature(getattr(AsyncIdentityService, name)).parameters
        ), name
