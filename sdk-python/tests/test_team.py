"""Team: forgetting single sign-on bindings, sync and async alike, with the approval header and the argument checks."""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.team import AsyncTeamService
from getstack.team import TeamService

CLEARED = {"cleared": [{"id": "mem_1", "email": "a@corp.example", "sso_issuer": "https://old-idp.example"}]}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> Any:
        self.calls.append((path, {"json": json, "extra_headers": extra_headers}))
        return CLEARED


class AsyncCapture(Capture):
    async def post(  # type: ignore[override]
        self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None
    ) -> Any:
        return super().post(path, json, extra_headers)


EXPECTED = [
    ("/v1/team/sso-bindings/clear", {"json": {"member_id": "mem_1"}, "extra_headers": None}),
    (
        "/v1/team/sso-bindings/clear",
        {"json": {"issuer": "https://old-idp.example"}, "extra_headers": {"X-Governance-Approval": "gvr_1"}},
    ),
]


def test_sync_clear_sso_bindings_sends_one_target_and_the_approval() -> None:
    client = Capture()
    team = TeamService(client)  # type: ignore[arg-type]
    assert team.clear_sso_bindings(member_id="mem_1") == CLEARED
    team.clear_sso_bindings(issuer="https://old-idp.example", governance_approval_id="gvr_1")
    assert client.calls == EXPECTED


def test_async_clear_sso_bindings_matches_sync() -> None:
    client = AsyncCapture()
    team = AsyncTeamService(client)  # type: ignore[arg-type]

    async def drive() -> None:
        await team.clear_sso_bindings(member_id="mem_1")
        await team.clear_sso_bindings(issuer="https://old-idp.example", governance_approval_id="gvr_1")

    asyncio.run(drive())
    assert client.calls == EXPECTED
    assert inspect.iscoroutinefunction(AsyncTeamService.clear_sso_bindings)
    assert list(inspect.signature(TeamService.clear_sso_bindings).parameters) == list(
        inspect.signature(AsyncTeamService.clear_sso_bindings).parameters
    )


@pytest.mark.parametrize(
    ("member_id", "issuer"),
    [(None, None), ("mem_1", "https://old-idp.example"), ("", None), (None, "")],
)
def test_clear_sso_bindings_refuses_a_bad_target_before_any_request(member_id: str | None, issuer: str | None) -> None:
    client = Capture()
    with pytest.raises(ValueError, match="exactly one"):
        TeamService(client).clear_sso_bindings(member_id=member_id, issuer=issuer)  # type: ignore[arg-type]
    assert client.calls == []
