"""Who an agent is, answered on request by STACK: the lookup and the offline check of its statement.

The check is run against the vectors of the open conformance kit (``spec/conformance/fixtures/agent-identity``),
which are built by a public script from the specification alone, when the monorepo is present.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from getstack import AgentIdentityVerificationError, verify_agent_identity
from getstack._async.agent_identity import AsyncAgentIdentityService
from getstack.agent_identity import AgentIdentityService
from getstack.errors import NotFoundError

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "spec" / "conformance" / "fixtures" / "agent-identity" / "vectors.json"
)
AGENT = "agt_Q2x5b3Vkc0FyZUp1c3RlA"
KEY_ID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


class Public:
    """A client that serves what it is given and records every public request."""

    base_url = "http://api.fixture"

    def __init__(self, answers: dict[str, Any]):
        self.answers = answers
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def public_request(self, method: str, path: str, json: Any = None, params: dict[str, Any] | None = None) -> Any:
        self.calls.append((method, path, params))
        answer = self.answers[path]
        if isinstance(answer, Exception):
            raise answer
        return answer


class AsyncPublic(Public):
    async def public_request(  # type: ignore[override]
        self, method: str, path: str, json: Any = None, params: dict[str, Any] | None = None
    ) -> Any:
        return Public.public_request(self, method, path, json, params)


def _vectors() -> dict[str, Any]:
    if not VECTORS_PATH.exists():
        pytest.skip("the monorepo's conformance vectors are not here")
    return cast_dict(json.loads(VECTORS_PATH.read_text(encoding="utf8")))


def cast_dict(value: Any) -> dict[str, Any]:
    assert isinstance(value, dict)
    return value


def _statement(case: dict[str, Any]) -> str:
    return ".".join(case["statement_parts"])


def _check(case: dict[str, Any], vectors: dict[str, Any]) -> dict[str, Any]:
    return verify_agent_identity(
        _statement(case),
        jwks=vectors["jwks"],
        now=datetime.fromtimestamp(vectors["now"], tz=timezone.utc),
        issuer=vectors["issuer"],
        expect=case["expect"],
    )


def test_every_vector_of_the_open_kit_is_judged_as_it_says() -> None:
    vectors = _vectors()
    groups = {case["group"] for case in vectors["cases"]}
    assert groups == {"valid", "time", "header", "claims", "signature", "lookup", "lifetime"}
    for case in vectors["cases"]:
        if case["verdict"] == "accept":
            claims = _check(case, vectors)
            assert claims["identity"]["agent"]["id"] == case["agent_id"], case["id"]
        else:
            with pytest.raises(AgentIdentityVerificationError):
                _check(case, vectors)


def test_a_wrong_lookup_and_an_expired_statement_say_why() -> None:
    vectors = _vectors()
    by_id = {case["id"]: case for case in vectors["cases"]}
    with pytest.raises(AgentIdentityVerificationError) as wrong:
        _check(by_id["about-another-key"], vectors)
    assert wrong.value.reason == "wrong_lookup"
    with pytest.raises(AgentIdentityVerificationError) as expired:
        _check(by_id["expired"], vectors)
    assert expired.value.reason == "expired"


def test_it_takes_exactly_one_source_of_keys() -> None:
    vectors = _vectors()
    case = vectors["cases"][0]
    now = datetime.fromtimestamp(vectors["now"], tz=timezone.utc)
    with pytest.raises(ValueError, match="exactly one"):
        verify_agent_identity(_statement(case), now=now)
    with pytest.raises(ValueError, match="exactly one"):
        verify_agent_identity(_statement(case), jwks=vectors["jwks"], public_jwk=vectors["jwks"]["keys"][0], now=now)


def test_the_lookup_is_public_and_takes_exactly_one_thing() -> None:
    client = Public({"/v1/agent-identity": {"statement": "x"}})
    service = AgentIdentityService(client)  # type: ignore[arg-type]
    service.lookup(key_id=KEY_ID)
    service.lookup(site="acme.sites.example")
    service.lookup(agent_id=AGENT)
    assert client.calls == [
        ("GET", "/v1/agent-identity", {"key_id": KEY_ID}),
        ("GET", "/v1/agent-identity", {"site": "acme.sites.example"}),
        ("GET", "/v1/agent-identity", {"agent_id": AGENT}),
    ]
    with pytest.raises(ValueError):
        service.lookup()
    with pytest.raises(ValueError):
        service.lookup(key_id=KEY_ID, agent_id=AGENT)


def test_a_found_agent_is_checked_against_stacks_keys_and_the_facts_come_from_the_statement() -> None:
    vectors = _vectors()
    case = next(c for c in vectors["cases"] if c["id"] == "valid-by-key")
    lying = {"statement": _statement(case), "agent": {"id": AGENT, "status": "closed"}}
    client = Public({"/v1/agent-identity": lying, "/v1/.well-known/jwks.json": vectors["jwks"]})
    service = AgentIdentityService(client)  # type: ignore[arg-type]
    now = datetime.fromtimestamp(vectors["now"], tz=timezone.utc)
    verified = service.verified(key_id=KEY_ID, now=now)
    assert verified["facts"]["agent"]["status"] == "active"
    assert verified["facts"]["lookup"] == {"key_id": KEY_ID}
    with pytest.raises(AgentIdentityVerificationError):
        service.verified(agent_id=AGENT, now=now)
    asyncio.run(_verified_async(vectors, case, now))


async def _verified_async(vectors: dict[str, Any], case: dict[str, Any], now: datetime) -> None:
    client = AsyncPublic(
        {"/v1/agent-identity": {"statement": _statement(case)}, "/v1/.well-known/jwks.json": vectors["jwks"]}
    )
    service = AsyncAgentIdentityService(client)  # type: ignore[arg-type]
    verified = await service.verified(key_id=KEY_ID, now=now)
    assert verified["facts"]["agent"]["id"] == case["agent_id"]


def test_an_agent_that_is_not_found_is_the_apis_not_found() -> None:
    client = Public({"/v1/agent-identity": NotFoundError("No agent answers to this lookup.")})
    with pytest.raises(NotFoundError):
        AgentIdentityService(client).lookup(agent_id=AGENT)  # type: ignore[arg-type]


def test_it_knows_where_the_machine_files_of_an_agent_are() -> None:
    urls = AgentIdentityService(Public({})).urls(AGENT)  # type: ignore[arg-type]
    assert urls == {
        "lookup": f"http://api.fixture/v1/agent-identity?agent_id={AGENT}",
        "agent_card": f"http://api.fixture/v1/agent-identity/agents/{AGENT}/agent-card.json",
        "mcp_server_card": f"http://api.fixture/v1/agent-identity/agents/{AGENT}/mcp-server-card.json",
        "key_directory": f"http://api.fixture/v1/agent-identity/agents/{AGENT}/http-message-signatures-directory",
    }
