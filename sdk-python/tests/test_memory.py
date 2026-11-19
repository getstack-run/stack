"""Account memory calls: request shapes, sync and async alike, and the refusals made before any request."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncMemoryService, MemoryService

EDGE = "11111111-2222-4333-8444-555555555555"
EPISODE = "66666666-7777-4888-8999-aaaaaaaaaaaa"
PASSPORT = {"X-Passport-Token": "ppt"}


class Capture:
    """Records (method, path, json, params, headers) of every call, answering what the API would."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any, Any, Any]] = []

    def _record(self, method: str, path: str, json: Any, params: Any, headers: Any) -> Any:
        self.calls.append((method, path, json, params, headers))
        return {"ok": True}

    def request(self, method: str, path: str, json: Any = None, params: Any = None, extra_headers: Any = None) -> Any:
        return self._record(method, path, json, params, extra_headers)

    def get(self, path: str, params: Any = None, extra_headers: Any = None) -> Any:
        return self._record("GET", path, None, params, extra_headers)

    def post(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        return self._record("POST", path, json, None, extra_headers)

    def put(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        return self._record("PUT", path, json, None, extra_headers)

    def patch(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        return self._record("PATCH", path, json, None, extra_headers)

    def delete(self, path: str, extra_headers: Any = None) -> Any:
        return self._record("DELETE", path, None, None, extra_headers)


class AsyncCapture(Capture):
    async def request(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().request(*a, **k)

    async def get(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().get(*a, **k)

    async def post(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().post(*a, **k)

    async def put(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().put(*a, **k)

    async def patch(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().patch(*a, **k)

    async def delete(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        return super().delete(*a, **k)


def run_sync(use: Any) -> list[tuple[str, str, Any, Any, Any]]:
    capture = Capture()
    use(MemoryService(capture))  # type: ignore[arg-type]
    return capture.calls


def run_async(use: Any) -> list[tuple[str, str, Any, Any, Any]]:
    capture = AsyncCapture()
    asyncio.run(use(AsyncMemoryService(capture)))  # type: ignore[arg-type]
    return capture.calls


async def _await_all(*coros: Any) -> None:
    for coro in coros:
        await coro


def both(use: Any) -> list[tuple[str, str, Any, Any, Any]]:
    """The calls each client makes for the same use; they must be identical.

    ``use`` takes a service and returns the list of calls to make on it (awaitables for the async client).
    """
    sync_calls = run_sync(use)
    async_calls = run_async(lambda m: _await_all(*use(m)))
    assert sync_calls == async_calls
    return sync_calls


def test_add_memory_sends_what_it_is_given_and_the_passport_only_as_a_header() -> None:
    calls = both(
        lambda m: [
            m.add_memory(
                "Accountant",
                "Maria is my accountant",
                source="message",
                source_description="chat",
                reference_time="2026-10-01T10:00:00Z",
                saga="tax",
                previous_episode_uuids=[EPISODE],
            ),
            m.add_memory("Note", "Check the invoice number", passport_token="ppt"),
        ]
    )
    assert calls[0] == (
        "POST",
        "/v1/memory/episodes",
        {
            "name": "Accountant",
            "episode_body": "Maria is my accountant",
            "source": "message",
            "source_description": "chat",
            "reference_time": "2026-10-01T10:00:00Z",
            "saga": "tax",
            "previous_episode_uuids": [EPISODE],
        },
        None,
        None,
    )
    assert calls[1][2] == {"name": "Note", "episode_body": "Check the invoice number"}
    assert calls[1][4] == PASSPORT
    assert "ppt" not in str(calls[1][2])


def test_add_memory_refuses_a_bad_request_before_any_request() -> None:
    capture = Capture()
    service = MemoryService(capture)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.add_memory("n", "x", source="email")
    with pytest.raises(ValueError):
        service.add_memory("n", "   ")
    with pytest.raises(ValueError):
        service.add_memory("  ", "x")
    with pytest.raises(ValueError):
        service.add_triplet("Maria", "", "works for", "Kvarnen")
    with pytest.raises(ValueError):
        service.search_nodes("  ")
    with pytest.raises(ValueError):
        service.search_memory_facts("")
    with pytest.raises(ValueError):
        service.search_nodes("x", field_filters=[{"field": "paid", "value": True}])
    with pytest.raises(ValueError):
        service.search_nodes("x", entity_types=[], field_filters=[{"field": "paid", "value": True}])
    with pytest.raises(ValueError):
        service.get_episode_entities([])
    with pytest.raises(ValueError):
        service.summarize_saga(" ")
    assert capture.calls == []


def test_triplet_searches_and_saga() -> None:
    calls = both(
        lambda m: [
            m.add_triplet(
                "Maria", "WORKS_FOR", "Maria works for Kvarnen", "Kvarnen", source_node_uuid=EDGE, passport_token="ppt"
            ),
            m.search_nodes("Maria", max_nodes=5, entity_types=["Person"], center_node_uuid=EDGE),
            m.search_nodes("Invoice", entity_types=["Invoice"], field_filters=[{"field": "paid", "value": True}]),
            m.search_memory_facts(
                "where does Maria work", max_facts=3, edge_types=["WORKS_FOR"], valid_at_after="2026-01-01T00:00:00Z"
            ),
            m.summarize_saga("tax"),
        ]
    )
    assert [(c[0], c[1]) for c in calls] == [
        ("POST", "/v1/memory/triplets"),
        ("POST", "/v1/memory/nodes/search"),
        ("POST", "/v1/memory/nodes/search"),
        ("POST", "/v1/memory/facts/search"),
        ("POST", "/v1/memory/sagas/summary"),
    ]
    assert calls[0][2] == {
        "source_node_name": "Maria",
        "edge_name": "WORKS_FOR",
        "fact": "Maria works for Kvarnen",
        "target_node_name": "Kvarnen",
        "source_node_uuid": EDGE,
    }
    assert calls[0][4] == PASSPORT and calls[1][4] is None
    assert calls[1][2] == {"query": "Maria", "max_nodes": 5, "entity_types": ["Person"], "center_node_uuid": EDGE}
    assert calls[2][2] == {
        "query": "Invoice",
        "entity_types": ["Invoice"],
        "field_filters": [{"field": "paid", "value": True}],
    }
    assert calls[3][2] == {
        "query": "where does Maria work",
        "max_facts": 3,
        "edge_types": ["WORKS_FOR"],
        "valid_at_after": "2026-01-01T00:00:00Z",
    }
    assert calls[4][2] == {"saga_name": "tax"}


def test_reads_and_deletes() -> None:
    calls = both(
        lambda m: [
            m.get_episodes(max_episodes=25, passport_token="ppt"),
            m.get_episodes(),
            m.get_entity_edge(EDGE),
            m.get_episode_entities([EPISODE, EDGE]),
            m.delete_episode(EPISODE, passport_token="ppt"),
            m.delete_entity_edge(EDGE),
        ]
    )
    assert [(c[0], c[1]) for c in calls] == [
        ("GET", "/v1/memory/episodes"),
        ("GET", "/v1/memory/episodes"),
        ("GET", f"/v1/memory/facts/{EDGE}"),
        ("POST", "/v1/memory/episode-entities"),
        ("DELETE", f"/v1/memory/episodes/{EPISODE}"),
        ("DELETE", f"/v1/memory/facts/{EDGE}"),
    ]
    assert calls[0][3] == {"max_episodes": 25} and calls[0][4] == PASSPORT
    assert calls[1][3] is None
    assert calls[3][2] == {"episode_uuids": [EPISODE, EDGE]}
    assert calls[4][4] == PASSPORT and calls[5][4] is None


def test_an_id_is_one_path_segment() -> None:
    calls = run_sync(lambda m: m.get_entity_edge("../../v1/accounts"))
    assert calls[0][1] == "/v1/memory/facts/..%2F..%2Fv1%2Faccounts"


def test_settings_are_the_owners_and_take_no_passport() -> None:
    calls = both(lambda m: [m.get_settings(), m.update_settings(enabled=False)])
    assert [(c[0], c[1]) for c in calls] == [("GET", "/v1/memory/settings"), ("PUT", "/v1/memory/settings")]
    assert calls[1][2] == {"enabled": False}
    assert calls[0][4] is None and calls[1][4] is None


def test_settings_decide_whether_a_call_stack_holds_may_search_memory() -> None:
    calls = both(lambda m: [m.update_settings(call_memory_access=False)])
    assert calls[0][2] == {"call_memory_access": False}
    with pytest.raises(ValueError):
        run_sync(lambda m: m.update_settings())


def test_the_paths_exist_in_the_api() -> None:
    """When the monorepo is present, every path the SDK calls is a route the API registers."""
    api_src = Path(__file__).resolve().parents[2] / "apps" / "api" / "src"
    if not api_src.exists():
        pytest.skip("monorepo not present")
    routes = api_src / "hosted" / "routes" / "memory.ts"
    assert routes.exists(), "the memory routes moved; update this test"
    source = routes.read_text(encoding="utf8")
    for path in (
        "/v1/memory/episodes",
        "/v1/memory/episodes/:uuid",
        "/v1/memory/triplets",
        "/v1/memory/nodes/search",
        "/v1/memory/facts/search",
        "/v1/memory/facts/:uuid",
        "/v1/memory/episode-entities",
        "/v1/memory/sagas/summary",
        "/v1/memory/settings",
        "/v1/memory/entity-types",
        "/v1/memory/entity-types/:name",
        "/v1/memory/history",
        "/v1/memory/writes/:id/undo",
    ):
        assert f"'{path}'" in source, path


def test_entity_types_history_and_undo() -> None:
    fields = [{"name": "amount", "kind": "number"}, {"name": "currency", "kind": "one_of", "options": ["EUR", "USD"]}]
    calls = both(
        lambda m: [
            m.list_entity_types(passport_token="ppt"),
            m.create_entity_type("Invoice", "A bill.", fields=fields, passport_token="ppt"),
            m.update_entity_type("Invoice", description="A bill sent."),
            m.retire_entity_type("Invoice"),
            m.get_history(max_writes=5),
            m.get_history(max_writes=5, cursor="41", passport_token="ppt"),
            m.undo_write("mmo_abcdefgh1234", dry_run=True, passport_token="ppt"),
            m.undo_write("mmo_abcdefgh1234"),
        ]
    )
    assert [(c[0], c[1]) for c in calls] == [
        ("GET", "/v1/memory/entity-types"),
        ("POST", "/v1/memory/entity-types"),
        ("PATCH", "/v1/memory/entity-types/Invoice"),
        ("DELETE", "/v1/memory/entity-types/Invoice"),
        ("GET", "/v1/memory/history"),
        ("GET", "/v1/memory/history"),
        ("POST", "/v1/memory/writes/mmo_abcdefgh1234/undo"),
        ("POST", "/v1/memory/writes/mmo_abcdefgh1234/undo"),
    ]
    assert calls[0][4] == PASSPORT
    assert calls[1][2] == {"name": "Invoice", "description": "A bill.", "fields": fields}
    assert calls[2][2] == {"description": "A bill sent."}
    assert calls[4][3] == {"max_writes": 5}
    assert calls[5][3] == {"max_writes": 5, "cursor": "41"} and calls[5][4] == PASSPORT
    assert calls[6][2] == {"dry_run": True} and calls[6][4] == PASSPORT
    assert calls[7][2] == {"dry_run": False}


def test_an_entity_type_the_api_would_refuse_is_refused_before_any_request() -> None:
    for use in (
        lambda m: m.create_entity_type("Invoice", "", fields=None),
        lambda m: m.create_entity_type("Invoice", "A bill.", fields=[{"name": "a", "kind": "money"}]),
        lambda m: m.create_entity_type("Invoice", "A bill.", fields=[{"name": "a", "kind": "one_of"}]),
        lambda m: m.update_entity_type("Invoice"),
    ):
        with pytest.raises(ValueError):
            run_sync(use)
