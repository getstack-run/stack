"""The catalogue: request shapes, conditional reads, errors, and sync/async parity."""

from __future__ import annotations

import asyncio
import inspect
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.catalogue import AsyncCatalogueService
from getstack.auth import ApiKeyAuth
from getstack.catalogue import CatalogueService
from getstack.client import AsyncHttpClient, HttpClient
from getstack.errors import CatalogueUnavailableError, NotFoundError

VERSION = "a" * 64
ETAG = f'W/"{VERSION}"'
ENTRY = {
    "id": "tool:acme/search",
    "kind": "tool",
    "name": "Search",
    "description": "Searches.",
    "origin": "tools",
    "provider": "acme",
    "price": {"unit": "call", "currency": "USD", "provider_cost": {"per_unit_usd_micros": 1000}, "stack_actions": 1},
    "result_trust": "untrusted",
    "run": {
        "method": "POST",
        "path": "/v1/accounts/{account_id}/tools/run",
        "body": {"provider": "acme", "endpoint": "/search"},
        "mcp_tool": "stack_run_account_tool",
        "cost_cap": {"in": "body", "name": "max_cost_cents"},
    },
}
DOCUMENT = {
    "spec": "stack.catalogue",
    "spec_version": "1",
    "version": VERSION,
    "generated_at": "2026-10-22T08:00:00Z",
    "notice": "Prices are at cost.",
    "pricing": {
        "currency": "USD",
        "rule": "One action per run.",
        "included_actions_per_month": 100,
        "bands": [{"up_to": None, "usd_micros_per_action": 1000}],
    },
    "sections": [{"source": "tools", "status": "ok", "refreshed_at": "2026-10-22T07:59:00Z", "count": 1}],
    "entries": [ENTRY],
}
ACCOUNT_VIEW = {
    "account_id": "acct_one/two",
    "catalogue_version": VERSION,
    "connected_services": [{"id": "service:github", "provider": "github", "name": "GitHub", "connection_id": "scon_1"}],
    "pieces": [{"id": "account:inbox", "state": "ready"}],
}
ERROR_BODY = {"error": {"code": "CATALOGUE_UNAVAILABLE", "message": "Not built", "details": {"reason": "not_built"}}}

Handler = Callable[[httpx.Request], httpx.Response]


def _sync(handler: Handler) -> CatalogueService:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return CatalogueService(http)


def _async(handler: Handler) -> AsyncCatalogueService:
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return AsyncCatalogueService(http)


def _recording(seen: list[httpx.Request], status: int, body: Any, headers: dict[str, str] | None = None) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body, headers=headers)

    return handler


def _serving_the_document(seen: list[httpx.Request]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers.get("If-None-Match") == ETAG:
            return httpx.Response(304, headers={"ETag": ETAG})
        return httpx.Response(200, json=DOCUMENT, headers={"ETag": ETAG})

    return handler


def test_get_returns_the_document_and_a_current_copy_is_not_modified() -> None:
    seen: list[httpx.Request] = []
    catalogue = _sync(_serving_the_document(seen))
    first = catalogue.get()
    assert (first.not_modified, first.etag, first.document) == (False, ETAG, DOCUMENT)
    second = catalogue.get(if_none_match=first.etag)
    assert (second.not_modified, second.etag, second.document) == (True, ETAG, None)
    assert [(r.method, r.url.path) for r in seen] == [("GET", "/v1/catalogue"), ("GET", "/v1/catalogue")]
    assert "If-None-Match" not in seen[0].headers
    assert seen[1].headers["If-None-Match"] == ETAG
    assert seen[0].headers["Authorization"] == "Bearer sk_live_dummy"


def test_a_stale_etag_gets_the_new_document() -> None:
    seen: list[httpx.Request] = []
    read = _sync(_serving_the_document(seen)).get(if_none_match='W/"old"')
    assert (read.not_modified, read.etag, read.document) == (False, ETAG, DOCUMENT)
    assert seen[0].headers["If-None-Match"] == 'W/"old"'


def test_a_not_modified_answer_without_an_etag_keeps_the_one_sent() -> None:
    read = _sync(lambda request: httpx.Response(304)).get(if_none_match=ETAG)
    assert (read.not_modified, read.etag, read.document) == (True, ETAG, None)


def test_async_get_matches_sync() -> None:
    async def run() -> None:
        seen: list[httpx.Request] = []
        catalogue = _async(_serving_the_document(seen))
        first = await catalogue.get()
        second = await catalogue.get(if_none_match=first.etag)
        assert (first.not_modified, first.etag, first.document) == (False, ETAG, DOCUMENT)
        assert (second.not_modified, second.etag, second.document) == (True, ETAG, None)
        assert "If-None-Match" not in seen[0].headers
        assert seen[1].headers["If-None-Match"] == ETAG

    asyncio.run(run())


def test_search_finds_the_tools_of_stacks_own_server() -> None:
    seen: list[httpx.Request] = []
    answer = {"version": VERSION, "total": 0, "entries": []}
    catalogue = _sync(_recording(seen, 200, answer))
    assert catalogue.search("send letter", kind="mcp_tool") == answer
    assert seen[0].url.query == b"q=send+letter&kind=mcp_tool"


def test_search_encodes_its_query() -> None:
    seen: list[httpx.Request] = []
    answer = {"version": VERSION, "total": 1, "entries": [ENTRY]}
    catalogue = _sync(_recording(seen, 200, answer))
    assert catalogue.search("espresso machine & grinder", kind="tool", limit=10, offset=20) == answer
    assert catalogue.search() == answer
    assert catalogue.search(q="ünï/cøde?") == answer
    assert [r.url.path for r in seen] == ["/v1/catalogue/search"] * 3
    assert seen[0].url.query == b"q=espresso+machine+%26+grinder&kind=tool&limit=10&offset=20"
    assert dict(seen[0].url.params) == {
        "q": "espresso machine & grinder",
        "kind": "tool",
        "limit": "10",
        "offset": "20",
    }
    assert seen[1].url.query == b""
    assert dict(seen[2].url.params) == {"q": "ünï/cøde?"}


def test_async_search_encodes_its_query() -> None:
    async def run() -> None:
        seen: list[httpx.Request] = []
        answer = {"version": VERSION, "total": 0, "entries": []}
        catalogue = _async(_recording(seen, 200, answer))
        assert await catalogue.search("a b", kind="model", limit=1, offset=0) == answer
        assert seen[0].url.query == b"q=a+b&kind=model&limit=1&offset=0"

    asyncio.run(run())


@pytest.mark.parametrize(
    "kwargs",
    [{"kind": "agent"}, {"limit": 0}, {"limit": 101}, {"offset": -1}],
)
def test_search_refuses_a_bad_query_before_any_request(kwargs: dict[str, Any]) -> None:
    seen: list[httpx.Request] = []
    with pytest.raises(ValueError, match=r"kind is one of|limit is|offset is"):
        _sync(_recording(seen, 200, {})).search("x", **kwargs)
    with pytest.raises(ValueError, match=r"kind is one of|limit is|offset is"):
        asyncio.run(_async(_recording(seen, 200, {})).search("x", **kwargs))
    assert seen == []


def test_for_account_reads_the_accounts_path() -> None:
    seen: list[httpx.Request] = []
    catalogue = _sync(_recording(seen, 200, ACCOUNT_VIEW))
    assert catalogue.for_account("acct_one/two") == ACCOUNT_VIEW
    assert (seen[0].method, seen[0].url.raw_path) == ("GET", b"/v1/accounts/acct_one%2Ftwo/catalogue")

    async def run() -> None:
        aseen: list[httpx.Request] = []
        view = await _async(_recording(aseen, 200, ACCOUNT_VIEW)).for_account("acct_one/two")
        assert view == ACCOUNT_VIEW
        assert aseen[0].url.raw_path == b"/v1/accounts/acct_one%2Ftwo/catalogue"

    asyncio.run(run())


def test_an_account_that_is_not_the_callers_is_not_found() -> None:
    body = {"error": {"code": "NOT_FOUND", "message": "Agent account not found"}}
    with pytest.raises(NotFoundError):
        _sync(_recording([], 404, body)).for_account("acct_other")


def test_an_unbuilt_catalogue_is_a_typed_503() -> None:
    for call in (
        lambda c: c.get(),
        lambda c: c.get(if_none_match=ETAG),
        lambda c: c.search("x"),
    ):
        with pytest.raises(CatalogueUnavailableError) as raised:
            call(_sync(_recording([], 503, ERROR_BODY)))
        error = raised.value
        assert (error.code, error.status_code, error.reason, str(error)) == (
            "CATALOGUE_UNAVAILABLE",
            503,
            "not_built",
            "Not built",
        )
        assert error.details == {"reason": "not_built"}


def test_async_503_is_the_same_typed_error() -> None:
    async def run() -> CatalogueUnavailableError:
        catalogue = _async(_recording([], 503, ERROR_BODY))
        for call in (catalogue.get(), catalogue.search("x"), catalogue.for_account("acct_1")):
            try:
                await call
            except CatalogueUnavailableError as error:
                assert error.reason == "not_built"
                last = error
        return last

    assert asyncio.run(run()).status_code == 503


def test_both_clients_expose_the_same_catalogue_surface() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    sync, async_ = Stack(**kw).catalogue, AsyncStack(**kw).catalogue
    s_methods = {n: m for n, m in inspect.getmembers(sync, inspect.ismethod) if not n.startswith("_")}
    a_methods = {n: m for n, m in inspect.getmembers(async_, inspect.ismethod) if not n.startswith("_")}
    assert set(s_methods) == set(a_methods) == {"get", "search", "for_account"}
    for name, method in s_methods.items():
        assert inspect.iscoroutinefunction(a_methods[name]), name
        assert list(inspect.signature(method).parameters) == list(inspect.signature(a_methods[name]).parameters), name
    assert list(inspect.signature(sync.get).parameters) == ["if_none_match"]
    assert list(inspect.signature(sync.search).parameters) == ["q", "kind", "limit", "offset"]


def test_the_paths_exist_in_the_api() -> None:
    """When the monorepo is present, every path the SDK calls is a route the API registers."""
    api_src = Path(__file__).resolve().parents[2] / "apps" / "api" / "src"
    if not api_src.exists():
        pytest.skip("monorepo not present")
    routes = api_src / "hosted" / "routes"
    catalogue, tools = routes / "catalogue.ts", routes / "account-tools.ts"
    assert catalogue.exists() and tools.exists(), "the catalogue and account-tools routes moved; update this test"
    source = catalogue.read_text(encoding="utf8")
    for path in ("/v1/catalogue", "/v1/catalogue/search", "/v1/accounts/:id/catalogue"):
        assert f"'{path}'" in source, path
    source = tools.read_text(encoding="utf8")
    for path in ("/v1/accounts/:id/tools/run", "/v1/accounts/:id/tools/runs/:runId"):
        assert f"'{path}'" in source, path
    assert "/tools/ready" not in source
