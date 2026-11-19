"""A generic call to OpenRouter's API: any method and path under ``/v1/llm/openrouter``, sync and async."""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import ModelCostCapError, StackError
from getstack._async.llm import AsyncLlmService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.llm import LlmService

SSE = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n'


def _responder(seen: list[httpx.Request], answer: httpx.Response | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer if answer is not None else httpx.Response(200, json={"ok": True})

    return handler


def _sync(seen: list[httpx.Request], answer: httpx.Response | None = None) -> LlmService:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=httpx.MockTransport(_responder(seen, answer)))
    return LlmService(http)


def _async(seen: list[httpx.Request], answer: httpx.Response | None = None) -> AsyncLlmService:
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.AsyncClient(transport=httpx.MockTransport(_responder(seen, answer)))
    return AsyncLlmService(http)


def test_each_method_goes_to_its_path_under_the_gateway_with_the_passport_and_the_cap() -> None:
    seen: list[httpx.Request] = []
    llm = _sync(seen)
    body = {"model": "acme/embed-1", "input": "hello"}
    assert llm.openrouter.request("POST", "/embeddings", passport="ppt", body=body, max_cost_cents=250) == {"ok": True}
    llm.openrouter.request("get", "/models?output_modalities=all", passport="ppt")
    llm.openrouter.request("PUT", "/some/thing", passport="ppt", body={"a": 1})
    llm.openrouter.request("PATCH", "/some/thing", passport="ppt", body={"a": 2})
    llm.openrouter.request("DELETE", "/some/thing", passport="ppt")

    assert [(r.method, r.url.path, r.url.query.decode()) for r in seen] == [
        ("POST", "/v1/llm/openrouter/embeddings", ""),
        ("GET", "/v1/llm/openrouter/models", "output_modalities=all"),
        ("PUT", "/v1/llm/openrouter/some/thing", ""),
        ("PATCH", "/v1/llm/openrouter/some/thing", ""),
        ("DELETE", "/v1/llm/openrouter/some/thing", ""),
    ]
    assert json.loads(seen[0].content) == body
    assert seen[0].headers["X-Passport-Token"] == "ppt"
    assert seen[0].headers["X-Max-Cost-Cents"] == "250"
    assert seen[0].headers["Authorization"] == "Bearer sk_live_dummy"
    for later in seen[1:]:
        assert "X-Max-Cost-Cents" not in later.headers
    assert seen[1].content == b""


def test_a_path_that_is_not_openrouters_or_a_method_it_does_not_use_is_refused_before_any_call() -> None:
    seen: list[httpx.Request] = []
    llm = _sync(seen)
    for path in ("embeddings", "//evil.example/x", ""):
        with pytest.raises(ValueError):
            llm.openrouter.request("POST", path, passport="ppt")
    with pytest.raises(ValueError):
        llm.openrouter.request("TRACE", "/models", passport="ppt")
    with pytest.raises(ValueError):
        llm.openrouter.request("POST", "/embeddings", passport="ppt", max_cost_cents=0)
    assert seen == []


def test_a_post_that_asks_for_a_stream_returns_the_parsed_events() -> None:
    seen: list[httpx.Request] = []
    llm = _sync(seen, httpx.Response(200, content=SSE, headers={"content-type": "text/event-stream"}))
    events = list(
        llm.openrouter.request("POST", "/responses", passport="ppt", body={"model": "m", "input": "x", "stream": True})
    )
    assert events == [{"choices": [{"delta": {"content": "hi"}}]}]
    assert seen[0].url.path == "/v1/llm/openrouter/responses"
    assert json.loads(seen[0].content)["stream"] is True

    again = list(llm.openrouter.request("POST", "/responses", passport="ppt", body={"model": "m"}, stream=True))
    assert again == events


def test_request_bytes_returns_a_file_as_its_bytes_and_type() -> None:
    seen: list[httpx.Request] = []
    llm = _sync(seen, httpx.Response(200, content=b"\x00\x01\x02", headers={"content-type": "video/mp4"}))
    got = llm.openrouter.request_bytes("GET", "/videos/gen-abc/content", passport="ppt", max_cost_cents=5)
    assert got == {"status": 200, "content_type": "video/mp4", "content": b"\x00\x01\x02"}
    assert seen[0].url.path == "/v1/llm/openrouter/videos/gen-abc/content"
    assert seen[0].headers["X-Passport-Token"] == "ppt"
    assert seen[0].headers["X-Max-Cost-Cents"] == "5"


def test_the_apis_error_is_raised_for_a_call_and_for_a_file() -> None:
    cap = httpx.Response(
        422,
        json={
            "error": {"code": "MODEL_COST_CAP", "message": "Over the cap", "details": {"reason": "cost_cap_exceeded"}}
        },
    )
    llm = _sync([], cap)
    with pytest.raises(ModelCostCapError):
        llm.openrouter.request("POST", "/chat/completions", passport="ppt", body={})
    with pytest.raises(StackError):
        llm.openrouter.request_bytes("GET", "/videos/gen-abc/content", passport="ppt")


def test_the_async_calls_do_the_same() -> None:
    async def run() -> None:
        seen: list[httpx.Request] = []
        llm = _async(seen)
        assert await llm.openrouter.request(
            "POST", "/images", passport="ppt", body={"model": "m"}, max_cost_cents=100_000
        ) == {"ok": True}
        assert seen[0].url.path == "/v1/llm/openrouter/images"
        assert seen[0].headers["X-Max-Cost-Cents"] == "100000"
        assert seen[0].headers["X-Passport-Token"] == "ppt"

        with pytest.raises(ValueError):
            await llm.openrouter.request("POST", "images", passport="ppt")

        streaming = _async([], httpx.Response(200, content=SSE, headers={"content-type": "text/event-stream"}))
        events = [
            e
            async for e in await streaming.openrouter.request(
                "POST", "/responses", passport="ppt", body={"stream": True}
            )
        ]
        assert events == [{"choices": [{"delta": {"content": "hi"}}]}]

        files = _async([], httpx.Response(200, content=b"abc", headers={"content-type": "audio/mpeg"}))
        assert await files.openrouter.request_bytes("POST", "/audio/speech", passport="ppt", body={"model": "m"}) == {
            "status": 200,
            "content_type": "audio/mpeg",
            "content": b"abc",
        }

        with pytest.raises(ModelCostCapError):
            await _async(
                [], httpx.Response(422, json={"error": {"code": "MODEL_COST_CAP", "message": "x", "details": {}}})
            ).openrouter.request(
                "POST",
                "/chat/completions",
                passport="ppt",
                body={},
            )

    asyncio.run(run())


def test_sync_and_async_take_the_same_arguments() -> None:
    seen: list[httpx.Request] = []
    for name in ("request", "request_bytes"):
        sync_params = list(inspect.signature(getattr(_sync(seen).openrouter, name)).parameters)
        async_params = list(inspect.signature(getattr(_async(seen).openrouter, name)).parameters)
        assert sync_params == async_params, name
        assert inspect.iscoroutinefunction(getattr(_async(seen).openrouter, name))
        assert not inspect.iscoroutinefunction(getattr(_sync(seen).openrouter, name))
