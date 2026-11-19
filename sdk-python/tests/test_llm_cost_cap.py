"""The model gateway's per-call cost cap: ``max_cost_cents`` is sent as ``X-Max-Cost-Cents``."""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, ModelCostCapError, Stack, StackError
from getstack._async.llm import AsyncLlmService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.llm import LlmService

PATHS = {
    "anthropic.messages": "/v1/llm/anthropic/messages",
    "openai.chat.completions": "/v1/llm/openai/chat/completions",
    "openrouter.chat.completions": "/v1/llm/openrouter/chat/completions",
}
CAP_ERROR = {"error": {"code": "MODEL_COST_CAP", "message": "Over the cap", "details": {"reason": "cost_cap_exceeded"}}}


def _group(service: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        service = getattr(service, part)
    return service


def _sync(seen: list[httpx.Request], status: int = 200, body: Any = None) -> LlmService:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body if body is not None else {"ok": True})

    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return LlmService(http)


def _async(seen: list[httpx.Request], status: int = 200, body: Any = None) -> AsyncLlmService:
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body if body is not None else {"ok": True})

    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return AsyncLlmService(http)


def test_the_cap_is_sent_as_a_header_on_every_provider_call() -> None:
    seen: list[httpx.Request] = []
    llm = _sync(seen)
    for group in PATHS:
        _group(llm, group).create({}, passport="ppt", max_cost_cents=250)
        _group(llm, group).create({}, passport="ppt")
    assert [r.url.path for r in seen[::2]] == list(PATHS.values())
    for capped, uncapped in zip(seen[::2], seen[1::2]):
        assert capped.headers["X-Max-Cost-Cents"] == "250"
        assert capped.headers["X-Passport-Token"] == "ppt"
        assert "X-Max-Cost-Cents" not in uncapped.headers


def test_the_async_cap_is_sent_as_a_header_on_every_provider_call() -> None:
    async def run() -> None:
        seen: list[httpx.Request] = []
        llm = _async(seen)
        for group in PATHS:
            await _group(llm, group).create({}, passport="ppt", max_cost_cents=5_000_000)
            await _group(llm, group).create({}, passport="ppt")
        for capped, uncapped in zip(seen[::2], seen[1::2]):
            assert capped.headers["X-Max-Cost-Cents"] == "5000000"
            assert "X-Max-Cost-Cents" not in uncapped.headers

    asyncio.run(run())


@pytest.mark.parametrize("value", [0, -5, 1.5, True, "5"])
def test_a_bad_cap_is_refused_before_any_request(value: Any) -> None:
    seen: list[httpx.Request] = []
    sync, async_ = _sync(seen), _async(seen)
    for group in PATHS:
        for stream in (None, True):
            with pytest.raises(ValueError, match="max_cost_cents"):
                _group(sync, group).create({}, passport="ppt", stream=stream, max_cost_cents=value)
            with pytest.raises(ValueError, match="max_cost_cents"):
                asyncio.run(_group(async_, group).create({}, passport="ppt", stream=stream, max_cost_cents=value))
    assert seen == []


def test_the_cap_error_is_typed_with_its_reason() -> None:
    with pytest.raises(ModelCostCapError) as raised:
        _sync([], 422, CAP_ERROR).openrouter.chat.completions.create({}, passport="ppt", max_cost_cents=1)
    error = raised.value
    assert isinstance(error, StackError)
    assert (error.code, error.status_code, error.reason, str(error)) == (
        "MODEL_COST_CAP",
        422,
        "cost_cap_exceeded",
        "Over the cap",
    )

    async def run() -> ModelCostCapError:
        try:
            await _async([], 422, CAP_ERROR).openrouter.chat.completions.create({}, passport="ppt", max_cost_cents=1)
        except ModelCostCapError as caught:
            return caught
        raise AssertionError("expected an error")

    assert asyncio.run(run()).reason == "cost_cap_exceeded"


def test_sync_and_async_calls_take_the_same_arguments() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    sync, async_ = Stack(**kw).llm, AsyncStack(**kw).llm
    for group in PATHS:
        s, a = _group(sync, group).create, _group(async_, group).create
        assert list(inspect.signature(s).parameters) == list(inspect.signature(a).parameters), group
        param = inspect.signature(s).parameters["max_cost_cents"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY and param.default is None, group
