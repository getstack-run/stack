"""Images on your own OpenAI key: ``llm.openai.images.generate``."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.llm import AsyncLlmService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.llm import LlmService

RESULT = {
    "provider": "openai",
    "model": "gpt-image-1",
    "untrusted": True,
    "key": "own",
    "files": [],
    "revised_prompts": [],
}


def _sync(seen: list[httpx.Request]) -> LlmService:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=RESULT)

    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return LlmService(http)


def _async(seen: list[httpx.Request]) -> AsyncLlmService:
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=RESULT)

    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return AsyncLlmService(http)


def test_openai_posts_to_its_image_route_with_the_passport() -> None:
    seen: list[httpx.Request] = []
    llm = _sync(seen)
    body: dict[str, Any] = {"model": "gpt-image-1", "prompt": "a cat", "size": "1024x1024"}
    assert llm.openai.images.generate(body, passport="ppt") == RESULT
    assert [r.url.path for r in seen] == ["/v1/llm/openai/images"]
    assert [r.headers["X-Passport-Token"] for r in seen] == ["ppt"]
    assert json.loads(seen[0].content) == body
    # A cost cap is not offered: the provider bills you, so there is no worst case of STACK's to hold it to.
    assert "X-Max-Cost-Cents" not in seen[0].headers


def test_the_async_service_does_the_same() -> None:
    seen: list[httpx.Request] = []
    llm = _async(seen)

    async def run() -> Any:
        first = await llm.openai.images.generate({"model": "gpt-image-1", "prompt": "a cat"}, passport="ppt")
        return first

    assert asyncio.run(run()) == RESULT
    assert [r.url.path for r in seen] == ["/v1/llm/openai/images"]
