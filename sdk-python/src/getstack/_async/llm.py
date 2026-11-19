"""async LLM gateway service mirror."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any, Union, cast

from .._authority_request import authority_request_headers
from ..client import AsyncHttpClient
from ..llm import max_cost_header, openrouter_path
from .passport_session import AsyncPassportSession

AsyncPassportInput = Union[str, AsyncPassportSession]


async def _resolve_passport(p: AsyncPassportInput) -> str:
    if isinstance(p, str):
        return p
    return await p.get_token()


async def _build_headers(
    passport: AsyncPassportInput,
    intent_approval_id: str | None = None,
    authority_request_id: str | None = None,
    max_cost_cents: int | None = None,
) -> dict[str, str]:
    max_cost = max_cost_header(max_cost_cents)
    headers = {"X-Passport-Token": await _resolve_passport(passport)}
    if intent_approval_id:
        headers["X-Intent-Approval-Id"] = intent_approval_id
    headers.update(authority_request_headers(authority_request_id))
    headers.update(max_cost)
    return headers


async def _aiterate_sse(response: Any) -> AsyncIterator[dict[str, Any]]:
    async for line in response.aiter_lines():
        if not line or not line.startswith("data: "):
            continue
        payload = line[6:].strip()
        if payload == "[DONE]" or payload == "":
            continue
        try:
            yield json.loads(payload)
        except json.JSONDecodeError:
            continue


async def _stream_provider_call(
    client: AsyncHttpClient,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str],
) -> AsyncIterator[dict[str, Any]]:
    async with client.stream_post(path, json=body, extra_headers=headers) as response:
        if response.status_code >= 400:
            try:
                body_text = (await response.aread()).decode("utf-8")
            except Exception:
                body_text = response.reason_phrase
            raise RuntimeError(f"LLM streaming call failed: {response.status_code} {body_text}")
        async for event in _aiterate_sse(response):
            yield event


# ── Provider sub-services ────────────────────────────────────────────


class _AsyncImages:
    """An image on your own OpenAI key: ``POST /v1/llm/openai/images``.

    The call goes through the same gates as a chat call (Passport, Mission, scope, your controls); STACK counts one
    action and OpenAI bills you. The answer is files saved to the agent's drive (never the bytes), marked
    ``untrusted``. The body takes ``model``, ``prompt``, ``n``, ``size`` and ``quality``.
    """

    def __init__(self, client: AsyncHttpClient):
        self._client = client
        self._path = "/v1/llm/openai/images"

    async def generate(
        self,
        body: dict[str, Any],
        *,
        passport: AsyncPassportInput,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
    ) -> Any:
        headers = await _build_headers(passport, intent_approval_id, authority_request_id)
        return await self._client.post(self._path, json=body, extra_headers=headers)


class _AsyncAnthropicMessages:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create(
        self,
        body: dict[str, Any],
        *,
        passport: AsyncPassportInput,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        effective_stream = bool(stream if stream is not None else body.get("stream"))
        headers = await _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        if effective_stream:
            body = {**body, "stream": True}
            return _stream_provider_call(self._client, "/v1/llm/anthropic/messages", body, headers)
        return await self._client.post("/v1/llm/anthropic/messages", json=body, extra_headers=headers)


class _AsyncAnthropicProvider:
    def __init__(self, client: AsyncHttpClient):
        self.messages = _AsyncAnthropicMessages(client)


class _AsyncOpenAIChatCompletions:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create(
        self,
        body: dict[str, Any],
        *,
        passport: AsyncPassportInput,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        effective_stream = bool(stream if stream is not None else body.get("stream"))
        headers = await _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        if effective_stream:
            body = {**body, "stream": True}
            return _stream_provider_call(self._client, "/v1/llm/openai/chat/completions", body, headers)
        return await self._client.post("/v1/llm/openai/chat/completions", json=body, extra_headers=headers)


class _AsyncOpenAIChat:
    def __init__(self, client: AsyncHttpClient):
        self.completions = _AsyncOpenAIChatCompletions(client)


class _AsyncOpenAIProvider:
    def __init__(self, client: AsyncHttpClient):
        self.chat = _AsyncOpenAIChat(client)
        self.images = _AsyncImages(client)


class _AsyncOpenRouterChatCompletions:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create(
        self,
        body: dict[str, Any],
        *,
        passport: AsyncPassportInput,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        effective_stream = bool(stream if stream is not None else body.get("stream"))
        headers = await _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        if effective_stream:
            body = {**body, "stream": True}
            return _stream_provider_call(self._client, "/v1/llm/openrouter/chat/completions", body, headers)
        return await self._client.post("/v1/llm/openrouter/chat/completions", json=body, extra_headers=headers)


class _AsyncOpenRouterChat:
    def __init__(self, client: AsyncHttpClient):
        self.completions = _AsyncOpenRouterChatCompletions(client)


class _AsyncOpenRouterProvider:
    def __init__(self, client: AsyncHttpClient):
        self._client = client
        self.chat = _AsyncOpenRouterChat(client)

    async def request(
        self,
        method: str,
        path: str,
        *,
        passport: AsyncPassportInput,
        body: dict[str, Any] | None = None,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        """Any call to OpenRouter's API, as the sync ``llm.openrouter.request``: a JSON answer parsed, or, for a POST
        whose body (or ``stream=True``) asks for a stream, an async iterator of parsed SSE events."""
        verb, target = openrouter_path(method, path)
        headers = await _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        if verb == "POST" and bool(stream if stream is not None else (body or {}).get("stream")):
            return _stream_provider_call(self._client, target, {**(body or {}), "stream": True}, headers)
        return await self._client.request(verb, target, json=body, extra_headers=headers)

    async def request_bytes(
        self,
        method: str,
        path: str,
        *,
        passport: AsyncPassportInput,
        body: dict[str, Any] | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> dict[str, Any]:
        """The same call for a file: ``{"status", "content_type", "content"}`` with the bytes in ``content``."""
        verb, target = openrouter_path(method, path)
        headers = await _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        status, content_type, content = await self._client.request_raw(verb, target, json=body, extra_headers=headers)
        return {"status": status, "content_type": content_type, "content": content}


class _AsyncLlmUsageQuery:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        provider: str | None = None,
        passport_jti: str | None = None,
        mission_id: str | None = None,
        agent_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if cursor is not None:
            params["cursor"] = cursor
        if provider is not None:
            params["provider"] = provider
        if passport_jti is not None:
            params["passport_jti"] = passport_jti
        if mission_id is not None:
            params["mission_id"] = mission_id
        if agent_id is not None:
            params["agent_id"] = agent_id
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        return cast("dict[str, Any]", await self._client.get("/v1/llm/usage", params=params))

    async def summary(
        self,
        *,
        provider: str | None = None,
        passport_jti: str | None = None,
        mission_id: str | None = None,
        agent_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        group_by_model: bool | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if provider is not None:
            params["provider"] = provider
        if passport_jti is not None:
            params["passport_jti"] = passport_jti
        if mission_id is not None:
            params["mission_id"] = mission_id
        if agent_id is not None:
            params["agent_id"] = agent_id
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        if group_by_model is not None:
            params["group_by_model"] = str(group_by_model).lower()
        return cast("dict[str, Any]", await self._client.get("/v1/llm/usage/summary", params=params))


class AsyncLlmService:
    def __init__(self, client: AsyncHttpClient):
        self.anthropic = _AsyncAnthropicProvider(client)
        self.openai = _AsyncOpenAIProvider(client)
        self.openrouter = _AsyncOpenRouterProvider(client)
        self.usage = _AsyncLlmUsageQuery(client)
