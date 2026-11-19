"""LLM gateway SDK service (sync).

Drop-in compatible with each provider's official SDK call shape (with
one deviation: passport per-call as a second arg, because STACK
passport TTLs are 15 min default and would silently invalidate
mid-session in a constructor-time pattern).

Usage::

    from getstack import Stack

    stack = Stack(api_key="sk_live_...")
    mission = stack.missions.open("Answer support tickets", agent_id="agt_x")
    session = stack.issue_passport(agent_id="agt_x", mission_ids=[mission["mission_id"]])

    # non-streaming
    response = stack.llm.anthropic.messages.create(
        body={
            "model": "claude-opus-4-7",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100,
        },
        passport=session,
    )

    # streaming
    for event in stack.llm.anthropic.messages.create(
        body={...},
        passport=session,
        stream=True,
    ):
        print(event)

    # observability
    rows = stack.llm.usage.list(limit=10)
    buckets = stack.llm.usage.summary(since="2026-05-01T00:00:00Z")

Wire shapes mirror packages/shared/src/schemas/llm/usage.ts. Types
stay loose (dicts) — same convention as missions.py.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, Union, cast

from ._authority_request import authority_request_headers
from .client import HttpClient
from .passport_session import PassportSession

PassportInput = Union[str, PassportSession]


def _resolve_passport(p: PassportInput) -> str:
    if isinstance(p, str):
        return p
    return p.get_token()


_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def openrouter_path(method: str, path: str) -> tuple[str, str]:
    """The method (upper-cased) and the gateway's path for one of OpenRouter's; refused here when it is not one."""
    verb = method.upper()
    if verb not in _METHODS:
        raise ValueError(f"method is one of {', '.join(_METHODS)}")
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("An OpenRouter path starts with one slash, such as /chat/completions.")
    return verb, f"/v1/llm/openrouter{path}"


_MAX_COST_CENTS_MIN = 1


def max_cost_header(max_cost_cents: int | None) -> dict[str, str]:
    """``X-Max-Cost-Cents``: a cap on the call's worst case, whole cents, 1 or more. Refused client-side otherwise."""
    if max_cost_cents is None:
        return {}
    if isinstance(max_cost_cents, bool) or not isinstance(max_cost_cents, int) or max_cost_cents < _MAX_COST_CENTS_MIN:
        raise ValueError(f"max_cost_cents is a whole number of cents, {_MAX_COST_CENTS_MIN} or more")
    return {"X-Max-Cost-Cents": str(max_cost_cents)}


def _build_headers(
    passport: PassportInput,
    intent_approval_id: str | None = None,
    authority_request_id: str | None = None,
    max_cost_cents: int | None = None,
) -> dict[str, str]:
    headers = {"X-Passport-Token": _resolve_passport(passport)}
    if intent_approval_id:
        headers["X-Intent-Approval-Id"] = intent_approval_id
    headers.update(authority_request_headers(authority_request_id))
    headers.update(max_cost_header(max_cost_cents))
    return headers


def _iterate_sse(response: Any) -> Iterator[dict[str, Any]]:
    """Parse an httpx streaming Response's iter_lines into SSE events.
    Yields each `data: { ... }` JSON payload. Skips `event:` / `id:` /
    blank / comment lines. Terminates on `[DONE]` (OpenAI) or stream end.
    """
    for line in response.iter_lines():
        if not line:
            continue
        # httpx returns str (text); strip the SSE `data: ` prefix.
        if not line.startswith("data: "):
            continue
        payload = line[6:].strip()
        if payload == "[DONE]" or payload == "":
            continue
        try:
            yield json.loads(payload)
        except json.JSONDecodeError:
            continue


# ── Provider sub-services ────────────────────────────────────────────


class _Images:
    """An image on your own OpenAI key: ``POST /v1/llm/openai/images``.

    The call goes through the same gates as a chat call (Passport, Mission, scope, your controls); STACK counts one
    action and OpenAI bills you. The answer is files saved to the agent's drive (never the bytes), marked
    ``untrusted``. The body takes ``model``, ``prompt``, ``n``, ``size`` and ``quality``.
    """

    def __init__(self, client: HttpClient):
        self._client = client
        self._path = "/v1/llm/openai/images"

    def generate(
        self,
        body: dict[str, Any],
        *,
        passport: PassportInput,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
    ) -> Any:
        headers = _build_headers(passport, intent_approval_id, authority_request_id)
        return self._client.post(self._path, json=body, extra_headers=headers)


class _AnthropicMessages:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(
        self,
        body: dict[str, Any],
        *,
        passport: PassportInput,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        """If body['stream'] is True OR stream=True, returns an iterator
        of parsed SSE events. Otherwise returns the JSON response body.
        """
        effective_stream = bool(stream if stream is not None else body.get("stream"))
        if effective_stream:
            body = {**body, "stream": True}
            headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
            return _stream_provider_call(self._client, "/v1/llm/anthropic/messages", body, headers)
        headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        return self._client.post("/v1/llm/anthropic/messages", json=body, extra_headers=headers)


class _AnthropicProvider:
    def __init__(self, client: HttpClient):
        self.messages = _AnthropicMessages(client)


class _OpenAIChatCompletions:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(
        self,
        body: dict[str, Any],
        *,
        passport: PassportInput,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        effective_stream = bool(stream if stream is not None else body.get("stream"))
        if effective_stream:
            body = {**body, "stream": True}
            headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
            return _stream_provider_call(self._client, "/v1/llm/openai/chat/completions", body, headers)
        headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        return self._client.post("/v1/llm/openai/chat/completions", json=body, extra_headers=headers)


class _OpenAIChat:
    def __init__(self, client: HttpClient):
        self.completions = _OpenAIChatCompletions(client)


class _OpenAIProvider:
    def __init__(self, client: HttpClient):
        self.chat = _OpenAIChat(client)
        self.images = _Images(client)


class _OpenRouterChatCompletions:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(
        self,
        body: dict[str, Any],
        *,
        passport: PassportInput,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        effective_stream = bool(stream if stream is not None else body.get("stream"))
        if effective_stream:
            body = {**body, "stream": True}
            headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
            return _stream_provider_call(self._client, "/v1/llm/openrouter/chat/completions", body, headers)
        headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        return self._client.post("/v1/llm/openrouter/chat/completions", json=body, extra_headers=headers)


class _OpenRouterChat:
    def __init__(self, client: HttpClient):
        self.completions = _OpenRouterChatCompletions(client)


class _OpenRouterProvider:
    def __init__(self, client: HttpClient):
        self._client = client
        self.chat = _OpenRouterChat(client)

    def request(
        self,
        method: str,
        path: str,
        *,
        passport: PassportInput,
        body: dict[str, Any] | None = None,
        stream: bool | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> Any:
        """Any call to OpenRouter's API: any method, any path below it (``/chat/completions``, ``/images``,
        ``/embeddings``, ``/videos/<job id>``, ``/models?output_modalities=all``), with OpenRouter's own body and the
        answer as OpenRouter sent it. On STACK's key (an agent account's) the call holds its worst case first
        (``max_cost_cents`` lowers the hold to it; a cost above the hold is taken from the account's credit at once)
        and is charged what OpenRouter reports it cost.

        A JSON answer is returned parsed. If ``body["stream"]`` is True OR ``stream=True`` on a POST, returns an
        iterator of parsed SSE events, as ``chat.completions.create`` does. An answer that is a file is read with
        ``request_bytes``.
        """
        verb, target = openrouter_path(method, path)
        headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        if verb == "POST" and bool(stream if stream is not None else (body or {}).get("stream")):
            return _stream_provider_call(self._client, target, {**(body or {}), "stream": True}, headers)
        return self._client.request(verb, target, json=body, extra_headers=headers)

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        passport: PassportInput,
        body: dict[str, Any] | None = None,
        intent_approval_id: str | None = None,
        authority_request_id: str | None = None,
        max_cost_cents: int | None = None,
    ) -> dict[str, Any]:
        """The same call for an answer that is not JSON (a speech file, a picture, a finished video at
        ``/videos/<job id>/content``): ``{"status", "content_type", "content"}`` with the bytes in ``content``."""
        verb, target = openrouter_path(method, path)
        headers = _build_headers(passport, intent_approval_id, authority_request_id, max_cost_cents)
        status, content_type, content = self._client.request_raw(verb, target, json=body, extra_headers=headers)
        return {"status": status, "content_type": content_type, "content": content}


# ── Usage query sub-service ──────────────────────────────────────────


class _LlmUsageQuery:
    def __init__(self, client: HttpClient):
        self._client = client

    def list(
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
        return cast("dict[str, Any]", self._client.get("/v1/llm/usage", params=params))

    def summary(
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
        return cast("dict[str, Any]", self._client.get("/v1/llm/usage/summary", params=params))


# ── Top-level service ────────────────────────────────────────────────


class LlmService:
    def __init__(self, client: HttpClient):
        self.anthropic = _AnthropicProvider(client)
        self.openai = _OpenAIProvider(client)
        self.openrouter = _OpenRouterProvider(client)
        self.usage = _LlmUsageQuery(client)


# ── Streaming helper ─────────────────────────────────────────────────


def _stream_provider_call(
    client: HttpClient,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str],
) -> Iterator[dict[str, Any]]:
    """Open a streaming connection and yield parsed SSE events. The httpx
    response context manager is held open across the yield — caller MUST
    fully drain the iterator (or `break` early; the GC closes the
    connection). Keeps the streaming UX clean: `for event in
    stack.llm.anthropic.messages.create(..., stream=True): ...`.
    """
    with client.stream_post(path, json=body, extra_headers=headers) as response:
        if response.status_code >= 400:
            # Read the error body before yielding (no chunks to emit).
            try:
                body_text = response.read().decode("utf-8")
            except Exception:
                body_text = response.reason_phrase
            raise RuntimeError(f"LLM streaming call failed: {response.status_code} {body_text}")
        yield from _iterate_sse(response)
