"""Retrying an action the owner approved: ``X-Control-Ref`` on the retry, sync and async, and none otherwise."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack.auth import ApiKeyAuth

EMAIL = {"to": "ada@example.com", "subject": "Hi", "body": "Hello"}


def _handler(seen: list[httpx.Request]):
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    return handle


def _sync_stack(seen: list[httpx.Request]) -> Stack:
    stack = Stack(_auth=ApiKeyAuth("sk_live_x"), base_url="http://api.test")
    stack._client._client = httpx.Client(transport=httpx.MockTransport(_handler(seen)))
    return stack


def test_sync_sends_the_ref_only_through_the_scoped_client() -> None:
    seen: list[httpx.Request] = []
    stack = _sync_stack(seen)

    stack.accounts.send_email("acct_1", EMAIL, passport_token="ppt")
    assert "x-control-ref" not in seen[0].headers

    stack.with_control_ref("cref_approved").accounts.send_email("acct_1", EMAIL, passport_token="ppt")
    assert seen[1].url.path == "/v1/accounts/acct_1/email/send"
    assert seen[1].headers["x-control-ref"] == "cref_approved"
    # The credential and the Passport go as before.
    assert seen[1].headers["authorization"] == "Bearer sk_live_x"
    assert seen[1].headers["x-passport-token"] == "ppt"

    # A group inside a service is scoped too, and the original is unchanged.
    stack.with_control_ref("cref_approved").accounts.calls.place("acct_1", {"to": "+14155550123"}, passport_token="ppt")
    assert seen[2].headers["x-control-ref"] == "cref_approved"
    stack.accounts.send_email("acct_1", EMAIL, passport_token="ppt")
    assert "x-control-ref" not in seen[3].headers


def test_an_empty_ref_is_refused() -> None:
    stack = _sync_stack([])
    with pytest.raises(ValueError):
        stack.with_control_ref("  ")


def test_async_sends_the_ref_only_through_the_scoped_client() -> None:
    seen: list[httpx.Request] = []

    async def run() -> None:
        stack = AsyncStack(_auth=ApiKeyAuth("sk_live_x"), base_url="http://api.test")
        stack._client._client = httpx.AsyncClient(transport=httpx.MockTransport(_handler(seen)))
        await stack.accounts.send_email("acct_1", EMAIL, passport_token="ppt")
        await stack.with_control_ref("cref_approved").accounts.send_email("acct_1", EMAIL, passport_token="ppt")
        await stack.accounts.send_email("acct_1", EMAIL, passport_token="ppt")

    asyncio.run(run())
    assert "x-control-ref" not in seen[0].headers
    assert seen[1].headers["x-control-ref"] == "cref_approved"
    assert seen[1].headers["x-passport-token"] == "ppt"
    assert "x-control-ref" not in seen[2].headers
