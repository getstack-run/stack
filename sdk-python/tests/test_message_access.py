"""Message access and message search: the requests of both clients, and the refusals before any request."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.accounts import AsyncAccountMessagesService
from getstack._async.message_access import AsyncMessageAccessService
from getstack.accounts import AccountMessagesService
from getstack.message_access import MessageAccessService


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    def get(self, path: str) -> Any:
        self.calls.append(("GET", path, None))
        return {}

    def put(self, path: str, json: Any = None) -> Any:
        self.calls.append(("PUT", path, json))
        return {}

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs.get("params")))
        return {}


class AsyncCapture(Capture):
    async def get(self, path: str) -> Any:  # type: ignore[override]
        return super().get(path)

    async def put(self, path: str, json: Any = None) -> Any:  # type: ignore[override]
        return super().put(path, json)

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


EXPECTED = [
    ("GET", "/v1/message-access", None),
    ("PUT", "/v1/message-access", {"messages_read_only": True}),
    ("GET", "/v1/agents/agt_one/message-access", None),
    ("PUT", "/v1/agents/agt_one/message-access", {"read_teammates": False, "messages_read_only": False}),
    ("PUT", "/v1/agents/agt_one/message-access", {"read_teammates": None}),
    ("PUT", "/v1/agents/agt_one/message-access", {"read_teammates": None, "messages_read_only": None}),
]


def test_sync_requests() -> None:
    client = Capture()
    service = MessageAccessService(client)  # type: ignore[arg-type]
    service.get()
    service.set(messages_read_only=True)
    service.get("agt_one")
    service.set("agt_one", read_teammates=False, messages_read_only=False)
    service.clear("agt_one", ["read_teammates"])
    service.clear("agt_one", ["read_teammates", "messages_read_only"])
    assert client.calls == EXPECTED


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    service = AsyncMessageAccessService(client)  # type: ignore[arg-type]

    async def drive() -> None:
        await service.get()
        await service.set(messages_read_only=True)
        await service.get("agt_one")
        await service.set("agt_one", read_teammates=False, messages_read_only=False)
        await service.clear("agt_one", ["read_teammates"])
        await service.clear("agt_one", ["read_teammates", "messages_read_only"])

    asyncio.run(drive())
    assert client.calls == EXPECTED


def test_refuses_a_bad_change_before_any_request() -> None:
    client = Capture()
    service = MessageAccessService(client)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.set()
    with pytest.raises(ValueError):
        service.clear("agt_one", ["everything"])
    with pytest.raises(ValueError):
        service.clear("agt_one", [])
    assert client.calls == []


def test_search_and_attachment_requests_for_both_clients() -> None:
    sync_client = Capture()
    sync_messages = AccountMessagesService(sync_client)  # type: ignore[arg-type]
    sync_messages.search(agent_id="agt_one", channel="email", q="invoice", limit=10)
    sync_messages.search()
    sync_messages.read_attachment("acct_1", "amsg_1", "drv_1")

    async_client = AsyncCapture()
    async_messages = AsyncAccountMessagesService(async_client)  # type: ignore[arg-type]

    async def drive() -> None:
        await async_messages.search(agent_id="agt_one", channel="email", q="invoice", limit=10)
        await async_messages.search()
        await async_messages.read_attachment("acct_1", "amsg_1", "drv_1")

    asyncio.run(drive())
    paths = [(method, path) for method, path, _ in sync_client.calls]
    assert paths[0] == ("GET", "/v1/messages")
    assert paths[2][1].endswith("/messages/amsg_1/attachments/drv_1")
    assert sync_client.calls[0][2] == {"agent_id": "agt_one", "channel": "email", "q": "invoice", "limit": 10}
    assert sync_client.calls[1][2] in (None, {})
    assert async_client.calls == sync_client.calls
