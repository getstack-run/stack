"""Chat channels and an agent's Telegram bot: request shapes (sync and async alike), the token's one route, errors."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.accounts import AsyncAccountsService
from getstack._async.chat_channels import AsyncChatChannelsService
from getstack.accounts import AccountsService
from getstack.chat_channels import ChatChannelsService
from getstack.errors import ControlLimitExceededError, TelegramSendRefusedError, raise_for_status

TOKEN = "123456789:AAHfixturefixturefixturefixturefixture1"


class Capture:
    """Records every call a service makes, through either the verb methods or `request`."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _record(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {}

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._record("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self._record("POST", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self._record("DELETE", path, **kwargs)

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        return self._record(method, path, **kwargs)


class AsyncCapture(Capture):
    async def get(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().get(path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().post(path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().delete(path, **kwargs)

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


CHAT_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("GET", "/v1/chat-channels", {}),
    ("POST", "/v1/chat-channels/identities", {"json": {"channel": "telegram"}}),
    ("POST", "/v1/chat-channels/identities", {"json": {"channel": "sms", "phone": "+46701740605"}}),
    ("POST", "/v1/chat-channels/identities/cid_abc/verify", {"json": {"code": "123456"}}),
    ("POST", "/v1/chat-channels/identities/cid_abc/confirm", {"json": {}}),
    ("DELETE", "/v1/chat-channels/identities/cid_abc", {}),
    (
        "GET",
        "/v1/chat-channels/slack/install-url",
        {"params": {"redirect_uri": "https://console.example/cb", "state": "abcdefgh12"}},
    ),
    (
        "POST",
        "/v1/chat-channels/slack/install",
        {"json": {"code": "c0de", "redirect_uri": "https://console.example/cb"}},
    ),
    ("DELETE", "/v1/chat-channels/slack", {}),
]

ACCOUNT_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("PUT", "/v1/accounts/acct_1/telegram", {"json": {"bot_token": TOKEN}}),
    ("GET", "/v1/accounts/acct_1/telegram", {}),
    ("GET", "/v1/accounts/acct_1/telegram/chats", {}),
    ("DELETE", "/v1/accounts/acct_1/telegram", {}),
    (
        "POST",
        "/v1/accounts/acct_1/telegram/messages",
        {"json": {"chat_id": "42", "text": "hi"}, "extra_headers": {"X-Passport-Token": "p.jwt"}},
    ),
]


def test_sync_chat_channels_match_the_routes() -> None:
    client = Capture()
    svc = ChatChannelsService(client)  # type: ignore[arg-type]
    svc.get()
    svc.create_identity("telegram")
    svc.create_identity("sms", phone="+46701740605")
    svc.verify_identity("cid_abc", "123456")
    svc.confirm_identity("cid_abc")
    svc.remove_identity("cid_abc")
    svc.slack_install_url("https://console.example/cb", "abcdefgh12")
    svc.install_slack("c0de", "https://console.example/cb")
    svc.remove_slack()
    assert client.calls == CHAT_CALLS


def test_async_chat_channels_match_the_routes() -> None:
    client = AsyncCapture()
    svc = AsyncChatChannelsService(client)  # type: ignore[arg-type]

    async def drive() -> None:
        await svc.get()
        await svc.create_identity("telegram")
        await svc.create_identity("sms", phone="+46701740605")
        await svc.verify_identity("cid_abc", "123456")
        await svc.confirm_identity("cid_abc")
        await svc.remove_identity("cid_abc")
        await svc.slack_install_url("https://console.example/cb", "abcdefgh12")
        await svc.install_slack("c0de", "https://console.example/cb")
        await svc.remove_slack()

    asyncio.run(drive())
    assert client.calls == CHAT_CALLS


def test_an_id_cannot_leave_its_path() -> None:
    client = Capture()
    ChatChannelsService(client).confirm_identity("../x")  # type: ignore[arg-type]
    assert client.calls[0][1] == "/v1/chat-channels/identities/..%2Fx/confirm"


def test_telegram_bot_sync_and_async_match_the_routes() -> None:
    client = Capture()
    accounts = AccountsService(client)  # type: ignore[arg-type]
    accounts.telegram.connect("acct_1", TOKEN)
    accounts.telegram.get("acct_1")
    accounts.telegram.chats("acct_1")
    accounts.telegram.disconnect("acct_1")
    accounts.send_telegram("acct_1", {"chat_id": "42", "text": "hi"}, passport_token="p.jwt")
    assert client.calls == ACCOUNT_CALLS
    # The token goes to the connect route and nowhere else.
    assert TOKEN not in repr(client.calls[1:])

    aclient = AsyncCapture()
    aaccounts = AsyncAccountsService(aclient)  # type: ignore[arg-type]

    async def drive() -> None:
        await aaccounts.telegram.connect("acct_1", TOKEN)
        await aaccounts.telegram.get("acct_1")
        await aaccounts.telegram.chats("acct_1")
        await aaccounts.telegram.disconnect("acct_1")
        await aaccounts.send_telegram("acct_1", {"chat_id": "42", "text": "hi"}, passport_token="p.jwt")

    asyncio.run(drive())
    assert aclient.calls == ACCOUNT_CALLS


def test_both_clients_expose_the_chat_channels_and_the_telegram_bot() -> None:
    sync = Stack(api_key="sk_live_test", base_url="https://api.example.test")
    asynchronous = AsyncStack(api_key="sk_live_test", base_url="https://api.example.test")
    for client in (sync, asynchronous):
        assert hasattr(client, "chat_channels")
        assert hasattr(client.accounts, "telegram")
        assert hasattr(client.accounts, "send_telegram")


def test_a_telegram_refusal_is_a_typed_error() -> None:
    body = {"error": {"code": "TELEGRAM_SEND_REFUSED", "message": "no", "details": {"reason": "chat_unknown"}}}
    try:
        raise_for_status(403, body)
    except TelegramSendRefusedError as error:
        assert error.reason == "chat_unknown"
        assert error.status_code == 403
    else:  # pragma: no cover
        raise AssertionError("no error raised")


def test_a_spend_rule_limit_names_its_counter() -> None:
    body = {
        "error": {
            "code": "CONTROL_LIMIT_EXCEEDED",
            "message": "limit",
            "details": {"limit": {"window": "day", "unit": "cents", "scope": "spend:shop"}, "remaining": 0},
        }
    }
    try:
        raise_for_status(403, body)
    except ControlLimitExceededError as error:
        assert error.limit == {"window": "day", "unit": "cents", "scope": "spend:shop"}
        assert error.remaining == 0
    else:  # pragma: no cover
        raise AssertionError("no error raised")
