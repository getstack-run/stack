"""Agent account calls: request shapes, sync and async alike, and typed errors."""

from __future__ import annotations

import asyncio
import base64
import importlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.accounts import AsyncAccountsService
from getstack.accounts import AccountsService, email_body
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.errors import (
    AccountCallFailedError,
    AccountPieceNotReadyError,
    AgentBudgetExceededError,
    BudgetNeedsControlsError,
    CatalogueUnavailableError,
    DestinationNotAvailableError,
    ForbiddenError,
    GovernanceApprovalRequiredError,
    PlatformSubscriptionRequiredError,
    ProviderCapacityUnavailableError,
    RecipientOptedOutError,
    SharedMailDailyLimitError,
    StackError,
    ToolPriceRefusedError,
    ToolRunRejectedError,
    ToolsUnavailableError,
    UnboundedSendRuleError,
)

ACCT = "acct_one/two"
Q = "acct_one%2Ftwo"
OPEN_REQUEST = {"name": "Support", "monthly_budget_cents": 5000, "skip": ["phone"]}
TOLL_FREE = {"business_name": "Acme", "business_website": "https://acme.example", "business_type": "SOLE_PROPRIETOR"}
CALL = {"to": "+14155550123", "on_behalf_of": "Ada Lovelace", "brief": "Book a table for two at 19:00"}
ANSWER = {"greeting": "Ada's office.", "wait_seconds": 10, "max_seconds": 300}
TOOL_RUN = {"provider": "acme", "endpoint": "/v1/search", "input": {"q": "espresso"}, "max_results": 5}
REPORT_PDF = b"%PDF-1.4 quarterly report"
REPORT_B64 = base64.b64encode(REPORT_PDF).decode("ascii")
GROUP_EMAIL: dict[str, Any] = {
    "to": ["ada@example.test", "grace@example.test"],
    "cc": ["alan@example.test"],
    "bcc": ["audit@example.test"],
    "subject": "Quarterly report",
    "body": "Attached.",
    "attachments": [
        {"file_id": "dfl_1", "filename": "figures.csv"},
        {"filename": "report.pdf", "content_type": "application/pdf", "content": REPORT_PDF},
    ],
}
GROUP_EMAIL_WIRE: dict[str, Any] = {
    **GROUP_EMAIL,
    "attachments": [
        {"file_id": "dfl_1", "filename": "figures.csv"},
        {"filename": "report.pdf", "content_type": "application/pdf", "content_base64": REPORT_B64},
    ],
}
REPLY = {"body": "Thanks, noted.", "reply_all": True, "cc": ["alan@example.test"]}
FORWARD = {
    "to": "ada@example.test",
    "body": "For your files.",
    "include_attachments": False,
    "attachments": [{"filename": "note.txt", "content_type": "text/plain", "content": b"hello"}],
}
FORWARD_WIRE = {
    **FORWARD,
    "attachments": [{"filename": "note.txt", "content_type": "text/plain", "content_base64": "aGVsbG8="}],
}


class Capture:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path, kwargs))
        return {"ok": True, "workspaces": []}


class AsyncCapture(Capture):
    async def request(self, method: str, path: str, **kwargs: Any) -> Any:  # type: ignore[override]
        return super().request(method, path, **kwargs)


def _drive_sync(accounts: AccountsService) -> None:
    accounts.open(OPEN_REQUEST, idempotency_key="open-12345", governance_approval_id="gvr_1")
    accounts.open(OPEN_REQUEST, idempotency_key="open-12345")
    accounts.get(ACCT)
    accounts.list()
    accounts.list(limit=10)
    accounts.close(ACCT)
    accounts.messages.list(ACCT)
    accounts.messages.list(ACCT, limit=5, cursor="c1", channel="sms", passport_token="ppt")
    accounts.messages.get(ACCT, "msg/1", passport_token="ppt")
    accounts.messages.delete(ACCT, "msg/1")
    accounts.opt_outs.list()
    accounts.opt_outs.add("+14155550123")
    accounts.opt_outs.remove("aoo/1")
    accounts.blocked_callers.list()
    accounts.blocked_callers.add("+14155550123")
    accounts.blocked_callers.remove("abk/1")
    accounts.send_email(ACCT, {"to": "a@example.test", "subject": "Hi", "body": "Hello"}, passport_token="ppt")
    accounts.send_sms(ACCT, {"to": "+14155550123", "body": "Hello"})
    accounts.toll_free_verification.submit(ACCT, TOLL_FREE)
    accounts.toll_free_verification.submit(ACCT, TOLL_FREE, governance_approval_id="gvr_4")
    accounts.toll_free_verification.get(ACCT)
    accounts.resume_piece(ACCT, "inbox")
    accounts.resume_piece(ACCT, "phone")
    accounts.calls.place(ACCT, CALL, passport_token="ppt")
    accounts.calls.place(ACCT, CALL)
    accounts.calls.list(ACCT)
    accounts.calls.list(ACCT, limit=5, cursor="c1", passport_token="ppt")
    accounts.calls.get(ACCT, "acall/1", passport_token="ppt")
    accounts.calls.get(ACCT, "acall/1")
    accounts.calls.answer(ACCT, "acall/1", ANSWER, passport_token="ppt")
    accounts.calls.answer(ACCT, "acall/1", ANSWER)
    accounts.calls.decline(ACCT, "acall/1", passport_token="ppt")
    accounts.calls.decline(ACCT, "acall/1")
    accounts.tools.discover(ACCT, query="espresso prices", passport_token="ppt")
    accounts.tools.discover(ACCT, query="espresso prices", limit=10, passport_token="ppt")
    accounts.tools.inspect(ACCT, provider="acme", endpoint="/v1/search", passport_token="ppt")
    accounts.tools.run(ACCT, TOOL_RUN, passport_token="ppt")
    accounts.tools.get_run(ACCT, "atr/1", passport_token="ppt")
    accounts.tools.get_run(ACCT, "atr/1")
    accounts.workspace.exec(ACCT, "ls", stack_access=True, passport_token="ppt")
    accounts.workspace.exec(
        ACCT,
        "ls",
        workspace_id="wsp_12345678",
        cwd="/w",
        env={"A": "1"},
        timeout_seconds=30,
        passport_token="ppt",
    )
    accounts.workspace.read_file(ACCT, "wsp_12345678", "a.txt", passport_token="ppt")
    accounts.workspace.write_file(ACCT, "wsp_12345678", "a.txt", content_text="x", mode="755", passport_token="ppt")
    accounts.workspace.save_file(
        ACCT, "wsp_12345678", "a.csv", name="r.csv", visibility="account", passport_token="ppt"
    )
    accounts.workspace.list(ACCT)
    accounts.workspace.list()
    accounts.workspace.set_sharing(ACCT, "wsp_12345678", False)
    accounts.workspace.stop(ACCT, "wsp_12345678", delete=True)
    accounts.workspace.get_settings()
    accounts.workspace.get_settings(ACCT)
    accounts.workspace.set_settings({"idle_pause_minutes": 0, "delete_after_days": 30})
    accounts.workspace.set_settings({"max_workspaces": 5, "idle_pause_minutes": None}, ACCT)
    accounts.browser.start_session(ACCT, passport_token="ppt")
    accounts.browser.navigate(ACCT, "bs/1", "https://shop.example", passport_token="ppt")
    accounts.browser.act(ACCT, "bs/1", {"action": "click", "target": {"text": "Buy"}}, passport_token="ppt")
    accounts.browser.read(ACCT, "bs/1", passport_token="ppt")
    accounts.browser.screenshot(ACCT, "bs/1", passport_token="ppt")
    accounts.browser.end_session(ACCT, "bs/1")
    accounts.browser.checkout(
        ACCT, "bs/1", {"merchant_origin": "https://shop.example", "amount_minor": 1299, "currency": "USD"}
    )
    accounts.purchases.get(ACCT, "pur/1")
    accounts.purchases.report_merchant_result(
        ACCT, "pur/1", {"status": "completed", "order_id": "o1"}, passport_token="ppt"
    )
    accounts.wallet.pay(ACCT, {"typed_data": {"a": 1}, "agent_signature": "sig"}, passport_token="ppt")
    accounts.wallet.owner_status()
    accounts.mail_domains.list()
    accounts.mail_domains.connect("mail.example.com")
    accounts.mail_domains.verify("omd/1")
    accounts.signing_keys.list(ACCT)
    accounts.signing_keys.rotate(ACCT)
    accounts.identity.get(ACCT)
    accounts.identity.update(ACCT, show_name=True)
    accounts.identity.update(ACCT, enabled=False)
    accounts.send_email(ACCT, {"to": "a@example.test", "subject": "Receipt", "body": "Thanks"})
    accounts.send_email(ACCT, GROUP_EMAIL, passport_token="ppt")
    accounts.reply_email(ACCT, "msg/1", REPLY, passport_token="ppt")
    accounts.reply_email(ACCT, "msg/1", {"body": "Thanks."})
    accounts.forward_email(ACCT, "msg/1", FORWARD, passport_token="ppt")


async def _drive_async(accounts: AsyncAccountsService) -> None:
    await accounts.open(OPEN_REQUEST, idempotency_key="open-12345", governance_approval_id="gvr_1")
    await accounts.open(OPEN_REQUEST, idempotency_key="open-12345")
    await accounts.get(ACCT)
    await accounts.list()
    await accounts.list(limit=10)
    await accounts.close(ACCT)
    await accounts.messages.list(ACCT)
    await accounts.messages.list(ACCT, limit=5, cursor="c1", channel="sms", passport_token="ppt")
    await accounts.messages.get(ACCT, "msg/1", passport_token="ppt")
    await accounts.messages.delete(ACCT, "msg/1")
    await accounts.opt_outs.list()
    await accounts.opt_outs.add("+14155550123")
    await accounts.opt_outs.remove("aoo/1")
    await accounts.blocked_callers.list()
    await accounts.blocked_callers.add("+14155550123")
    await accounts.blocked_callers.remove("abk/1")
    await accounts.send_email(ACCT, {"to": "a@example.test", "subject": "Hi", "body": "Hello"}, passport_token="ppt")
    await accounts.send_sms(ACCT, {"to": "+14155550123", "body": "Hello"})
    await accounts.toll_free_verification.submit(ACCT, TOLL_FREE)
    await accounts.toll_free_verification.submit(ACCT, TOLL_FREE, governance_approval_id="gvr_4")
    await accounts.toll_free_verification.get(ACCT)
    await accounts.resume_piece(ACCT, "inbox")
    await accounts.resume_piece(ACCT, "phone")
    await accounts.calls.place(ACCT, CALL, passport_token="ppt")
    await accounts.calls.place(ACCT, CALL)
    await accounts.calls.list(ACCT)
    await accounts.calls.list(ACCT, limit=5, cursor="c1", passport_token="ppt")
    await accounts.calls.get(ACCT, "acall/1", passport_token="ppt")
    await accounts.calls.get(ACCT, "acall/1")
    await accounts.calls.answer(ACCT, "acall/1", ANSWER, passport_token="ppt")
    await accounts.calls.answer(ACCT, "acall/1", ANSWER)
    await accounts.calls.decline(ACCT, "acall/1", passport_token="ppt")
    await accounts.calls.decline(ACCT, "acall/1")
    await accounts.tools.discover(ACCT, query="espresso prices", passport_token="ppt")
    await accounts.tools.discover(ACCT, query="espresso prices", limit=10, passport_token="ppt")
    await accounts.tools.inspect(ACCT, provider="acme", endpoint="/v1/search", passport_token="ppt")
    await accounts.tools.run(ACCT, TOOL_RUN, passport_token="ppt")
    await accounts.tools.get_run(ACCT, "atr/1", passport_token="ppt")
    await accounts.tools.get_run(ACCT, "atr/1")
    await accounts.workspace.exec(ACCT, "ls", stack_access=True, passport_token="ppt")
    await accounts.workspace.exec(
        ACCT,
        "ls",
        workspace_id="wsp_12345678",
        cwd="/w",
        env={"A": "1"},
        timeout_seconds=30,
        passport_token="ppt",
    )
    await accounts.workspace.read_file(ACCT, "wsp_12345678", "a.txt", passport_token="ppt")
    await accounts.workspace.write_file(
        ACCT, "wsp_12345678", "a.txt", content_text="x", mode="755", passport_token="ppt"
    )
    await accounts.workspace.save_file(
        ACCT, "wsp_12345678", "a.csv", name="r.csv", visibility="account", passport_token="ppt"
    )
    await accounts.workspace.list(ACCT)
    await accounts.workspace.list()
    await accounts.workspace.set_sharing(ACCT, "wsp_12345678", False)
    await accounts.workspace.stop(ACCT, "wsp_12345678", delete=True)
    await accounts.workspace.get_settings()
    await accounts.workspace.get_settings(ACCT)
    await accounts.workspace.set_settings({"idle_pause_minutes": 0, "delete_after_days": 30})
    await accounts.workspace.set_settings({"max_workspaces": 5, "idle_pause_minutes": None}, ACCT)
    await accounts.browser.start_session(ACCT, passport_token="ppt")
    await accounts.browser.navigate(ACCT, "bs/1", "https://shop.example", passport_token="ppt")
    await accounts.browser.act(ACCT, "bs/1", {"action": "click", "target": {"text": "Buy"}}, passport_token="ppt")
    await accounts.browser.read(ACCT, "bs/1", passport_token="ppt")
    await accounts.browser.screenshot(ACCT, "bs/1", passport_token="ppt")
    await accounts.browser.end_session(ACCT, "bs/1")
    await accounts.browser.checkout(
        ACCT, "bs/1", {"merchant_origin": "https://shop.example", "amount_minor": 1299, "currency": "USD"}
    )
    await accounts.purchases.get(ACCT, "pur/1")
    await accounts.purchases.report_merchant_result(
        ACCT, "pur/1", {"status": "completed", "order_id": "o1"}, passport_token="ppt"
    )
    await accounts.wallet.pay(ACCT, {"typed_data": {"a": 1}, "agent_signature": "sig"}, passport_token="ppt")
    await accounts.wallet.owner_status()
    await accounts.mail_domains.list()
    await accounts.mail_domains.connect("mail.example.com")
    await accounts.mail_domains.verify("omd/1")
    await accounts.signing_keys.list(ACCT)
    await accounts.signing_keys.rotate(ACCT)
    await accounts.identity.get(ACCT)
    await accounts.identity.update(ACCT, show_name=True)
    await accounts.identity.update(ACCT, enabled=False)
    await accounts.send_email(ACCT, {"to": "a@example.test", "subject": "Receipt", "body": "Thanks"})
    await accounts.send_email(ACCT, GROUP_EMAIL, passport_token="ppt")
    await accounts.reply_email(ACCT, "msg/1", REPLY, passport_token="ppt")
    await accounts.reply_email(ACCT, "msg/1", {"body": "Thanks."})
    await accounts.forward_email(ACCT, "msg/1", FORWARD, passport_token="ppt")


PPT = {"X-Passport-Token": "ppt"}
# A payment from the wallet is made as the agent: its Passport is the bearer credential as well.
PPT_AS_AGENT = {"X-Passport-Token": "ppt", "Authorization": "Bearer ppt"}

EXPECTED_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    (
        "POST",
        "/v1/accounts",
        {
            "json": OPEN_REQUEST,
            "extra_headers": {"Idempotency-Key": "open-12345", "X-Governance-Approval": "gvr_1"},
        },
    ),
    ("POST", "/v1/accounts", {"json": OPEN_REQUEST, "extra_headers": {"Idempotency-Key": "open-12345"}}),
    ("GET", f"/v1/accounts/{Q}", {}),
    ("GET", "/v1/accounts", {}),
    ("GET", "/v1/accounts", {"params": {"limit": 10}}),
    ("DELETE", f"/v1/accounts/{Q}", {}),
    ("GET", f"/v1/accounts/{Q}/messages", {}),
    (
        "GET",
        f"/v1/accounts/{Q}/messages",
        {"params": {"limit": 5, "cursor": "c1", "channel": "sms"}, "extra_headers": PPT},
    ),
    ("GET", f"/v1/accounts/{Q}/messages/msg%2F1", {"extra_headers": PPT}),
    ("DELETE", f"/v1/accounts/{Q}/messages/msg%2F1", {}),
    ("GET", "/v1/opt-outs", {}),
    ("POST", "/v1/opt-outs", {"json": {"number": "+14155550123"}}),
    ("DELETE", "/v1/opt-outs/aoo%2F1", {}),
    ("GET", "/v1/blocked-callers", {}),
    ("POST", "/v1/blocked-callers", {"json": {"number": "+14155550123"}}),
    ("DELETE", "/v1/blocked-callers/abk%2F1", {}),
    (
        "POST",
        f"/v1/accounts/{Q}/email/send",
        {"json": {"to": "a@example.test", "subject": "Hi", "body": "Hello"}, "extra_headers": PPT},
    ),
    ("POST", f"/v1/accounts/{Q}/sms/send", {"json": {"to": "+14155550123", "body": "Hello"}}),
    ("POST", f"/v1/accounts/{Q}/phone/toll-free-verification", {"json": TOLL_FREE}),
    (
        "POST",
        f"/v1/accounts/{Q}/phone/toll-free-verification",
        {"json": TOLL_FREE, "extra_headers": {"X-Governance-Approval": "gvr_4"}},
    ),
    ("GET", f"/v1/accounts/{Q}/phone/toll-free-verification", {}),
    ("POST", f"/v1/accounts/{Q}/pieces/resume", {"json": {"piece": "inbox"}}),
    ("POST", f"/v1/accounts/{Q}/pieces/resume", {"json": {"piece": "phone"}}),
    ("POST", f"/v1/accounts/{Q}/calls", {"json": CALL, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/calls", {"json": CALL}),
    ("GET", f"/v1/accounts/{Q}/calls", {}),
    ("GET", f"/v1/accounts/{Q}/calls", {"params": {"limit": 5, "cursor": "c1"}, "extra_headers": PPT}),
    ("GET", f"/v1/accounts/{Q}/calls/acall%2F1", {"extra_headers": PPT}),
    ("GET", f"/v1/accounts/{Q}/calls/acall%2F1", {}),
    ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/answer", {"json": ANSWER, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/answer", {"json": ANSWER}),
    ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/decline", {"json": {}, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/decline", {"json": {}}),
    ("POST", f"/v1/accounts/{Q}/tools/discover", {"json": {"query": "espresso prices"}, "extra_headers": PPT}),
    (
        "POST",
        f"/v1/accounts/{Q}/tools/discover",
        {"json": {"query": "espresso prices", "limit": 10}, "extra_headers": PPT},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/tools/inspect",
        {"json": {"provider": "acme", "endpoint": "/v1/search"}, "extra_headers": PPT},
    ),
    ("POST", f"/v1/accounts/{Q}/tools/run", {"json": TOOL_RUN, "extra_headers": PPT}),
    ("GET", f"/v1/accounts/{Q}/tools/runs/atr%2F1", {"extra_headers": PPT}),
    ("GET", f"/v1/accounts/{Q}/tools/runs/atr%2F1", {}),
    (
        "POST",
        f"/v1/accounts/{Q}/workspaces/exec",
        {"json": {"command": "ls", "stack_access": True}, "extra_headers": PPT},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/workspaces/exec",
        {
            "json": {
                "workspace_id": "wsp_12345678",
                "command": "ls",
                "cwd": "/w",
                "env": {"A": "1"},
                "timeout_seconds": 30,
            },
            "extra_headers": PPT,
        },
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/workspaces/wsp_12345678/files/read",
        {"json": {"path": "a.txt"}, "extra_headers": PPT},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/workspaces/wsp_12345678/files/write",
        {"json": {"path": "a.txt", "content_text": "x", "mode": "755"}, "extra_headers": PPT},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/workspaces/wsp_12345678/files/save",
        {"json": {"path": "a.csv", "name": "r.csv", "visibility": "account"}, "extra_headers": PPT},
    ),
    ("GET", f"/v1/accounts/{Q}/workspaces", {}),
    ("GET", "/v1/workspaces", {}),
    ("PUT", f"/v1/accounts/{Q}/workspaces/wsp_12345678/sharing", {"json": {"shared": False}}),
    ("POST", f"/v1/accounts/{Q}/workspaces/wsp_12345678/stop", {"json": {"delete": True}}),
    ("GET", "/v1/workspace/settings", {}),
    ("GET", f"/v1/accounts/{Q}/workspace/settings", {}),
    ("PUT", "/v1/workspace/settings", {"json": {"idle_pause_minutes": 0, "delete_after_days": 30}}),
    ("PUT", f"/v1/accounts/{Q}/workspace/settings", {"json": {"max_workspaces": 5, "idle_pause_minutes": None}}),
    ("POST", f"/v1/accounts/{Q}/browser/sessions", {"json": {}, "extra_headers": PPT}),
    (
        "POST",
        f"/v1/accounts/{Q}/browser/sessions/bs%2F1/navigate",
        {"json": {"url": "https://shop.example"}, "extra_headers": PPT},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/browser/sessions/bs%2F1/act",
        {"json": {"action": "click", "target": {"text": "Buy"}}, "extra_headers": PPT},
    ),
    ("POST", f"/v1/accounts/{Q}/browser/sessions/bs%2F1/read", {"json": {}, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/browser/sessions/bs%2F1/screenshot", {"json": {}, "extra_headers": PPT}),
    ("DELETE", f"/v1/accounts/{Q}/browser/sessions/bs%2F1", {}),
    (
        "POST",
        f"/v1/accounts/{Q}/browser/sessions/bs%2F1/checkout",
        {"json": {"merchant_origin": "https://shop.example", "amount_minor": 1299, "currency": "USD"}},
    ),
    ("GET", f"/v1/accounts/{Q}/purchases/pur%2F1", {}),
    (
        "POST",
        f"/v1/accounts/{Q}/purchases/pur%2F1/merchant-result",
        {"json": {"status": "completed", "order_id": "o1"}, "extra_headers": PPT},
    ),
    (
        "POST",
        f"/v1/accounts/{Q}/wallet/payments",
        {"json": {"typed_data": {"a": 1}, "agent_signature": "sig"}, "extra_headers": PPT_AS_AGENT},
    ),
    ("GET", "/v1/accounts/wallet-owner", {}),
    ("GET", "/v1/accounts/mail-domains", {}),
    ("POST", "/v1/accounts/mail-domains", {"json": {"domain": "mail.example.com"}}),
    ("POST", "/v1/accounts/mail-domains/omd%2F1/verify", {"json": {}}),
    ("GET", f"/v1/accounts/{Q}/signing-keys", {}),
    ("POST", f"/v1/accounts/{Q}/signing-keys/rotate", {"json": {}}),
    ("GET", f"/v1/accounts/{Q}/identity", {}),
    ("PUT", f"/v1/accounts/{Q}/identity", {"json": {"show_name": True}}),
    ("PUT", f"/v1/accounts/{Q}/identity", {"json": {"enabled": False}}),
    (
        "POST",
        f"/v1/accounts/{Q}/email/send",
        {"json": {"to": "a@example.test", "subject": "Receipt", "body": "Thanks"}},
    ),
    ("POST", f"/v1/accounts/{Q}/email/send", {"json": GROUP_EMAIL_WIRE, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/messages/msg%2F1/reply", {"json": REPLY, "extra_headers": PPT}),
    ("POST", f"/v1/accounts/{Q}/messages/msg%2F1/reply", {"json": {"body": "Thanks."}}),
    ("POST", f"/v1/accounts/{Q}/messages/msg%2F1/forward", {"json": FORWARD_WIRE, "extra_headers": PPT}),
]


def test_sync_requests_match_the_routes() -> None:
    client = Capture()
    _drive_sync(AccountsService(client))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_async_requests_match_sync() -> None:
    client = AsyncCapture()
    asyncio.run(_drive_async(AsyncAccountsService(client)))  # type: ignore[arg-type]
    assert client.calls == EXPECTED_CALLS


def test_open_sends_a_request_without_a_budget() -> None:
    client = Capture()
    aclient = AsyncCapture()
    AccountsService(client).open({"name": "Support"}, idempotency_key="open-67890")  # type: ignore[arg-type]
    asyncio.run(AsyncAccountsService(aclient).open({"name": "Support"}, idempotency_key="open-67890"))  # type: ignore[arg-type]
    expected = [
        ("POST", "/v1/accounts", {"json": {"name": "Support"}, "extra_headers": {"Idempotency-Key": "open-67890"}})
    ]
    assert client.calls == expected and aclient.calls == expected


@pytest.mark.parametrize("key", ["", "short", "x" * 129])
def test_open_refuses_a_bad_idempotency_key_before_any_request(key: str) -> None:
    client = Capture()
    aclient = AsyncCapture()
    with pytest.raises(ValueError, match="idempotency_key"):
        AccountsService(client).open(OPEN_REQUEST, idempotency_key=key)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="idempotency_key"):
        asyncio.run(AsyncAccountsService(aclient).open(OPEN_REQUEST, idempotency_key=key))  # type: ignore[arg-type]
    assert client.calls == [] and aclient.calls == []


def test_accounts_have_no_ai_disclosure_service() -> None:
    assert not hasattr(AccountsService(Capture()), "disclosure")  # type: ignore[arg-type]
    assert not hasattr(AsyncAccountsService(AsyncCapture()), "disclosure")  # type: ignore[arg-type]


@pytest.mark.parametrize("settings", [{}, {"hold_cents": 5}, {"idle_pause_minutes": 0, "segment_max_minutes": 600}])
def test_workspace_settings_refuse_nothing_to_change_and_what_is_not_a_setting_before_any_request(
    settings: dict[str, Any],
) -> None:
    client = Capture()
    aclient = AsyncCapture()
    with pytest.raises(ValueError):
        AccountsService(client).workspace.set_settings(settings)
    with pytest.raises(ValueError):
        asyncio.run(AsyncAccountsService(aclient).workspace.set_settings(settings, ACCT))
    assert client.calls == [] and aclient.calls == []


def test_workspace_settings_send_zero_and_null_as_they_are() -> None:
    client = Capture()
    AccountsService(client).workspace.set_settings({"idle_pause_minutes": 0, "delete_after_days": None})
    assert client.calls[0][0:2] == ("PUT", "/v1/workspace/settings")
    assert client.calls[0][2]["json"] == {"idle_pause_minutes": 0, "delete_after_days": None}


def test_workspace_settings_paths_are_the_routes_of_the_api() -> None:
    routes = (
        Path(__file__).resolve().parents[2]
        / "apps"
        / "api"
        / "src"
        / "hosted"
        / "routes"
        / "account-workspace-settings.ts"
    )
    if not routes.exists():
        pytest.skip("the monorepo is not present")
    source = routes.read_text(encoding="utf-8")
    for path in ("/v1/workspace/settings", "/v1/accounts/:id/workspace/settings"):
        assert f"app.get('{path}'" in source and f"app.put('{path}'" in source


@pytest.mark.parametrize("token", ["", None])
def test_tools_refuse_a_missing_passport_before_any_request(token: Any) -> None:
    client = Capture()
    aclient = AsyncCapture()
    tools = AccountsService(client).tools  # type: ignore[arg-type]
    atools = AsyncAccountsService(aclient).tools  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="passport_token"):
        tools.discover(ACCT, query="q", passport_token=token)
    with pytest.raises(ValueError, match="passport_token"):
        tools.inspect(ACCT, provider="acme", endpoint="/v1/search", passport_token=token)
    with pytest.raises(ValueError, match="passport_token"):
        tools.run(ACCT, TOOL_RUN, passport_token=token)
    with pytest.raises(ValueError, match="passport_token"):
        asyncio.run(atools.discover(ACCT, query="q", passport_token=token))
    with pytest.raises(ValueError, match="passport_token"):
        asyncio.run(atools.inspect(ACCT, provider="acme", endpoint="/v1/search", passport_token=token))
    with pytest.raises(ValueError, match="passport_token"):
        asyncio.run(atools.run(ACCT, TOOL_RUN, passport_token=token))
    assert client.calls == [] and aclient.calls == []


def test_tools_passport_is_a_required_keyword() -> None:
    for service in (AccountsService, AsyncAccountsService):
        tools = service(Capture()).tools  # type: ignore[arg-type]
        for name in ("discover", "inspect", "run"):
            param = inspect.signature(getattr(tools, name)).parameters["passport_token"]
            assert param.kind is inspect.Parameter.KEYWORD_ONLY, name
            assert param.default is inspect.Parameter.empty, name


def _group(accounts: Any, path: str) -> Any:
    for part in filter(None, path.split(".")):
        accounts = getattr(accounts, part)
    return accounts


def test_both_clients_expose_the_same_account_surface() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    sync, async_ = Stack(**kw), AsyncStack(**kw)
    groups = [
        "",
        "messages",
        "toll_free_verification",
        "calls",
        "tools",
        "workspace",
        "browser",
        "purchases",
        "wallet",
        "mail_domains",
        "signing_keys",
    ]
    for group in groups:
        s = _group(sync.accounts, group)
        a = _group(async_.accounts, group)
        s_methods = {n: m for n, m in inspect.getmembers(s, inspect.ismethod) if not n.startswith("_")}
        a_methods = {n: m for n, m in inspect.getmembers(a, inspect.ismethod) if not n.startswith("_")}
        assert set(s_methods) == set(a_methods), group
        for name, method in s_methods.items():
            assert inspect.iscoroutinefunction(a_methods[name]), f"{group}.{name} is not async"
            assert list(inspect.signature(method).parameters) == list(inspect.signature(a_methods[name]).parameters), (
                f"{group}.{name}"
            )


def _error_response(status: int, code: str, details: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": f"{code} message", "details": details}})

    return httpx.MockTransport(handler)


ERROR_CASES = [
    (
        403,
        "GOVERNANCE_APPROVAL_REQUIRED",
        {"approval_id": "gvr_1", "approval_url": "https://getstack.run/approve/gvr_1"},
        GovernanceApprovalRequiredError,
        {"approval_id": "gvr_1", "approval_url": "https://getstack.run/approve/gvr_1"},
    ),
    (
        409,
        "ACCOUNT_PIECE_NOT_READY",
        {"account_id": "acct_1", "piece": "inbox", "state": "pending"},
        AccountPieceNotReadyError,
        {"account_id": "acct_1", "piece": "inbox", "state": "pending"},
    ),
    (
        402,
        "AGENT_BUDGET_EXCEEDED",
        {"account_id": "acct_1", "remaining_cents": 12},
        AgentBudgetExceededError,
        {"account_id": "acct_1", "remaining_cents": 12},
    ),
    (
        503,
        "PROVIDER_CAPACITY_UNAVAILABLE",
        {"provider": "telnyx"},
        ProviderCapacityUnavailableError,
        {"provider": "telnyx"},
    ),
    (
        502,
        "ACCOUNT_CALL_FAILED",
        {"reason": "provider_unavailable"},
        AccountCallFailedError,
        {"reason": "provider_unavailable", "retryable": True},
    ),
    (
        422,
        "ACCOUNT_CALL_FAILED",
        {"reason": "invalid_number"},
        AccountCallFailedError,
        {"reason": "invalid_number", "retryable": False},
    ),
    (422, "DESTINATION_NOT_AVAILABLE", {"reason": "no_price"}, DestinationNotAvailableError, {"reason": "no_price"}),
    (403, "RECIPIENT_OPTED_OUT", {"account_id": "acct_1"}, RecipientOptedOutError, {"account_id": "acct_1"}),
    (
        422,
        "DESTINATION_NOT_AVAILABLE",
        {"reason": "refused_by_twilio"},
        DestinationNotAvailableError,
        {"reason": "refused_by_twilio"},
    ),
    (
        422,
        "TOOL_PRICE_REFUSED",
        {"reason": "result_bound_unavailable", "provider": "acme", "endpoint": "/v1/search"},
        ToolPriceRefusedError,
        {"reason": "result_bound_unavailable", "provider": "acme", "endpoint": "/v1/search"},
    ),
    (503, "TOOLS_UNAVAILABLE", {"reason": "wallet_low"}, ToolsUnavailableError, {"reason": "wallet_low"}),
    (503, "CATALOGUE_UNAVAILABLE", {"reason": "not_built"}, CatalogueUnavailableError, {"reason": "not_built"}),
    (400, "TOOL_RUN_REJECTED", {"provider_status": 422}, ToolRunRejectedError, {"provider_status": 422}),
    (403, "BUDGET_NEEDS_CONTROLS", {}, BudgetNeedsControlsError, {}),
    (
        402,
        "PLATFORM_SUBSCRIPTION_REQUIRED",
        {"status": "lapsed"},
        PlatformSubscriptionRequiredError,
        {"subscription_status": "lapsed"},
    ),
    (429, "SHARED_MAIL_DAILY_LIMIT", {"limit": 20}, SharedMailDailyLimitError, {"limit": 20}),
    (
        400,
        "UNBOUNDED_SEND_RULE",
        {
            "rules": [
                {
                    "rule_id": "mail",
                    "connection_id": "scon_x",
                    "provider": "resend",
                    "reason": "unbound_recipient",
                    "intents": ["resend.send_email"],
                    "unbound_paths": ["body.to"],
                }
            ]
        },
        UnboundedSendRuleError,
        {
            "rules": [
                {
                    "rule_id": "mail",
                    "connection_id": "scon_x",
                    "provider": "resend",
                    "reason": "unbound_recipient",
                    "intents": ["resend.send_email"],
                    "unbound_paths": ["body.to"],
                }
            ]
        },
    ),
]


def test_budget_needs_controls_is_a_forbidden_error() -> None:
    assert issubclass(BudgetNeedsControlsError, ForbiddenError)


@pytest.mark.parametrize(("status", "code", "details", "cls", "attrs"), ERROR_CASES)
def test_sync_client_raises_typed_account_errors(
    status: int, code: str, details: dict[str, Any], cls: type[StackError], attrs: dict[str, Any]
) -> None:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=_error_response(status, code, details))
    with pytest.raises(cls) as raised:
        AccountsService(http).open(OPEN_REQUEST, idempotency_key="open-12345")
    error = raised.value
    assert isinstance(error, StackError)
    assert (error.code, error.status_code, error.details, str(error)) == (code, status, details, f"{code} message")
    for name, value in attrs.items():
        assert getattr(error, name) == value


@pytest.mark.parametrize(("status", "code", "details", "cls", "attrs"), ERROR_CASES)
def test_async_client_raises_typed_account_errors(
    status: int, code: str, details: dict[str, Any], cls: type[StackError], attrs: dict[str, Any]
) -> None:
    async def run() -> StackError:
        http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
        http._client = httpx.AsyncClient(transport=_error_response(status, code, details))
        try:
            await AsyncAccountsService(http).get("acct_1")
        except StackError as error:
            return error
        raise AssertionError("expected an error")

    error = asyncio.run(run())
    assert type(error) is cls
    for name, value in attrs.items():
        assert getattr(error, name) == value


def test_a_call_that_is_not_ringing_any_more_raises_the_api_error() -> None:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=_error_response(409, "CALL_NOT_RINGING", {"call_id": "acall_1"}))
    with pytest.raises(StackError) as declined:
        AccountsService(http).calls.decline("acct_1", "acall_1")
    assert (declined.value.code, declined.value.status_code) == ("CALL_NOT_RINGING", 409)
    with pytest.raises(StackError) as answered:
        AccountsService(http).calls.answer("acct_1", "acall_1", ANSWER)
    assert (answered.value.code, answered.value.status_code) == ("CALL_NOT_RINGING", 409)


def test_governance_error_is_still_a_forbidden_error() -> None:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=_error_response(403, "GOVERNANCE_APPROVAL_REQUIRED", {"approval_id": "g"}))
    with pytest.raises(ForbiddenError) as raised:
        AccountsService(http).close("acct_1")
    assert isinstance(raised.value, GovernanceApprovalRequiredError)
    assert raised.value.approval_id == "g"
    assert raised.value.approval_url is None


def _recording_client(seen: list[httpx.Request], status: int = 200) -> HttpClient:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json={"status": "added"})

    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return http


def test_governance_approval_and_passport_headers_reach_the_wire() -> None:
    seen: list[httpx.Request] = []
    accounts = AccountsService(_recording_client(seen, 201))
    accounts.toll_free_verification.submit("acct_1", TOLL_FREE, governance_approval_id="gvr_1")
    accounts.tools.run("acct_1", TOOL_RUN, passport_token="ppt")
    accounts.resume_piece("acct_1", "phone")
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/v1/accounts/acct_1/phone/toll-free-verification"),
        ("POST", "/v1/accounts/acct_1/tools/run"),
        ("POST", "/v1/accounts/acct_1/pieces/resume"),
    ]
    assert seen[0].headers["X-Governance-Approval"] == "gvr_1"
    assert seen[1].headers["X-Passport-Token"] == "ppt"
    assert "X-Governance-Approval" not in seen[2].headers
    assert "X-Passport-Token" not in seen[0].headers


SEND_VIEW = {
    "message_id": "amsg_1",
    "channel": "email",
    "provider_message_id": "om_1",
    "thread_id": "thr_1",
    "status": "sent",
    "to": ["ada@example.test"],
    "cc": ["grace@example.test", "alan@example.test"],
    "bcc": ["audit@example.test"],
    "attachments": [
        {"filename": "report.pdf", "content_type": "application/pdf", "size_bytes": 25, "file_id": "dfl_2"}
    ],
}


def test_send_reply_and_forward_reach_the_wire_and_answer_the_extended_result() -> None:
    seen: list[httpx.Request] = []
    accounts = AccountsService(_answering(seen, SEND_VIEW, 201))
    sent = accounts.send_email("acct_1", GROUP_EMAIL, passport_token="ppt")
    replied = accounts.reply_email("acct_1", "amsg_9", REPLY)
    forwarded = accounts.forward_email("acct_1", "amsg_9", FORWARD, passport_token="ppt")
    assert sent == replied == forwarded == SEND_VIEW
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/v1/accounts/acct_1/email/send"),
        ("POST", "/v1/accounts/acct_1/messages/amsg_9/reply"),
        ("POST", "/v1/accounts/acct_1/messages/amsg_9/forward"),
    ]
    assert [json.loads(r.content) for r in seen] == [GROUP_EMAIL_WIRE, REPLY, FORWARD_WIRE]
    assert seen[0].headers["X-Passport-Token"] == "ppt"
    assert "X-Passport-Token" not in seen[1].headers
    assert seen[2].headers["X-Passport-Token"] == "ppt"


def test_async_send_reply_and_forward_reach_the_wire() -> None:
    seen: list[httpx.Request] = []
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json=SEND_VIEW)

    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    accounts = AsyncAccountsService(http)

    async def run() -> list[Any]:
        return [
            await accounts.send_email("acct_1", GROUP_EMAIL),
            await accounts.reply_email("acct_1", "amsg_9", REPLY, passport_token="ppt"),
            await accounts.forward_email("acct_1", "amsg_9", FORWARD),
        ]

    assert asyncio.run(run()) == [SEND_VIEW, SEND_VIEW, SEND_VIEW]
    assert [json.loads(r.content) for r in seen] == [GROUP_EMAIL_WIRE, REPLY, FORWARD_WIRE]
    assert seen[1].headers["X-Passport-Token"] == "ppt"
    assert "X-Passport-Token" not in seen[2].headers


def test_inline_attachments_accept_bytes_bytearray_and_memoryview() -> None:
    pdf = {"filename": "r.pdf", "content_type": "application/pdf"}
    for content in (REPORT_PDF, bytearray(REPORT_PDF), memoryview(REPORT_PDF)):
        body = email_body({"to": "a@example.test", "body": "x", "attachments": [{**pdf, "content": content}]})
        assert body["attachments"] == [{**pdf, "content_base64": REPORT_B64}]


def test_an_empty_inline_file_is_sent_like_any_other() -> None:
    attachment = {"filename": "empty.txt", "content_type": "text/plain", "content": b""}
    body = email_body({"bcc": ["a@example.test"], "body": "x", "attachments": [attachment]})
    assert body["attachments"] == [{"filename": "empty.txt", "content_type": "text/plain", "content_base64": ""}]
    assert "to" not in body


def test_a_request_the_sdk_encodes_leaves_the_callers_dict_alone() -> None:
    attachment = {"filename": "r.pdf", "content_type": "application/pdf", "content": REPORT_PDF}
    email = {"to": "a@example.test", "body": "x", "attachments": [attachment]}
    client = Capture()
    AccountsService(client).send_email(ACCT, email)  # type: ignore[arg-type]
    assert attachment == {"filename": "r.pdf", "content_type": "application/pdf", "content": REPORT_PDF}
    assert client.calls[0][2]["json"]["attachments"][0]["content_base64"] == REPORT_B64


def test_an_attachment_that_is_already_base64_or_a_drive_file_goes_as_it_is() -> None:
    attachments = [
        {"file_id": "dfl_1"},
        {"filename": "n.txt", "content_type": "text/plain", "content_base64": "aGVsbG8="},
    ]
    client = Capture()
    AccountsService(client).send_email(ACCT, {"to": ["a@example.test"], "body": "x", "attachments": attachments})  # type: ignore[arg-type]
    assert client.calls[0][2]["json"]["attachments"] == attachments


@pytest.mark.parametrize(
    "attachments",
    [
        "report.pdf",
        {"file_id": "dfl_1"},
        ["report.pdf"],
        [{"filename": "r.txt", "content_type": "text/plain", "content": "text, not bytes"}],
        [{"file_id": "dfl_1", "content": b"x"}],
        [{"filename": "r.txt", "content_type": "text/plain", "content": b"x", "content_base64": "eA=="}],
    ],
)
def test_email_calls_refuse_a_bad_attachment_before_any_request(attachments: Any) -> None:
    client, aclient = Capture(), AsyncCapture()
    sync, async_ = AccountsService(client), AsyncAccountsService(aclient)  # type: ignore[arg-type]
    email = {"to": "a@example.test", "body": "x", "attachments": attachments}
    calls = [
        lambda: sync.send_email(ACCT, email),
        lambda: sync.reply_email(ACCT, "msg_1", email),
        lambda: sync.forward_email(ACCT, "msg_1", email),
        lambda: asyncio.run(async_.send_email(ACCT, email)),
        lambda: asyncio.run(async_.reply_email(ACCT, "msg_1", email)),
        lambda: asyncio.run(async_.forward_email(ACCT, "msg_1", email)),
    ]
    for call in calls:
        with pytest.raises(ValueError):
            call()
    assert client.calls == [] and aclient.calls == []


def test_a_plain_send_to_one_person_is_sent_as_it_was_before() -> None:
    client = Capture()
    email = {"to": "a@example.test", "subject": "Hi", "body": "Hello"}
    AccountsService(client).send_email(ACCT, email)  # type: ignore[arg-type]
    assert client.calls[0][2]["json"] == email


def test_a_send_names_the_stored_message_it_answers_for_a_per_job_policy() -> None:
    client = Capture()
    accounts = AccountsService(client)  # type: ignore[arg-type]
    email = {"to": "a@example.test", "subject": "Re: order", "body": "Done", "reply_to_message": "amsg_1"}
    sms = {"to": "+14155550123", "body": "Done", "reply_to_message": "amsg_2"}
    call = {**CALL, "reply_to_message": "amsg_3"}
    accounts.send_email(ACCT, email, passport_token="ppt")  # type: ignore[arg-type]
    accounts.send_sms(ACCT, sms)
    accounts.calls.place(ACCT, call)
    accounts.reply_email(ACCT, "amsg_9", {"body": "Thanks."})
    assert [(method, path) for method, path, _ in client.calls] == [
        ("POST", f"/v1/accounts/{Q}/email/send"),
        ("POST", f"/v1/accounts/{Q}/sms/send"),
        ("POST", f"/v1/accounts/{Q}/calls"),
        ("POST", f"/v1/accounts/{Q}/messages/amsg_9/reply"),
    ]
    assert [kwargs["json"] for _, _, kwargs in client.calls] == [email, sms, call, {"body": "Thanks."}]
    assert "reply_to_message" not in client.calls[3][2]["json"]


def test_async_send_names_the_stored_message_it_answers() -> None:
    seen: list[httpx.Request] = []
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={})

    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    accounts = AsyncAccountsService(http)
    email = {"to": "a@example.test", "subject": "Re: order", "body": "Done", "reply_to_message": "amsg_1"}
    sms = {"to": "+14155550123", "body": "Done", "reply_to_message": "amsg_2"}
    call = {**CALL, "reply_to_message": "amsg_3"}

    async def run() -> None:
        await accounts.send_email("acct_1", email)  # type: ignore[arg-type]
        await accounts.send_sms("acct_1", sms)
        await accounts.calls.place("acct_1", call)

    asyncio.run(run())
    assert [(r.url.path, json.loads(r.content)) for r in seen] == [
        ("/v1/accounts/acct_1/email/send", email),
        ("/v1/accounts/acct_1/sms/send", sms),
        ("/v1/accounts/acct_1/calls", call),
    ]


def test_message_delete_returns_none_on_204() -> None:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    assert AccountsService(http).messages.delete("acct_1", "msg_1") is None
    assert seen[0].method == "DELETE"
    assert seen[0].url.path == "/v1/accounts/acct_1/messages/msg_1"


RUN_VIEW: dict[str, Any] = {
    "id": "atr_1",
    "account_id": "acct_1",
    "provider": "acme",
    "endpoint": "/v1/search",
    "state": "settled",
    "price_type": "PER_CALL",
    "max_results": None,
    "reserved_cents": 10,
    "charged_cents": 4,
    "status": "COMPLETED",
    "provider_http_status": 200,
    "result": {"output": [{"title": "Espresso"}]},
    "withheld": None,
    "flag": None,
    "created_at": "2026-10-22T08:00:00Z",
    "settled_at": "2026-10-22T08:00:04Z",
}
FILE = {
    "name": "bike.png",
    "content_type": "image/png",
    "size_bytes": 2048,
    "drive_file_id": "df_1",
    "source_url": None,
    "data_base64": None,
}


def _answering(seen: list[httpx.Request], body: dict[str, Any], status: int = 200) -> HttpClient:
    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return http


def test_a_tool_run_carries_untrusted_and_its_files() -> None:
    seen: list[httpx.Request] = []
    accounts = AccountsService(_answering(seen, {**RUN_VIEW, "untrusted": True, "files": [FILE]}))
    run = accounts.tools.run("acct_1", TOOL_RUN, passport_token="ppt")
    assert run["untrusted"] is True
    assert run["files"] == [FILE]
    assert run["files"][0]["drive_file_id"] == "df_1"
    read = accounts.tools.get_run("acct_1", "atr_1")
    assert read["untrusted"] is True
    assert read["files"][0]["name"] == "bike.png"
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/v1/accounts/acct_1/tools/run"),
        ("GET", "/v1/accounts/acct_1/tools/runs/atr_1"),
    ]


def test_no_ready_tool_method_remains() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    for stack in (Stack(**kw), AsyncStack(**kw)):
        assert not hasattr(stack.accounts.tools, "ready")
        assert not hasattr(stack.accounts, "ready")
    for module in ("getstack.accounts", "getstack._async.accounts"):
        source = Path(importlib.import_module(module).__file__ or "").read_text(encoding="utf8")
        assert "tools/ready" not in source
        assert "ReadyTool" not in source


def test_the_call_tools_and_the_account_voice_on_both_clients() -> None:
    client = Capture()
    accounts = AccountsService(client)  # type: ignore[arg-type]
    accounts.calls.say(ACCT, "acall/1", "Hello, is this Sam?", wait_seconds=5, passport_token="ppt")
    accounts.calls.say(ACCT, "acall/1")
    accounts.calls.press_keys(ACCT, "acall/1", "1w#")
    accounts.calls.set_call_voice(ACCT, "acall/1", {"language": "es-ES"})
    accounts.calls.hang_up(ACCT, "acall/1", passport_token="ppt")
    accounts.calls.get_account_voice(ACCT)
    accounts.calls.set_account_voice(ACCT, {"tts_provider": "Google", "voicemail_greeting": "Leave a message."})
    assert [(method, path, kwargs.get("json")) for method, path, kwargs in client.calls] == [
        ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/say", {"text": "Hello, is this Sam?", "wait_seconds": 5}),
        ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/say", {}),
        ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/keys", {"digits": "1w#"}),
        ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/voice", {"voice": {"language": "es-ES"}}),
        ("POST", f"/v1/accounts/{Q}/calls/acall%2F1/hang-up", {}),
        ("GET", f"/v1/accounts/{Q}/phone/voice", None),
        ("PUT", f"/v1/accounts/{Q}/phone/voice", {"tts_provider": "Google", "voicemail_greeting": "Leave a message."}),
    ]

    seen: list[httpx.Request] = []
    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"call": {}, "events": []})

    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    calls = AsyncAccountsService(http).calls

    async def run() -> None:
        await calls.say("acct_1", "acall_1", "Hi", passport_token="ppt")
        await calls.press_keys("acct_1", "acall_1", "9")
        await calls.set_call_voice("acct_1", "acall_1", {"voice": "Joanna-Neural"})
        await calls.hang_up("acct_1", "acall_1")
        await calls.get_account_voice("acct_1")
        await calls.set_account_voice("acct_1", {"language": "fr-FR"})

    asyncio.run(run())
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/v1/accounts/acct_1/calls/acall_1/say"),
        ("POST", "/v1/accounts/acct_1/calls/acall_1/keys"),
        ("POST", "/v1/accounts/acct_1/calls/acall_1/voice"),
        ("POST", "/v1/accounts/acct_1/calls/acall_1/hang-up"),
        ("GET", "/v1/accounts/acct_1/phone/voice"),
        ("PUT", "/v1/accounts/acct_1/phone/voice"),
    ]
    assert seen[0].headers["X-Passport-Token"] == "ppt"


def test_the_live_stream_of_a_call() -> None:
    from getstack.accounts import AccountCallStream, call_stream_target

    url, headers = call_stream_target(
        "https://api.example.test", {"Authorization": "Bearer sk_live_x"}, "acct_1", "acall_1", "ppt"
    )
    assert url == "wss://api.example.test/v1/accounts/acct_1/calls/acall_1/live"
    assert headers == {"Authorization": "Bearer sk_live_x", "X-Passport-Token": "ppt"}

    class FakeSocket:
        def __init__(self) -> None:
            self.sent: list[str] = []
            self.incoming = [
                json.dumps({"seq": 1, "at": "t", "type": "heard", "text": "Yes."}),
                json.dumps({"type": "error", "code": "VALIDATION_ERROR", "message": "no"}),
                json.dumps({"seq": 2, "at": "t", "type": "ended", "reason": "agent_hung_up"}),
            ]

        def __iter__(self):  # type: ignore[no-untyped-def]
            return iter(self.incoming)

        def send(self, data: str) -> None:
            self.sent.append(data)

        def close(self) -> None:
            pass

    socket = FakeSocket()
    stream = AccountCallStream(socket)
    stream.text("Hello, ")
    stream.text("is this Sam?", last=True)
    stream.press_keys("1")
    stream.hang_up()
    assert [json.loads(m) for m in socket.sent] == [
        {"type": "text", "token": "Hello, ", "last": False},
        {"type": "text", "token": "is this Sam?", "last": True},
        {"type": "keys", "digits": "1"},
        {"type": "hang_up"},
    ]
    assert [e["seq"] for e in stream] == [1, 2]
    assert stream.errors == [{"type": "error", "code": "VALIDATION_ERROR", "message": "no"}]


@pytest.mark.parametrize("cents", [2500, None])
def test_set_budget_puts_the_budget_and_the_approval_on_retry(cents: int | None) -> None:
    client = Capture()
    aclient = AsyncCapture()
    AccountsService(client).set_budget(ACCT, cents)  # type: ignore[arg-type]
    AccountsService(client).set_budget(ACCT, cents, governance_approval_id="gvr_7")  # type: ignore[arg-type]
    asyncio.run(AsyncAccountsService(aclient).set_budget(ACCT, cents))  # type: ignore[arg-type]
    asyncio.run(AsyncAccountsService(aclient).set_budget(ACCT, cents, governance_approval_id="gvr_7"))  # type: ignore[arg-type]
    expected = [
        ("PUT", f"/v1/accounts/{Q}/budget", {"json": {"monthly_budget_cents": cents}}),
        (
            "PUT",
            f"/v1/accounts/{Q}/budget",
            {"json": {"monthly_budget_cents": cents}, "extra_headers": {"X-Governance-Approval": "gvr_7"}},
        ),
    ]
    assert client.calls == expected and aclient.calls == expected


@pytest.mark.parametrize("cents", [0, -1, 12.5, True, "2500"])
def test_set_budget_refuses_a_bad_budget_before_any_request(cents: Any) -> None:
    client = Capture()
    aclient = AsyncCapture()
    with pytest.raises(ValueError, match="monthly_budget_cents"):
        AccountsService(client).set_budget(ACCT, cents)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="monthly_budget_cents"):
        asyncio.run(AsyncAccountsService(aclient).set_budget(ACCT, cents))  # type: ignore[arg-type]
    assert client.calls == [] and aclient.calls == []
