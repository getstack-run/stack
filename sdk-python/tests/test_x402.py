"""The one-step x402 payment: both versions, the refusals, and stack.accounts.wallet.pay_url on both clients."""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import httpx
import pytest

from getstack import AsyncStack, Stack
from getstack.wallet_key import generate_agent_wallet_key
from getstack.x402 import (
    BASE_USDC_ADDRESS,
    X402PaymentError,
    X402Wallet,
    pay_x402,
    pay_x402_async,
    read_x402_ask,
)

SELLER = "https://seller.example/reports/42"
PAY_TO = "0x5555555555555555555555555555555555555555"
WALLET = X402Wallet(address="0x1111111111111111111111111111111111111111", wallet_id="wal_1", app_id="app_1")
SIGNATURE = "0x" + "ab" * 65
NOW = 1_800_000_000
ACCOUNT = "acct_0123456789abcdef0123456789abcdef"
KEY = generate_agent_wallet_key()


def _b64(value: Any) -> str:
    return base64.b64encode(json.dumps(value).encode()).decode()


def _unb64(value: str) -> dict[str, Any]:
    decoded: dict[str, Any] = json.loads(base64.b64decode(value))
    return decoded


def v2_entry(**over: Any) -> dict[str, Any]:
    entry = {
        "scheme": "exact",
        "network": "eip155:8453",
        "amount": "250000",
        "asset": BASE_USDC_ADDRESS,
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    entry.update(over)
    return entry


def v1_entry(**over: Any) -> dict[str, Any]:
    entry = {
        "scheme": "exact",
        "network": "base",
        "maxAmountRequired": "10000",
        "resource": SELLER,
        "payTo": PAY_TO,
        "asset": BASE_USDC_ADDRESS,
        "maxTimeoutSeconds": 120,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    entry.update(over)
    return entry


class Seller:
    """402 until a payment header comes, then the goods."""

    def __init__(self, version: int, accepts: list[Any] | None = None, after_payment: httpx.Response | None = None):
        self.version = version
        self.accepts = accepts
        self.after_payment = after_payment
        self.seen: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        name = "payment-signature" if self.version == 2 else "x-payment"
        if request.headers.get(name):
            if self.after_payment is not None:
                return self.after_payment
            receipt = "payment-response" if self.version == 2 else "x-payment-response"
            return httpx.Response(
                200, text="the report", headers={receipt: _b64({"success": True, "transaction": "0xfeed"})}
            )
        accepts = self.accepts or [v2_entry() if self.version == 2 else v1_entry()]
        if self.version == 2:
            return httpx.Response(
                402,
                text="{}",
                headers={"payment-required": _b64({"x402Version": 2, "resource": {"url": SELLER}, "accepts": accepts})},
            )
        return httpx.Response(402, json={"x402Version": 1, "accepts": accepts})


class StackPay:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, payment: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(payment)
        return {"payment_id": "wpay_1", "signature": SIGNATURE, "amount_atomic": "250000", "amount_cents": 25}


def _pay(seller: Seller, stack: StackPay, url: str = SELLER, **kwargs: Any) -> Any:
    with httpx.Client(transport=httpx.MockTransport(seller)) as http:
        return pay_x402(url, key=KEY, wallet=WALLET, pay=stack, http=http, now_seconds=lambda: NOW, **kwargs)


def test_pays_a_version_2_seller_once_and_returns_the_goods() -> None:
    seller, stack = Seller(2), StackPay()
    result = _pay(seller, stack)
    assert result.paid and result.response.text == "the report"
    assert result.settlement == {"success": True, "transaction": "0xfeed"}
    assert len(stack.calls) == 1
    typed = stack.calls[0]["typed_data"]
    assert typed["domain"] == {
        "name": "USD Coin",
        "version": "2",
        "chainId": 8453,
        "verifyingContract": BASE_USDC_ADDRESS,
    }
    assert typed["message"]["to"] == PAY_TO and typed["message"]["value"] == "250000"
    assert typed["message"]["from"] == WALLET.address and typed["message"]["validBefore"] == str(NOW + 60)
    header = _unb64(seller.seen[1].headers["payment-signature"])
    assert header["x402Version"] == 2 and header["accepted"] == v2_entry() and header["resource"] == {"url": SELLER}
    assert header["payload"] == {"signature": SIGNATURE, "authorization": typed["message"]}


def test_pays_a_version_1_seller_with_x_payment() -> None:
    seller, stack = Seller(1), StackPay()
    result = _pay(seller, stack)
    assert result.paid and result.response.text == "the report"
    typed = stack.calls[0]["typed_data"]
    assert typed["message"]["value"] == "10000" and typed["message"]["validBefore"] == str(NOW + 120)
    header = _unb64(seller.seen[1].headers["x-payment"])
    assert header == {
        "x402Version": 1,
        "scheme": "exact",
        "network": "base",
        "payload": {"signature": SIGNATURE, "authorization": typed["message"]},
    }


def test_an_answer_that_is_not_a_402_comes_back_unpaid() -> None:
    stack = StackPay()
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="free"))) as http:
        result = pay_x402(SELLER, key=KEY, wallet=WALLET, pay=stack, http=http)
    assert not result.paid and result.response.text == "free" and stack.calls == []


@pytest.mark.parametrize(
    ("seller", "kwargs", "code"),
    [
        (Seller(2, accepts=[v2_entry(network="eip155:1")]), {}, "not_payable"),
        (Seller(2, accepts=[v2_entry(asset="0x2222222222222222222222222222222222222222")]), {}, "not_payable"),
        (Seller(2, accepts=[v2_entry(scheme="upto")]), {}, "not_payable"),
        (Seller(2), {"max_cents": 24}, "over_max"),
        (Seller(2), {"url": "http://seller.example/reports/42"}, "insecure_url"),
    ],
)
def test_refuses_before_stack_is_asked(seller: Seller, kwargs: dict[str, Any], code: str) -> None:
    stack = StackPay()
    url = kwargs.pop("url", SELLER)
    with pytest.raises(X402PaymentError) as refused:
        _pay(seller, stack, url, **kwargs)
    assert refused.value.code == code
    assert stack.calls == []


def test_the_paid_request_follows_no_redirect_and_a_failure_comes_back_with_the_payment() -> None:
    stack = StackPay()
    seller = Seller(2, after_payment=httpx.Response(302, headers={"location": "https://elsewhere.example/"}))
    result = _pay(seller, stack)
    assert result.paid and result.response.status_code == 302 and len(seller.seen) == 2
    assert result.payment["payment_id"] == "wpay_1"


def test_unreadable_requirements_are_refused() -> None:
    with pytest.raises(X402PaymentError):
        read_x402_ask(payment_required_header="not base64 json")
    with pytest.raises(X402PaymentError):
        read_x402_ask(body_text="<html>pay us</html>")


def test_async_matches_sync() -> None:
    seller = Seller(2)
    calls: list[dict[str, Any]] = []

    async def pay(payment: dict[str, Any]) -> dict[str, Any]:
        calls.append(payment)
        return {"payment_id": "wpay_1", "signature": SIGNATURE, "amount_atomic": "250000", "amount_cents": 25}

    async def run() -> Any:
        async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as http:
            return await pay_x402_async(SELLER, key=KEY, wallet=WALLET, pay=pay, http=http, now_seconds=lambda: NOW)

    result = asyncio.run(run())
    assert result.paid and result.response.text == "the report" and len(calls) == 1


def _stack_api(piece_state: str = "ready") -> tuple[httpx.MockTransport, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":
            return httpx.Response(
                201,
                json={"payment_id": "wpay_1", "signature": SIGNATURE, "amount_atomic": "250000", "amount_cents": 25},
            )
        details = (
            {"address": WALLET.address, "wallet_id": "wal_1", "privy_app_id": "app_1"} if piece_state == "ready" else {}
        )
        return httpx.Response(
            200, json={"id": ACCOUNT, "pieces": [{"kind": "wallet", "state": piece_state, "details": details}]}
        )

    return httpx.MockTransport(handler), seen


def test_stack_accounts_wallet_pay_url() -> None:
    transport, seen = _stack_api()
    stack = Stack(api_key="sk_live_wallet_test", base_url="http://api.fixture")
    stack._client._client = httpx.Client(transport=transport)
    with httpx.Client(transport=httpx.MockTransport(Seller(2))) as http:
        result = stack.accounts.wallet.pay_url(ACCOUNT, SELLER, key=KEY, passport_token="passport-token", http=http)
    assert result.response.text == "the report"
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", f"/v1/accounts/{ACCOUNT}"),
        ("POST", f"/v1/accounts/{ACCOUNT}/wallet/payments"),
    ]
    assert all(r.headers.get("x-passport-token") == "passport-token" for r in seen)
    # The wallet payment route accepts only an agent: the Passport is the bearer credential of both calls.
    assert all(r.headers.get("authorization") == "Bearer passport-token" for r in seen)


class _NotSignedIn:
    def get_headers(self) -> dict[str, str]:
        raise RuntimeError("not signed in")


def test_pay_url_with_a_passport_needs_no_sign_in() -> None:
    transport, seen = _stack_api()
    stack = Stack(api_key="sk_live_wallet_test", base_url="http://api.fixture")
    stack._client.auth = _NotSignedIn()  # type: ignore[assignment]
    stack._client._client = httpx.Client(transport=transport)
    with httpx.Client(transport=httpx.MockTransport(Seller(2))) as http:
        stack.accounts.wallet.pay_url(ACCOUNT, SELLER, key=KEY, passport_token="passport-token", http=http)
    assert all(r.headers.get("authorization") == "Bearer passport-token" for r in seen)


def test_pay_url_without_a_passport_keeps_the_client_credential() -> None:
    transport, seen = _stack_api()
    stack = Stack(api_key="sk_live_wallet_test", base_url="http://api.fixture")
    stack._client._client = httpx.Client(transport=transport)
    with httpx.Client(transport=httpx.MockTransport(Seller(2))) as http:
        stack.accounts.wallet.pay_url(ACCOUNT, SELLER, key=KEY, http=http)
    assert all(r.headers.get("authorization") == "Bearer sk_live_wallet_test" for r in seen)
    assert all("x-passport-token" not in r.headers for r in seen)


def test_pay_url_refuses_a_wallet_that_is_not_ready() -> None:
    transport, seen = _stack_api("pending")
    stack = Stack(api_key="sk_live_wallet_test", base_url="http://api.fixture")
    stack._client._client = httpx.Client(transport=transport)
    with pytest.raises(X402PaymentError) as refused:
        stack.accounts.wallet.pay_url(ACCOUNT, SELLER, key=KEY)
    assert refused.value.code == "wallet_not_ready"
    assert [r.method for r in seen] == ["GET"]


def test_async_stack_accounts_wallet_pay_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":
            return httpx.Response(
                201,
                json={"payment_id": "wpay_1", "signature": SIGNATURE, "amount_atomic": "250000", "amount_cents": 25},
            )
        return httpx.Response(
            200,
            json={
                "id": ACCOUNT,
                "pieces": [
                    {
                        "kind": "wallet",
                        "state": "ready",
                        "details": {"address": WALLET.address, "wallet_id": "wal_1", "privy_app_id": "app_1"},
                    }
                ],
            },
        )

    async def run() -> Any:
        stack = AsyncStack(api_key="sk_live_wallet_test", base_url="http://api.fixture")
        stack._client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with httpx.AsyncClient(transport=httpx.MockTransport(Seller(2))) as http:
            return await stack.accounts.wallet.pay_url(ACCOUNT, SELLER, key=KEY, passport_token="p", http=http)

    result = asyncio.run(run())
    assert result.response.text == "the report" and [r.method for r in seen] == ["GET", "POST"]
    assert all(r.headers.get("authorization") == "Bearer p" for r in seen)
