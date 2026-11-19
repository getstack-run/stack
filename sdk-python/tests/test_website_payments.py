"""An agent's website and getting paid: request shapes, Passport headers, typed errors, sync and async alike."""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncStack, Stack
from getstack._async.payments import AsyncPaymentsService
from getstack._async.website import AsyncWebsiteService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.errors import (
    ForbiddenError,
    PaymentConnectionRequiredError,
    StackError,
    StripeRequestFailedError,
    WebsiteHostnameUnavailableError,
    WebsiteLimitExceededError,
    WebsitePublishRejectedError,
    WebsiteSuspendedError,
)
from getstack.payments import PaymentsService
from getstack.website import WebsiteService, site_files

ACCOUNT = "acct_0123456789abcdef0123456789abcdef"
TOKEN = "agent.passport.jwt"


def _sync(seen: list[httpx.Request], reply: Any = None, status: int = 200) -> HttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if status == 204:
            return httpx.Response(204)
        return httpx.Response(status, json=reply if reply is not None else {})

    http = HttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    return http


def _async(seen: list[httpx.Request], reply: Any = None, status: int = 200) -> AsyncHttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if status == 204:
            return httpx.Response(204)
        return httpx.Response(status, json=reply if reply is not None else {})

    http = AsyncHttpClient(ApiKeyAuth("sk_live_dummy"), base_url="http://api.test")
    http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return http


def _shape(request: httpx.Request) -> tuple[str, str, str, Any, str | None]:
    body = json.loads(request.content) if request.content else None
    raw_path = request.url.raw_path.decode().split("?")[0]
    return (request.method, raw_path, request.url.query.decode(), body, request.headers.get("X-Passport-Token"))


def _drive_website_sync(site: WebsiteService) -> None:
    site.get(ACCOUNT)
    site.get(ACCOUNT, passport_token=TOKEN)
    site.publish(ACCOUNT, files=[{"path": "/index.html", "content": "<h1>Hi</h1>"}], passport_token=TOKEN)
    site.publish(
        ACCOUNT,
        files=[{"path": "/index.html", "content": "x"}],
        server={"source": "export default {}"},
        passport_token=TOKEN,
    )
    site.list_deploys(ACCOUNT, limit=5)
    site.get_deploy(ACCOUNT, "dpl 1")
    site.add_hostname(ACCOUNT, hostname="www.example.com", passport_token=TOKEN)
    site.list_hostnames(ACCOUNT)
    site.check_hostname(ACCOUNT, "hst_1")
    site.check_hostname(ACCOUNT, "hst_1", passport_token=TOKEN)
    site.remove_hostname(ACCOUNT, "hst_1", passport_token=TOKEN)
    site.set_prices(ACCOUNT, prices=[{"path": "/r/*", "price_usdc": "0.25"}], passport_token=TOKEN)
    site.get_prices(ACCOUNT)
    site.suspend(ACCOUNT, reason="checking it")
    site.resume(ACCOUNT)
    site.suspend_all(reason="checking them all")
    site.report("https://a.sites.test/x", "phishing", "asks for a bank login", reporter_email="r@example.com")
    site.report("https://a.sites.test/x", "spam", "sells things nobody asked for")


async def _drive_website_async(site: AsyncWebsiteService) -> None:
    await site.get(ACCOUNT)
    await site.get(ACCOUNT, passport_token=TOKEN)
    await site.publish(ACCOUNT, files=[{"path": "/index.html", "content": "<h1>Hi</h1>"}], passport_token=TOKEN)
    await site.publish(
        ACCOUNT,
        files=[{"path": "/index.html", "content": "x"}],
        server={"source": "export default {}"},
        passport_token=TOKEN,
    )
    await site.list_deploys(ACCOUNT, limit=5)
    await site.get_deploy(ACCOUNT, "dpl 1")
    await site.add_hostname(ACCOUNT, hostname="www.example.com", passport_token=TOKEN)
    await site.list_hostnames(ACCOUNT)
    await site.check_hostname(ACCOUNT, "hst_1")
    await site.check_hostname(ACCOUNT, "hst_1", passport_token=TOKEN)
    await site.remove_hostname(ACCOUNT, "hst_1", passport_token=TOKEN)
    await site.set_prices(ACCOUNT, prices=[{"path": "/r/*", "price_usdc": "0.25"}], passport_token=TOKEN)
    await site.get_prices(ACCOUNT)
    await site.suspend(ACCOUNT, reason="checking it")
    await site.resume(ACCOUNT)
    await site.suspend_all(reason="checking them all")
    await site.report("https://a.sites.test/x", "phishing", "asks for a bank login", reporter_email="r@example.com")
    await site.report("https://a.sites.test/x", "spam", "sells things nobody asked for")


SITE = f"/v1/accounts/{ACCOUNT}/website"
EXPECTED_WEBSITE = [
    ("GET", SITE, "", None, None),
    ("GET", SITE, "", None, TOKEN),
    ("POST", f"{SITE}/deploys", "", {"files": [{"path": "/index.html", "content": "<h1>Hi</h1>"}]}, TOKEN),
    (
        "POST",
        f"{SITE}/deploys",
        "",
        {"files": [{"path": "/index.html", "content": "x"}], "server": {"source": "export default {}"}},
        TOKEN,
    ),
    ("GET", f"{SITE}/deploys", "limit=5", None, None),
    ("GET", f"{SITE}/deploys/dpl%201", "", None, None),
    ("POST", f"{SITE}/hostnames", "", {"hostname": "www.example.com"}, TOKEN),
    ("GET", f"{SITE}/hostnames", "", None, None),
    ("POST", f"{SITE}/hostnames/hst_1/check", "", None, None),
    ("POST", f"{SITE}/hostnames/hst_1/check", "", None, TOKEN),
    ("DELETE", f"{SITE}/hostnames/hst_1", "", None, TOKEN),
    ("PUT", f"{SITE}/prices", "", {"prices": [{"path": "/r/*", "price_usdc": "0.25"}]}, TOKEN),
    ("GET", f"{SITE}/prices", "", None, None),
    ("POST", f"{SITE}/suspension", "", {"reason": "checking it"}, None),
    ("DELETE", f"{SITE}/suspension", "", None, None),
    ("POST", "/v1/websites/suspend-all", "", {"reason": "checking them all"}, None),
    (
        "POST",
        "/v1/public/site-reports",
        "",
        {
            "url": "https://a.sites.test/x",
            "category": "phishing",
            "description": "asks for a bank login",
            "reporter_email": "r@example.com",
        },
        None,
    ),
    (
        "POST",
        "/v1/public/site-reports",
        "",
        {"url": "https://a.sites.test/x", "category": "spam", "description": "sells things nobody asked for"},
        None,
    ),
]

PAY = f"/v1/accounts/{ACCOUNT}/payments"


def _drive_payments_sync(pay: PaymentsService) -> None:
    pay.start_stripe(ACCOUNT)
    pay.start_stripe(ACCOUNT, passport_token=TOKEN)
    pay.get_stripe(ACCOUNT)
    pay.disconnect_stripe(ACCOUNT)
    pay.create_link(ACCOUNT, name="Report", amount_minor=1200, passport_token=TOKEN)
    pay.create_link(
        ACCOUNT,
        name="Report",
        amount_minor=1200,
        currency="eur",
        item="r-1",
        after_payment_url="https://a.sites.test/ok",
        passport_token=TOKEN,
    )
    pay.create_checkout_session(
        ACCOUNT, name="Report", amount_minor=1200, success_url="https://a.sites.test/ok", passport_token=TOKEN
    )
    pay.list_links(ACCOUNT, limit=10)
    pay.deactivate_link(ACCOUNT, "pl 1", passport_token=TOKEN)
    pay.list_payments(ACCOUNT)
    pay.list_payments(ACCOUNT, rail="x402", limit=5, cursor="c1")
    pay.get_payment(ACCOUNT, "pay_1")


async def _drive_payments_async(pay: AsyncPaymentsService) -> None:
    await pay.start_stripe(ACCOUNT)
    await pay.start_stripe(ACCOUNT, passport_token=TOKEN)
    await pay.get_stripe(ACCOUNT)
    await pay.disconnect_stripe(ACCOUNT)
    await pay.create_link(ACCOUNT, name="Report", amount_minor=1200, passport_token=TOKEN)
    await pay.create_link(
        ACCOUNT,
        name="Report",
        amount_minor=1200,
        currency="eur",
        item="r-1",
        after_payment_url="https://a.sites.test/ok",
        passport_token=TOKEN,
    )
    await pay.create_checkout_session(
        ACCOUNT, name="Report", amount_minor=1200, success_url="https://a.sites.test/ok", passport_token=TOKEN
    )
    await pay.list_links(ACCOUNT, limit=10)
    await pay.deactivate_link(ACCOUNT, "pl 1", passport_token=TOKEN)
    await pay.list_payments(ACCOUNT)
    await pay.list_payments(ACCOUNT, rail="x402", limit=5, cursor="c1")
    await pay.get_payment(ACCOUNT, "pay_1")


EXPECTED_PAYMENTS = [
    ("POST", f"{PAY}/stripe", "", {}, None),
    ("POST", f"{PAY}/stripe", "", {}, TOKEN),
    ("GET", f"{PAY}/stripe", "", None, None),
    ("DELETE", f"{PAY}/stripe", "", None, None),
    ("POST", f"{PAY}/links", "", {"name": "Report", "amount_minor": 1200}, TOKEN),
    (
        "POST",
        f"{PAY}/links",
        "",
        {
            "name": "Report",
            "amount_minor": 1200,
            "currency": "eur",
            "item": "r-1",
            "after_payment_url": "https://a.sites.test/ok",
        },
        TOKEN,
    ),
    (
        "POST",
        f"{PAY}/checkout-sessions",
        "",
        {"name": "Report", "amount_minor": 1200, "success_url": "https://a.sites.test/ok"},
        TOKEN,
    ),
    ("GET", f"{PAY}/links", "limit=10", None, None),
    ("POST", f"{PAY}/links/pl%201/deactivate", "", None, TOKEN),
    ("GET", PAY, "", None, None),
    ("GET", PAY, "rail=x402&limit=5&cursor=c1", None, None),
    ("GET", f"{PAY}/pay_1", "", None, None),
]


def test_website_sync_requests_match_the_routes() -> None:
    seen: list[httpx.Request] = []
    _drive_website_sync(WebsiteService(_sync(seen, {"accepted": True})))
    assert [_shape(r) for r in seen] == EXPECTED_WEBSITE


def test_website_async_requests_match_sync() -> None:
    seen: list[httpx.Request] = []
    asyncio.run(_drive_website_async(AsyncWebsiteService(_async(seen, {"accepted": True}))))
    assert [_shape(r) for r in seen] == EXPECTED_WEBSITE


def test_payments_sync_requests_match_the_routes() -> None:
    seen: list[httpx.Request] = []
    _drive_payments_sync(PaymentsService(_sync(seen, {"links": []})))
    assert [_shape(r) for r in seen] == EXPECTED_PAYMENTS


def test_payments_async_requests_match_sync() -> None:
    seen: list[httpx.Request] = []
    asyncio.run(_drive_payments_async(AsyncPaymentsService(_async(seen, {"links": []}))))
    assert [_shape(r) for r in seen] == EXPECTED_PAYMENTS


def test_the_public_report_sends_no_credential() -> None:
    seen: list[httpx.Request] = []
    WebsiteService(_sync(seen, {"accepted": True})).report(
        "https://a.sites.test/x", "spam", "sells things nobody asked"
    )
    assert "Authorization" not in seen[0].headers
    assert "X-Api-Key" not in seen[0].headers
    assert all("sk_live_dummy" not in value for value in seen[0].headers.values())
    seen_async: list[httpx.Request] = []
    asyncio.run(
        AsyncWebsiteService(_async(seen_async, {"accepted": True})).report(
            "https://a.sites.test/x", "spam", "sells things nobody asked"
        )
    )
    assert all("sk_live_dummy" not in value for value in seen_async[0].headers.values())


def test_the_agent_calls_refuse_without_a_passport_before_any_request() -> None:
    seen: list[httpx.Request] = []
    site = WebsiteService(_sync(seen))
    pay = PaymentsService(_sync(seen))
    with pytest.raises(ValueError):
        site.publish(ACCOUNT, files=[{"path": "/a", "content": "x"}], passport_token="")
    with pytest.raises(ValueError):
        site.add_hostname(ACCOUNT, hostname="www.example.com", passport_token="")
    with pytest.raises(ValueError):
        site.remove_hostname(ACCOUNT, "hst_1", passport_token="")
    with pytest.raises(ValueError):
        site.set_prices(ACCOUNT, prices=[], passport_token="")
    with pytest.raises(ValueError):
        pay.create_link(ACCOUNT, name="R", amount_minor=100, passport_token="")
    with pytest.raises(ValueError):
        pay.create_checkout_session(
            ACCOUNT, name="R", amount_minor=100, success_url="https://x.test", passport_token=""
        )
    with pytest.raises(ValueError):
        pay.deactivate_link(ACCOUNT, "pl_1", passport_token="")
    assert seen == []


def _error(code: str, status: int, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": f"{code} happened", "details": details or {}}}


def test_typed_errors() -> None:
    def raised(code: str, status: int, details: dict[str, Any] | None = None) -> StackError:
        seen: list[httpx.Request] = []
        site = WebsiteService(_sync(seen, _error(code, status, details), status))
        with pytest.raises(StackError) as caught:
            site.get(ACCOUNT)
        return caught.value

    rejected = raised(
        "WEBSITE_PUBLISH_REJECTED",
        422,
        {"findings": [{"code": "brand_impersonation", "path": "/login.html"}, {"code": "scanner_unavailable"}]},
    )
    assert isinstance(rejected, WebsitePublishRejectedError)
    assert rejected.findings == [
        {"code": "brand_impersonation", "path": "/login.html"},
        {"code": "scanner_unavailable", "path": None},
    ]
    assert rejected.status_code == 422

    limit = raised("WEBSITE_LIMIT_EXCEEDED", 403, {"limit": "max_total_bytes", "max": 52428800})
    assert isinstance(limit, WebsiteLimitExceededError)
    assert isinstance(limit, ForbiddenError)
    assert (limit.limit, limit.max) == ("max_total_bytes", 52428800)

    suspended = raised("WEBSITE_SUSPENDED", 403, {"state": "taken_down", "by": "staff"})
    assert isinstance(suspended, WebsiteSuspendedError)
    assert (suspended.state, suspended.by) == ("taken_down", "staff")

    taken = raised("WEBSITE_HOSTNAME_UNAVAILABLE", 409, {"reason": "taken"})
    assert isinstance(taken, WebsiteHostnameUnavailableError)
    assert taken.reason == "taken"

    assert isinstance(raised("PAYMENT_CONNECTION_REQUIRED", 409), PaymentConnectionRequiredError)

    stripe = raised("STRIPE_REQUEST_FAILED", 502, {"kind": "unavailable", "provider_status": 503})
    assert isinstance(stripe, StripeRequestFailedError)
    assert (stripe.kind, stripe.provider_status, stripe.status_code) == ("unavailable", 503, 502)

    other = raised("SOMETHING_ELSE", 500)
    assert type(other) is StackError


def test_site_files_builds_a_bundle() -> None:
    files = site_files(
        [
            {"path": "/index.html", "content": "<h1>Hi</h1>"},
            {"path": "/note.txt", "content": b"plain bytes"},
            {"path": "/logo.png", "content": b"\x89PNG\r\n\x1a\n\x00\x00"},
            {"path": "/bad.bin", "content": b"\xff\xfe\xfd"},
        ]
    )
    assert files[0] == {"path": "/index.html", "content": "<h1>Hi</h1>"}
    assert files[1] == {"path": "/note.txt", "content": "plain bytes"}
    assert files[2] == {"path": "/logo.png", "content_base64": "iVBORw0KGgoAAA=="}
    assert files[3] == {"path": "/bad.bin", "content_base64": "//79"}


def test_site_files_refuses_an_empty_bundle_and_a_repeated_path_and_takes_any_number_of_files() -> None:
    with pytest.raises(ValueError):
        site_files([])
    assert len(site_files([{"path": f"/{i}.txt", "content": "x"} for i in range(501)])) == 501
    with pytest.raises(ValueError):
        site_files([{"path": "/a", "content": "x"}, {"path": "/a", "content": "y"}])


def test_both_clients_expose_the_same_surface() -> None:
    kw: dict[str, Any] = {"api_key": "sk_live_dummy", "base_url": "http://localhost:9999"}
    sync, asynchronous = Stack(**kw), AsyncStack(**kw)
    for name in ("website", "payments"):
        s, a = getattr(sync, name), getattr(asynchronous, name)
        s_methods = {n: m for n, m in inspect.getmembers(s, inspect.ismethod) if not n.startswith("_")}
        a_methods = {n: m for n, m in inspect.getmembers(a, inspect.ismethod) if not n.startswith("_")}
        assert set(s_methods) == set(a_methods), name
        for method_name, method in s_methods.items():
            assert inspect.iscoroutinefunction(a_methods[method_name]), method_name
            assert list(inspect.signature(method).parameters) == list(
                inspect.signature(a_methods[method_name]).parameters
            ), method_name
