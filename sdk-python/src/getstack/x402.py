"""Paying an x402 seller from an agent account's wallet in one step.

Ask the URL; when the seller answers 402, make the payment it asks for, sign it with the agent's own wallet key, let
STACK check it and pass it to the wallet (``POST /v1/accounts/:id/wallet/payments``), and ask again with the payment
attached. What the seller answers then is what was bought: there is no order and no checkout page.

The wallet signs one kind of payment, an EIP-3009 TransferWithAuthorization of USDC on Base, which is x402's
``exact`` scheme. Both versions of x402 are read: version 2 (``PAYMENT-REQUIRED`` and ``PAYMENT-SIGNATURE``, the shape
of STACK's spec/agent-site-payments) and version 1 (the requirements in the body, the payment in ``X-PAYMENT``). A
seller that asks for anything else is refused here, before STACK is asked. The key never leaves this process; the
seller's address must be https (localhost aside), and the paid request follows no redirect.

The TypeScript SDK's ``x402-pay.ts`` is the same, step for step.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from .wallet_key import AgentWalletKey, WalletPaymentTarget, sign_wallet_payment

BASE_CHAIN_ID = 8453
BASE_CAIP2 = f"eip155:{BASE_CHAIN_ID}"
BASE_USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_DOMAIN_NAME = "USD Coin"
_DOMAIN_VERSION = "2"
_MAX_AUTHORIZATION_SECONDS = 540
_MIN_AUTHORIZATION_SECONDS = 60
_ATOMIC_PER_CENT = 10_000
_TRANSFER_FIELDS = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = re.compile(r"^0x0{40}$")
_UINT = re.compile(r"^(0|[1-9][0-9]{0,77})$")


class X402PaymentError(Exception):
    """The payment was not made: nothing was signed and STACK was not asked.

    ``code`` is one of insecure_url, unreadable_requirements, not_payable, over_max, wallet_not_ready.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class X402Result:
    """``paid`` is False when the seller answered without asking for payment. ``response`` is what was bought when
    ``paid`` and the response is a success. ``payment`` is STACK's record; ``settlement`` the seller's receipt."""

    paid: bool
    response: httpx.Response
    payment: dict[str, Any] | None = None
    settlement: Any = field(default=None)


@dataclass(frozen=True)
class X402Wallet:
    address: str
    wallet_id: str
    app_id: str


def assert_payable_url(url: str) -> None:
    """Only https carries a payment, except to this machine."""
    parsed = urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise X402PaymentError("insecure_url", "A payment is sent only over https (http only to localhost).")


def _requirement(entry: Any, version: int) -> dict[str, Any] | None:
    if not isinstance(entry, Mapping):
        return None
    amount = entry.get("amount") if version == 2 else entry.get("maxAmountRequired")
    network = BASE_CAIP2 if (version == 1 and entry.get("network") == "base") else entry.get("network")
    if not all(
        isinstance(v, str) for v in (entry.get("scheme"), network, amount, entry.get("asset"), entry.get("payTo"))
    ):
        return None
    requirement: dict[str, Any] = {
        "scheme": entry["scheme"],
        "network": network,
        "amount": amount,
        "asset": entry["asset"],
        "payTo": entry["payTo"],
    }
    if isinstance(entry.get("maxTimeoutSeconds"), int):
        requirement["maxTimeoutSeconds"] = entry["maxTimeoutSeconds"]
    extra = entry.get("extra")
    if isinstance(extra, Mapping):
        requirement["extra"] = {k: extra[k] for k in ("name", "version") if isinstance(extra.get(k), str)}
    return requirement


def _payable(r: dict[str, Any]) -> bool:
    extra = r.get("extra", {})
    return (
        r["scheme"] == "exact"
        and r["network"] == BASE_CAIP2
        and r["asset"].lower() == BASE_USDC_ADDRESS.lower()
        and bool(_ADDRESS.match(r["payTo"]))
        and not _ZERO_ADDRESS.match(r["payTo"])
        and bool(_UINT.match(r["amount"]))
        and int(r["amount"]) > 0
        and extra.get("name", _DOMAIN_NAME) == _DOMAIN_NAME
        and extra.get("version", _DOMAIN_VERSION) == _DOMAIN_VERSION
    )


def read_x402_ask(*, payment_required_header: str | None = None, body_text: str | None = None) -> dict[str, Any]:
    """What a 402 asks for, and the entry the wallet can pay.

    Returns ``{"version", "requirement", "accepted"}``, with ``"resource"`` when the seller named one.
    """
    version = 2 if payment_required_header else 1
    try:
        if payment_required_header:
            document = json.loads(base64.b64decode(payment_required_header, validate=True).decode("utf-8"))
        else:
            document = json.loads(body_text or "")
    except (ValueError, UnicodeDecodeError) as error:
        raise X402PaymentError(
            "unreadable_requirements", "The 402 carries no payment requirements x402 can read."
        ) from error
    if (
        not isinstance(document, Mapping)
        or document.get("x402Version") != version
        or not isinstance(document.get("accepts"), list)
    ):
        raise X402PaymentError("unreadable_requirements", f"The payment requirements are not x402 version {version}.")
    for entry in document["accepts"]:
        requirement = _requirement(entry, version)
        if requirement is not None and _payable(requirement):
            ask: dict[str, Any] = {"version": version, "requirement": requirement, "accepted": entry}
            resource = document.get("resource") if version == 2 else entry.get("resource")
            if resource is not None:
                ask["resource"] = resource
            return ask
    raise X402PaymentError(
        "not_payable", "The seller asks for a payment the wallet cannot make: only USDC on Base with the exact scheme."
    )


def cents_of_atomic(atomic: str) -> int:
    """Cents of an atomic USDC amount, rounded up (as STACK's budget counts it)."""
    return -(-int(atomic) // _ATOMIC_PER_CENT)


def x402_transfer_typed_data(
    requirement: Mapping[str, Any], from_address: str, now_seconds: int, nonce: str | None = None
) -> dict[str, Any]:
    """The authorization the wallet signs: from the wallet, to and value exactly as the seller asked."""
    lifetime = min(
        max(int(requirement.get("maxTimeoutSeconds", 300)), _MIN_AUTHORIZATION_SECONDS), _MAX_AUTHORIZATION_SECONDS
    )
    return {
        "domain": {
            "name": _DOMAIN_NAME,
            "version": _DOMAIN_VERSION,
            "chainId": BASE_CHAIN_ID,
            "verifyingContract": BASE_USDC_ADDRESS,
        },
        "types": {"TransferWithAuthorization": [{"name": n, "type": t} for n, t in _TRANSFER_FIELDS]},
        "primary_type": "TransferWithAuthorization",
        "message": {
            "from": from_address,
            "to": requirement["payTo"],
            "value": requirement["amount"],
            "validAfter": "0",
            "validBefore": str(int(now_seconds) + lifetime),
            "nonce": nonce or "0x" + os.urandom(32).hex(),
        },
    }


def x402_payment_header(ask: Mapping[str, Any], typed_data: Mapping[str, Any], signature: str) -> tuple[str, str]:
    """The header (name, value) that carries the signed payment on the repeated request."""
    payload = {"signature": signature, "authorization": typed_data["message"]}
    if ask["version"] == 2:
        body: dict[str, Any] = {"x402Version": 2}
        if "resource" in ask:
            body["resource"] = ask["resource"]
        body.update({"accepted": ask["accepted"], "payload": payload})
        name = "PAYMENT-SIGNATURE"
    else:
        body = {"x402Version": 1, "scheme": "exact", "network": ask["accepted"]["network"], "payload": payload}
        name = "X-PAYMENT"
    return name, base64.b64encode(json.dumps(body, separators=(",", ":")).encode("utf-8")).decode("ascii")


def x402_wallet_of(pieces: Sequence[Mapping[str, Any]]) -> X402Wallet:
    """The account's wallet from its ``wallet`` piece; raises when it is not ready."""
    piece = next((p for p in pieces if p.get("kind") == "wallet"), None)
    details = (piece or {}).get("details") or {}
    address, wallet_id, app_id = details.get("address"), details.get("wallet_id"), details.get("privy_app_id")
    if (
        piece is None
        or piece.get("state") != "ready"
        or not isinstance(address, str)
        or not isinstance(wallet_id, str)
        or not isinstance(app_id, str)
    ):
        raise X402PaymentError("wallet_not_ready", "The account has no ready wallet to pay from.")
    return X402Wallet(address=address, wallet_id=wallet_id, app_id=app_id)


def _settlement(response: httpx.Response, version: int) -> Any:
    receipt = response.headers.get("payment-response" if version == 2 else "x-payment-response")
    if not receipt:
        return None
    try:
        return json.loads(base64.b64decode(receipt).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return receipt


def _prepare(
    first: httpx.Response, url: str, max_cents: int | None, key: AgentWalletKey, wallet: X402Wallet, now: int
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    resource = str(first.url) if first.url else url
    assert_payable_url(resource)
    ask = read_x402_ask(payment_required_header=first.headers.get("payment-required"), body_text=first.text)
    cents = cents_of_atomic(ask["requirement"]["amount"])
    if max_cents is not None and cents > max_cents:
        raise X402PaymentError("over_max", f"The seller asks {cents} cents, over the most allowed ({max_cents}).")
    typed_data = x402_transfer_typed_data(ask["requirement"], wallet.address, now)
    signed = sign_wallet_payment(
        key, WalletPaymentTarget(app_id=wallet.app_id, wallet_id=wallet.wallet_id, typed_data=typed_data)
    )
    return resource, ask, typed_data, signed


def pay_x402(
    url: str,
    *,
    key: AgentWalletKey,
    wallet: X402Wallet,
    pay: Callable[[dict[str, Any]], dict[str, Any]],
    max_cents: int | None = None,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    content: bytes | str | None = None,
    http: httpx.Client | None = None,
    now_seconds: Callable[[], int] | None = None,
) -> X402Result:
    """Ask ``url`` and, when the seller answers 402, pay it from the wallet and ask again. ``pay`` is STACK's payment
    route for the account. Raises ``X402PaymentError`` when nothing was paid; a STACK refusal from ``pay`` is raised
    as it came. Once STACK has passed the payment on, the result is returned whatever the seller answers."""
    assert_payable_url(url)
    client = http or httpx.Client(timeout=30.0)
    try:
        base = dict(headers or {})
        first = client.request(method.upper(), url, headers=base, content=content, follow_redirects=True)
        if first.status_code != 402:
            return X402Result(paid=False, response=first)
        now = now_seconds() if now_seconds else int(time.time())
        resource, ask, typed_data, signed = _prepare(first, url, max_cents, key, wallet, now)
        payment = pay(signed)
        name, value = x402_payment_header(ask, typed_data, payment["signature"])
        response = client.request(
            method.upper(), resource, headers={**base, name: value}, content=content, follow_redirects=False
        )
        response.read()
        return X402Result(
            paid=True, response=response, payment=payment, settlement=_settlement(response, ask["version"])
        )
    finally:
        if http is None:
            client.close()


async def pay_x402_async(
    url: str,
    *,
    key: AgentWalletKey,
    wallet: X402Wallet,
    pay: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
    max_cents: int | None = None,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    content: bytes | str | None = None,
    http: httpx.AsyncClient | None = None,
    now_seconds: Callable[[], int] | None = None,
) -> X402Result:
    """The asynchronous ``pay_x402``."""
    assert_payable_url(url)
    client = http or httpx.AsyncClient(timeout=30.0)
    try:
        base = dict(headers or {})
        first = await client.request(method.upper(), url, headers=base, content=content, follow_redirects=True)
        if first.status_code != 402:
            return X402Result(paid=False, response=first)
        await first.aread()
        now = now_seconds() if now_seconds else int(time.time())
        resource, ask, typed_data, signed = _prepare(first, url, max_cents, key, wallet, now)
        payment = await pay(signed)
        name, value = x402_payment_header(ask, typed_data, payment["signature"])
        response = await client.request(
            method.upper(), resource, headers={**base, name: value}, content=content, follow_redirects=False
        )
        await response.aread()
        return X402Result(
            paid=True, response=response, payment=payment, settlement=_settlement(response, ask["version"])
        )
    finally:
        if http is None:
            await client.aclose()
