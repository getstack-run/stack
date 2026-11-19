"""Getting paid: the customer's own Stripe, payment links and checkout sessions, and the payments received.

The customer connects their own Stripe with a restricted key; the account's agent then asks to be paid with
payment links and checkout sessions. The money goes from the buyer to the customer's own Stripe account and
STACK never holds it. Payments for priced site paths arrive in USDC on the agent's own wallet and are listed
with the card ones.

The restricted key is never typed into a chat, a call or this SDK: the customer pastes it, with the webhook
signing secret, into the connect page whose address ``start_stripe`` returns. Calls the agent makes
(``create_link``, ``create_checkout_session``, ``deactivate_link``) require its Passport as ``passport_token``,
sent as ``X-Passport-Token``, and refuse an empty one before any request. Disconnecting is the owner's alone.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


def _seg(value: str) -> str:
    return quote(value, safe="")


def _account(account_id: str) -> str:
    return f"/v1/accounts/{_seg(account_id)}/payments"


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _agent_passport(passport_token: str) -> dict[str, str]:
    if not isinstance(passport_token, str) or not passport_token:
        raise ValueError("passport_token is required: the account's agent does this, under its Passport")
    return {"X-Passport-Token": passport_token}


def _optional(**fields: Any) -> dict[str, Any]:
    return {key: value for key, value in fields.items() if value is not None}


class PaymentsService:
    def __init__(self, client: HttpClient):
        self._client = client

    def start_stripe(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Start the customer's Stripe connection, or return the open one.

        It is ``awaiting_key``: the customer opens ``connect_url``, adds ``webhook_url`` with ``webhook_events``
        as an endpoint in their Stripe, and pastes a restricted key and that endpoint's signing secret on the
        page. Called by an agent it returns the connection without a ``connect_url``.
        """
        # An empty JSON object, not no body: the API refuses a JSON request with an empty body.
        return cast(
            "dict[str, Any]",
            self._client.post(f"{_account(account_id)}/stripe", json={}, extra_headers=_passport(passport_token)),
        )

    def get_stripe(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """``{"connection": {...} | None}``."""
        return cast(
            "dict[str, Any]",
            self._client.get(f"{_account(account_id)}/stripe", extra_headers=_passport(passport_token)),
        )

    def disconnect_stripe(self, account_id: str) -> None:
        """Erase the key and signing secret and turn off the active links. Owner or admin only."""
        self._client.delete(f"{_account(account_id)}/stripe")

    def create_link(
        self,
        account_id: str,
        *,
        name: str,
        amount_minor: int,
        currency: str | None = None,
        item: str | None = None,
        after_payment_url: str | None = None,
        passport_token: str,
    ) -> dict[str, Any]:
        """A reusable link for one fixed price (``amount_minor`` in the currency's smallest unit; ``usd`` when
        ``currency`` is omitted). One metered action and a decision for the customer's controls. Raises
        ``PaymentConnectionRequiredError`` when there is no active connection."""
        headers = _agent_passport(passport_token)
        body = _optional(
            name=name, amount_minor=amount_minor, currency=currency, item=item, after_payment_url=after_payment_url
        )
        return cast(
            "dict[str, Any]", self._client.post(f"{_account(account_id)}/links", json=body, extra_headers=headers)
        )

    def create_checkout_session(
        self,
        account_id: str,
        *,
        name: str,
        amount_minor: int,
        success_url: str,
        cancel_url: str | None = None,
        currency: str | None = None,
        item: str | None = None,
        passport_token: str,
    ) -> dict[str, Any]:
        """A one-off checkout session for one fixed price. Metered and decided like ``create_link``; both
        addresses must be on the agent's own site."""
        headers = _agent_passport(passport_token)
        body = _optional(
            name=name,
            amount_minor=amount_minor,
            currency=currency,
            item=item,
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return cast(
            "dict[str, Any]",
            self._client.post(f"{_account(account_id)}/checkout-sessions", json=body, extra_headers=headers),
        )

    def list_links(
        self, account_id: str, *, limit: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """``{"links": [...]}``; ``limit`` is 1 to 100."""
        params = {"limit": str(limit)} if limit is not None else None
        return cast(
            "dict[str, Any]",
            self._client.get(f"{_account(account_id)}/links", params=params, extra_headers=_passport(passport_token)),
        )

    def deactivate_link(self, account_id: str, link_id: str, *, passport_token: str) -> dict[str, Any]:
        """Turn a link off so it can no longer be paid."""
        headers = _agent_passport(passport_token)
        return cast(
            "dict[str, Any]",
            self._client.post(f"{_account(account_id)}/links/{_seg(link_id)}/deactivate", extra_headers=headers),
        )

    def list_payments(
        self,
        account_id: str,
        *,
        rail: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Payments received on either rail, newest first: ``{"payments": [...], "next_cursor": ... | None}``.

        ``rail`` is ``stripe`` or ``x402``; ``limit`` is 1 to 100; pass the previous ``next_cursor`` as ``cursor``.
        """
        params = _optional(rail=rail, limit=str(limit) if limit is not None else None, cursor=cursor)
        return cast(
            "dict[str, Any]",
            self._client.get(_account(account_id), params=params or None, extra_headers=_passport(passport_token)),
        )

    def get_payment(self, account_id: str, payment_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.get(f"{_account(account_id)}/{_seg(payment_id)}", extra_headers=_passport(passport_token)),
        )
