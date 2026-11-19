"""Async PaymentsService mirror: getting paid through the customer's own Stripe and USDC."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..payments import _account, _agent_passport, _optional, _passport, _seg


class AsyncPaymentsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def start_stripe(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Start the customer's Stripe connection, or return the open one (an agent gets no ``connect_url``)."""
        return cast(
            "dict[str, Any]",
            await self._client.post(f"{_account(account_id)}/stripe", json={}, extra_headers=_passport(passport_token)),
        )

    async def get_stripe(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """``{"connection": {...} | None}``."""
        return cast(
            "dict[str, Any]",
            await self._client.get(f"{_account(account_id)}/stripe", extra_headers=_passport(passport_token)),
        )

    async def disconnect_stripe(self, account_id: str) -> None:
        """Erase the key and signing secret and turn off the active links. Owner or admin only."""
        await self._client.delete(f"{_account(account_id)}/stripe")

    async def create_link(
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
        """A reusable link for one fixed price. The agent's call, under its Passport."""
        headers = _agent_passport(passport_token)
        body = _optional(
            name=name, amount_minor=amount_minor, currency=currency, item=item, after_payment_url=after_payment_url
        )
        return cast(
            "dict[str, Any]",
            await self._client.post(f"{_account(account_id)}/links", json=body, extra_headers=headers),
        )

    async def create_checkout_session(
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
        """A one-off checkout session for one fixed price. The agent's call, under its Passport."""
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
            await self._client.post(f"{_account(account_id)}/checkout-sessions", json=body, extra_headers=headers),
        )

    async def list_links(
        self, account_id: str, *, limit: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """``{"links": [...]}``."""
        params = {"limit": str(limit)} if limit is not None else None
        return cast(
            "dict[str, Any]",
            await self._client.get(
                f"{_account(account_id)}/links", params=params, extra_headers=_passport(passport_token)
            ),
        )

    async def deactivate_link(self, account_id: str, link_id: str, *, passport_token: str) -> dict[str, Any]:
        """Turn a link off so it can no longer be paid. The agent's call, under its Passport."""
        headers = _agent_passport(passport_token)
        return cast(
            "dict[str, Any]",
            await self._client.post(f"{_account(account_id)}/links/{_seg(link_id)}/deactivate", extra_headers=headers),
        )

    async def list_payments(
        self,
        account_id: str,
        *,
        rail: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Payments received on either rail, newest first: ``{"payments": [...], "next_cursor": ...}``."""
        params = _optional(rail=rail, limit=str(limit) if limit is not None else None, cursor=cursor)
        return cast(
            "dict[str, Any]",
            await self._client.get(
                _account(account_id), params=params or None, extra_headers=_passport(passport_token)
            ),
        )

    async def get_payment(
        self, account_id: str, payment_id: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.get(
                f"{_account(account_id)}/{_seg(payment_id)}", extra_headers=_passport(passport_token)
            ),
        )
