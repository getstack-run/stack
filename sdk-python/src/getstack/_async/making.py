"""Async making: the awaitable mirror of ``getstack.making``."""

from __future__ import annotations

from typing import Any, cast

from ..accounts import _account, _agent_passport, _approval, _passport, _seg, request_kwargs
from ..client import AsyncHttpClient
from ..making import _limit


class AsyncMakingService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def _call(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        return await self._client.request(method, path, **request_kwargs(json, params, headers))

    def _base(self, account_id: str) -> str:
        return f"{_account(account_id)}/making"

    # ── The agent's actions ──────────────────────────────────────────────

    async def upload_design(self, account_id: str, design: dict[str, Any], *, passport_token: str) -> dict[str, Any]:
        """``design``: exactly one of content_base64, source_url and drive_file_id, with file_name (needed unless
        it is a drive file, whose own name is used) and an optional description.

        Bytes sent in the request are up to 20 MB, which is what one request carries. A larger file goes on the
        agent's drive first and is made a design by its id: nothing is copied and the file is streamed to the
        supplier. The extension of file_name is the format. The same file again returns the same design.
        """
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST", f"{self._base(account_id)}/designs", json=design, headers=_agent_passport(passport_token)
            ),
        )

    async def quote(self, account_id: str, quote: dict[str, Any], *, passport_token: str) -> dict[str, Any]:
        """``quote``: design_id, recipient, and optional supplier and spec.

        Returns ``{"quotes": [...], "unavailable": [...]}``, cheapest first. A request that produced no offer is
        not charged.
        """
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST", f"{self._base(account_id)}/quotes", json=quote, headers=_agent_passport(passport_token)
            ),
        )

    async def order(self, account_id: str, quote_id: str, *, passport_token: str) -> dict[str, Any]:
        """Order a quote. A ``customer_account`` order comes back ``awaiting_approval``; a ``checkout_page``
        order comes back with ``checkout``. Ordering the same quote again returns the same order."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{self._base(account_id)}/orders",
                json={"quote_id": quote_id},
                headers=_agent_passport(passport_token),
            ),
        )

    # ── Reads: the agent or its operator ────────────────────────────────

    async def get_design(self, account_id: str, design_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{self._base(account_id)}/designs/{_seg(design_id)}", headers=_passport(passport_token)
            ),
        )

    async def list_designs(
        self, account_id: str, *, limit: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{self._base(account_id)}/designs", params=_limit(limit), headers=_passport(passport_token)
            ),
        )

    async def get_quote(self, account_id: str, quote_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{self._base(account_id)}/quotes/{_seg(quote_id)}", headers=_passport(passport_token)
            ),
        )

    async def get_order(self, account_id: str, order_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The order as last known; a read refreshes it from the supplier first."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{self._base(account_id)}/orders/{_seg(order_id)}", headers=_passport(passport_token)
            ),
        )

    async def list_orders(
        self, account_id: str, *, limit: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{self._base(account_id)}/orders", params=_limit(limit), headers=_passport(passport_token)
            ),
        )

    async def cancel_order(
        self, account_id: str, order_id: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Stop an order while the supplier still can. It only narrows what happens, so the agent may do it."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{self._base(account_id)}/orders/{_seg(order_id)}/cancel",
                json={},
                headers=_passport(passport_token),
            ),
        )

    # ── The customer's own decisions: operator only ─────────────────────

    async def approve_order(
        self, account_id: str, order_id: str, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """Place a held order on the customer's own supplier account. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{self._base(account_id)}/orders/{_seg(order_id)}/approve",
                json={},
                headers=_approval(governance_approval_id),
            ),
        )

    async def reject_order(self, account_id: str, order_id: str) -> dict[str, Any]:
        """Decline a held order."""
        return cast(
            "dict[str, Any]",
            await self._call("POST", f"{self._base(account_id)}/orders/{_seg(order_id)}/reject", json={}),
        )

    async def list_suppliers(self) -> dict[str, Any]:
        """Every supplier, whether it is usable and, for print on demand, whether your own account is connected."""
        return cast("dict[str, Any]", await self._call("GET", "/v1/accounts/making/suppliers"))

    async def connect_supplier(
        self, supplier: str, *, api_key: str, api_secret: str | None = None, store_id: str | None = None
    ) -> dict[str, Any]:
        """Connect your own account at ``gelato``, ``prodigi``, ``printful`` or ``lulu`` (Lulu also needs
        ``api_secret``). Owner or admin only. The key is encrypted at rest and never read back; keep it out of
        any chat."""
        body: dict[str, Any] = {"api_key": api_key}
        if api_secret is not None:
            body["api_secret"] = api_secret
        if store_id is not None:
            body["store_id"] = store_id
        return cast(
            "dict[str, Any]", await self._call("PUT", f"/v1/accounts/making/suppliers/{_seg(supplier)}", json=body)
        )

    async def connect_printful(self) -> dict[str, Any]:
        """Connect your own Printful account by signing in at Printful instead of pasting a token.

        Returns ``authorize_url`` (and ``expires_in_seconds``): the owner opens it in a browser, signs in or up at
        Printful and approves there. STACK then stores the tokens sealed for you and renews them. Owner or admin only;
        503 ``PRINTFUL_APP_NOT_REGISTERED`` where STACK has not registered its Printful app.
        """
        return cast(
            "dict[str, Any]", await self._call("POST", "/v1/accounts/making/suppliers/printful/connect", json={})
        )

    async def disconnect_supplier(self, supplier: str) -> None:
        """Remove your account at a supplier. Owner or admin only."""
        await self._call("DELETE", f"/v1/accounts/making/suppliers/{_seg(supplier)}")
