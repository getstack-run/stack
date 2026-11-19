"""Async post: the awaitable mirror of ``getstack.post``."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..post import _account_post, _headers, _page_params, _seg, _send_input


class AsyncPostService:
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
        kwargs: dict[str, Any] = {}
        if json is not None:
            kwargs["json"] = json
        if params:
            kwargs["params"] = params
        if headers:
            kwargs["extra_headers"] = headers
        return await self._client.request(method, path, **kwargs)

    # The customer's street address (owner or admin).

    async def get_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._call("GET", "/v1/post/address"))

    async def start_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._call("POST", "/v1/post/address", json={}))

    async def connect_address(self, api_key: str, *, webhook_secret: str | None = None) -> dict[str, Any]:
        """Hand over the agent key the customer created at the supplier; it is a secret and is never returned."""
        body: dict[str, Any] = {"api_key": api_key}
        if webhook_secret is not None:
            body["webhook_secret"] = webhook_secret
        return cast("dict[str, Any]", await self._call("POST", "/v1/post/address/connect", json=body))

    async def refresh_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._call("POST", "/v1/post/address/refresh", json={}))

    async def pause_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._call("POST", "/v1/post/address/pause", json={}))

    async def resume_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._call("POST", "/v1/post/address/resume", json={}))

    async def close_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._call("DELETE", "/v1/post/address"))

    async def list_items(
        self, *, limit: int | None = None, cursor: str | None = None, routing: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", await self._call("GET", "/v1/post/items", params=_page_params(limit, cursor, routing))
        )

    async def assign_item(self, item_id: str, account_id: str) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call("POST", f"/v1/post/items/{_seg(item_id)}/assign", json={"account_id": account_id}),
        )

    # An account's post.

    async def account_address(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call("GET", f"{_account_post(account_id)}/address", headers=_headers(passport_token)),
        )

    async def list_account_items(
        self,
        account_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET",
                f"{_account_post(account_id)}/items",
                params=_page_params(limit, cursor),
                headers=_headers(passport_token),
            ),
        )

    async def get_account_item(
        self, account_id: str, item_id: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{_account_post(account_id)}/items/{_seg(item_id)}", headers=_headers(passport_token)
            ),
        )

    async def scan_item(
        self,
        account_id: str,
        item_id: str,
        *,
        capture: str | None = None,
        idempotency_key: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {} if capture is None else {"capture": capture}
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{_account_post(account_id)}/items/{_seg(item_id)}/scan",
                json=body,
                headers=_headers(passport_token, idempotency_key),
            ),
        )

    async def forward_item(
        self,
        account_id: str,
        item_id: str,
        destination: dict[str, Any],
        *,
        mail_class: str | None = None,
        idempotency_key: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"destination": destination}
        if mail_class is not None:
            body["mail_class"] = mail_class
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{_account_post(account_id)}/items/{_seg(item_id)}/forward",
                json=body,
                headers=_headers(passport_token, idempotency_key),
            ),
        )

    async def shred_item(
        self,
        account_id: str,
        item_id: str,
        *,
        idempotency_key: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{_account_post(account_id)}/items/{_seg(item_id)}/shred",
                json={"confirm": True},
                headers=_headers(passport_token, idempotency_key),
            ),
        )

    async def check_address(
        self, account_id: str, address: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{_account_post(account_id)}/address-check",
                json={"address": address},
                headers=_headers(passport_token),
            ),
        )

    async def send(
        self, account_id: str, letter: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Send a letter or a postcard; see ``PostService.send``."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                f"{_account_post(account_id)}/letters",
                json=_send_input(letter),
                headers=_headers(passport_token),
            ),
        )

    async def list_letters(
        self,
        account_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET",
                f"{_account_post(account_id)}/letters",
                params=_page_params(limit, cursor),
                headers=_headers(passport_token),
            ),
        )

    async def get_letter(self, account_id: str, letter_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._call(
                "GET", f"{_account_post(account_id)}/letters/{_seg(letter_id)}", headers=_headers(passport_token)
            ),
        )
