"""Async catalogue: the awaitable mirror of ``getstack.catalogue``."""

from __future__ import annotations

from typing import cast

from ..catalogue import account_path, conditional_headers, read_result, search_params
from ..client import AsyncHttpClient
from ..types import CatalogueAccountView, CatalogueRead, CatalogueSearchResult


class AsyncCatalogueService:
    """Everything an agent can use through its account, as one document. See ``CatalogueService``."""

    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self, if_none_match: str | None = None) -> CatalogueRead:
        """The whole catalogue, with its ``etag``; ``not_modified`` when ``if_none_match`` is current."""
        status, headers, body = await self._client.request_with_headers(
            "GET", "/v1/catalogue", extra_headers=conditional_headers(if_none_match)
        )
        return read_result(status, headers, body, if_none_match)

    async def search(
        self,
        q: str | None = None,
        kind: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> CatalogueSearchResult:
        """Entries whose id, name, description or provider contain every word of ``q``."""
        params = search_params(q, kind, limit, offset)
        return cast("CatalogueSearchResult", await self._client.request("GET", "/v1/catalogue/search", params=params))

    async def for_account(self, account_id: str) -> CatalogueAccountView:
        """What is true of one account: its connected services and the state of its own pieces."""
        return cast("CatalogueAccountView", await self._client.request("GET", account_path(account_id)))
