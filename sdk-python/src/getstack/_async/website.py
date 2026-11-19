"""Async WebsiteService mirror: an agent account's website."""

from __future__ import annotations

import builtins
from typing import Any, cast

from ..client import AsyncHttpClient
from ..website import _agent_passport, _passport, _seg, _site


class AsyncWebsiteService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The account's site: addresses, live deploy, prices and limits."""
        return cast(
            "dict[str, Any]", await self._client.get(_site(account_id), extra_headers=_passport(passport_token))
        )

    async def publish(
        self,
        account_id: str,
        *,
        files: builtins.list[dict[str, str]],
        server: dict[str, str] | None = None,
        passport_token: str,
    ) -> dict[str, Any]:
        """Publish a bundle; it becomes the live site once the scan passes. The agent's call, under its Passport."""
        headers = _agent_passport(passport_token)
        body: dict[str, Any] = {"files": files}
        if server is not None:
            body["server"] = server
        return cast(
            "dict[str, Any]",
            await self._client.post(f"{_site(account_id)}/deploys", json=body, extra_headers=headers),
        )

    async def list_deploys(
        self, account_id: str, *, limit: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """The recent deploys, newest first: ``{"deploys": [...]}``."""
        params = {"limit": str(limit)} if limit is not None else None
        return cast(
            "dict[str, Any]",
            await self._client.get(
                f"{_site(account_id)}/deploys", params=params, extra_headers=_passport(passport_token)
            ),
        )

    async def get_deploy(self, account_id: str, deploy_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.get(
                f"{_site(account_id)}/deploys/{_seg(deploy_id)}", extra_headers=_passport(passport_token)
            ),
        )

    async def add_hostname(self, account_id: str, *, hostname: str, passport_token: str) -> dict[str, Any]:
        """Add the customer's own domain. The agent's call, under its Passport."""
        headers = _agent_passport(passport_token)
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"{_site(account_id)}/hostnames", json={"hostname": hostname}, extra_headers=headers
            ),
        )

    async def list_hostnames(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.get(f"{_site(account_id)}/hostnames", extra_headers=_passport(passport_token)),
        )

    async def check_hostname(
        self, account_id: str, hostname_id: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Check the domain's DNS and certificate now. The owner or the agent."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"{_site(account_id)}/hostnames/{_seg(hostname_id)}/check", extra_headers=_passport(passport_token)
            ),
        )

    async def remove_hostname(self, account_id: str, hostname_id: str, *, passport_token: str) -> None:
        """Stop serving the site on a domain and release the name. The agent's call, under its Passport."""
        headers = _agent_passport(passport_token)
        await self._client.delete(f"{_site(account_id)}/hostnames/{_seg(hostname_id)}", extra_headers=headers)

    async def set_prices(
        self, account_id: str, *, prices: builtins.list[dict[str, str]], passport_token: str
    ) -> dict[str, Any]:
        """Set the paths that cost USDC to read; the list replaces the set. The agent's call."""
        headers = _agent_passport(passport_token)
        return cast(
            "dict[str, Any]",
            await self._client.put(f"{_site(account_id)}/prices", json={"prices": prices}, extra_headers=headers),
        )

    async def get_prices(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            await self._client.get(f"{_site(account_id)}/prices", extra_headers=_passport(passport_token)),
        )

    async def suspend(self, account_id: str, *, reason: str) -> dict[str, Any]:
        """Take the site offline now. Owner or admin only; an agent is refused."""
        return cast(
            "dict[str, Any]",
            await self._client.post(f"{_site(account_id)}/suspension", json={"reason": reason}),
        )

    async def resume(self, account_id: str) -> dict[str, Any]:
        """Bring the site back after your own suspension."""
        return cast("dict[str, Any]", await self._client.delete(f"{_site(account_id)}/suspension"))

    async def suspend_all(self, *, reason: str) -> dict[str, Any]:
        """Suspend every site of your account at once: ``{"suspended": <count>}``."""
        return cast("dict[str, Any]", await self._client.post("/v1/websites/suspend-all", json={"reason": reason}))

    async def report(
        self, url: str, category: str, description: str, *, reporter_email: str | None = None
    ) -> dict[str, Any]:
        """Report a page on a STACK-hosted site. Anyone may: it needs no account and sends no credential."""
        body: dict[str, Any] = {"url": url, "category": category, "description": description}
        if reporter_email is not None:
            body["reporter_email"] = reporter_email
        return cast("dict[str, Any]", await self._client.post_public("/v1/public/site-reports", json=body))
