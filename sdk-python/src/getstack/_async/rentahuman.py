"""Async mirror of RentAHumanService."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..rentahuman import _base, _join_body, _passport, sign_rentahuman_payment
from ..wallet_key import AgentWalletKey


class AsyncRentAHumanService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def join(
        self,
        account_id: str,
        *,
        country: str,
        accept_terms: bool,
        city: str | None = None,
        agent_name: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Step one of opening a RentAHuman account; see ``RentAHumanService.join``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/join",
                json=_join_body(country, city, agent_name, accept_terms),
                extra_headers=_passport(passport_token),
            ),
        )

    async def complete_join(
        self, account_id: str, join_id: str, signed: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Step two: the agent's signature; see ``RentAHumanService.complete_join``."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/join/complete",
                json={"join_id": join_id, "signed": signed},
                extra_headers=_passport(passport_token),
            ),
        )

    async def join_with_key(
        self,
        account_id: str,
        key: AgentWalletKey,
        *,
        country: str,
        accept_terms: bool,
        city: str | None = None,
        agent_name: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Both steps: ask, sign with the agent's wallet key, and send the signature."""
        start = await self.join(
            account_id,
            country=country,
            accept_terms=accept_terms,
            city=city,
            agent_name=agent_name,
            passport_token=passport_token,
        )
        return await self.complete_join(
            account_id, start["join_id"], sign_rentahuman_payment(key, start), passport_token=passport_token
        )

    async def fund(self, account_id: str, amount_cents: int, *, passport_token: str | None = None) -> dict[str, Any]:
        """Step one of topping up the customer's RentAHuman wallet."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/fund",
                json={"amount_cents": amount_cents},
                extra_headers=_passport(passport_token),
            ),
        )

    async def complete_fund(
        self, account_id: str, fund_id: str, signed: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Step two of a top-up."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"{_base(account_id)}/fund/complete",
                json={"fund_id": fund_id, "signed": signed},
                extra_headers=_passport(passport_token),
            ),
        )

    async def fund_with_key(
        self, account_id: str, key: AgentWalletKey, amount_cents: int, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Both steps of a top-up."""
        start = await self.fund(account_id, amount_cents, passport_token=passport_token)
        return await self.complete_fund(
            account_id, start["fund_id"], sign_rentahuman_payment(key, start), passport_token=passport_token
        )

    async def get(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The customer's RentAHuman connection. It shows no key."""
        return cast(
            "dict[str, Any]",
            await self._client.request("GET", _base(account_id), extra_headers=_passport(passport_token)),
        )
