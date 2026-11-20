"""RentAHuman for a customer's agents: the agent hires people for real-world tasks through the customer's own account.

Connect the customer's own key at the Console (the service ``rentahuman``), or let the agent open an account itself
with its own wallet (``join``): STACK keeps the key in the vault and the agent and its model never see it. Call
RentAHuman through the connection with ``stack.proxy.service_tools("rentahuman")`` and
``stack.proxy.service_call_tool("rentahuman", tool, args)``: searching people, posting and funding a bounty, reading
applications, and the conversations with the people it hires (``send_message``, ``get_conversation``,
``list_conversations``). A person applying, delivering or writing wakes the agent (wake source ``service_event``):
the wake carries the service, the kind of event and its ids, never what the person wrote; the agent reads the rest
through the connection and replies the same way.

Opening an account and topping its wallet up are two steps, because only the agent can sign for its own wallet:
``join`` makes the payment RentAHuman asks for and returns what to sign; the agent signs it with its wallet key and
``complete_join`` sends the signature, which goes through the wallet's caps and the customer's decider like any
payment from the wallet. ``join_with_key`` and ``fund_with_key`` do both steps.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient
from .wallet_key import AgentWalletKey, WalletPaymentTarget, wallet_payment_authorization_payload


def _seg(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("an id is required")
    return quote(value, safe="")


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _as_agent(passport_token: str | None) -> dict[str, str] | None:
    """The two calls that pay from the wallet are made as the agent: the Passport is the bearer credential as well as
    ``X-Passport-Token``."""
    return {"X-Passport-Token": passport_token, "Authorization": f"Bearer {passport_token}"} if passport_token else None


def _base(account_id: str) -> str:
    return f"/v1/accounts/{_seg(account_id)}/rentahuman"


def _join_body(country: str, city: str | None, agent_name: str | None, accept_terms: bool) -> dict[str, Any]:
    if accept_terms is not True:
        raise ValueError("accept_terms must be True: it is the customer accepting RentAHuman's terms through its agent")
    body: dict[str, Any] = {"country": country, "accept_terms": True}
    if city is not None:
        body["city"] = city
    if agent_name is not None:
        body["agent_name"] = agent_name
    return body


def sign_rentahuman_payment(key: AgentWalletKey, start: dict[str, Any]) -> str:
    """What the agent signs for a payment ``join`` or ``fund`` returned: Privy's payload for the signing request."""
    wallet = start["wallet"]
    return key.sign(
        wallet_payment_authorization_payload(
            WalletPaymentTarget(
                app_id=wallet["privy_app_id"], wallet_id=wallet["wallet_id"], typed_data=start["typed_data"]
            )
        )
    )


class RentAHumanService:
    def __init__(self, client: HttpClient):
        self._client = client

    def join(
        self,
        account_id: str,
        *,
        country: str,
        accept_terms: bool,
        city: str | None = None,
        agent_name: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Step one of opening a RentAHuman account for the customer, paid from the agent's wallet.

        Asks RentAHuman what it costs and returns the payment to sign (``join_id``, ``amount_cents``, ``pay_to``,
        ``typed_data``, ``wallet``, ``expires_at``). Takes nothing. One metered action. ``accept_terms=True`` is the
        customer accepting RentAHuman's terms through its agent.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/join",
                json=_join_body(country, city, agent_name, accept_terms),
                extra_headers=_passport(passport_token),
            ),
        )

    def complete_join(
        self, account_id: str, join_id: str, signed: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Step two: ``signed`` is the agent's signature. Only the account's own agent, under its Passport.

        The payment goes through the wallet's caps, the account's budget and the customer's decider; RentAHuman's
        key goes into the vault and is never returned. Called again with the same ``join_id`` it answers the same
        and, when the account's events were not registered, tries again.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/join/complete",
                json={"join_id": join_id, "signed": signed},
                extra_headers=_as_agent(passport_token),
            ),
        )

    def join_with_key(
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
        start = self.join(
            account_id,
            country=country,
            accept_terms=accept_terms,
            city=city,
            agent_name=agent_name,
            passport_token=passport_token,
        )
        return self.complete_join(
            account_id, start["join_id"], sign_rentahuman_payment(key, start), passport_token=passport_token
        )

    def fund(self, account_id: str, amount_cents: int, *, passport_token: str | None = None) -> dict[str, Any]:
        """Step one of topping up the customer's RentAHuman wallet from the agent's wallet (100 to 1,000,000 cents)."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/fund",
                json={"amount_cents": amount_cents},
                extra_headers=_passport(passport_token),
            ),
        )

    def complete_fund(
        self, account_id: str, fund_id: str, signed: str, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Step two of a top-up: the agent's signature of the payment ``fund`` returned."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"{_base(account_id)}/fund/complete",
                json={"fund_id": fund_id, "signed": signed},
                extra_headers=_as_agent(passport_token),
            ),
        )

    def fund_with_key(
        self, account_id: str, key: AgentWalletKey, amount_cents: int, *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Both steps of a top-up."""
        start = self.fund(account_id, amount_cents, passport_token=passport_token)
        return self.complete_fund(
            account_id, start["fund_id"], sign_rentahuman_payment(key, start), passport_token=passport_token
        )

    def get(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The customer's RentAHuman connection (``{"connection": ... | None}``). It shows no key."""
        return cast(
            "dict[str, Any]",
            self._client.request("GET", _base(account_id), extra_headers=_passport(passport_token)),
        )
