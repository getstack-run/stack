"""Partner-managed accounts: the partner surface.

Platform partners (is_partner=True on their operator row) run STACK under
their own product: each customer gets an isolated account that the partner
opens by its own reference, pays for and manages through the API, with no
consent screen and no action from the customer. The account holds the
partner's reference for the customer, not the customer's address. The
customer can be invited to see it (read-only), and when the relationship
ends the partner releases the account: the customer claims it through a
mailed link and the platform checkout, and it moves to them with
everything in it.

Every account has its own plan, free amounts and usage like any customer's,
and the partner's wallet pays for it. The partner does not choose an account's
plan. Hosted controls are the account's own switch (`set_controls`).

Error codes worth handling (``StackError.code``):

- TENANT_TIER_NOT_ALLOWED (400): ``tier`` was sent on create.
- TENANT_LIMIT_REACHED (409): the partner's deal caps the number of accounts.
- RELEASE_EMAIL_REQUIRED (400): a release with no invited customer and no ``email``.
- RELEASE_NOT_AVAILABLE (409): the account cannot be released now, or a
  release the customer asked for cannot be withdrawn.
- RELEASE_CMEK_ACTIVE (409): the account's data is under a customer-managed key;
  turn the key off first.
- RATE_LIMITED (429): too many releases and invitations this hour.
- ALLOWANCE_EXHAUSTED (402): a negotiated hard cap was reached.
- INSUFFICIENT_BALANCE (402): your wallet cannot cover the first month of a new
  account or of its controls; nothing changed.
- SPEND_FROZEN (402): your spending is frozen.
- TENANT_BILLED_BY_PARTNER (403): an account key called a billing mutation.
- BILLING_ACCOUNT_INACTIVE (403): the account's partner is suspended or removed.
"""

from __future__ import annotations

import builtins
from typing import Any, Literal, cast
from urllib.parse import quote

from .client import HttpClient
from .passports import _require_one_mission


def _account(account_id: str) -> str:
    return f"/v1/partner/accounts/{quote(account_id, safe='')}"


class PartnerAccountsService:
    def __init__(self, client: HttpClient):
        self._client = client

    def create(self, external_ref: str, *, controls: bool = False) -> dict[str, Any]:
        """Open an account for a customer under your own reference.

        Idempotent on ``external_ref`` (1 to 256 characters, unique per
        partner): a repeat returns the account that exists with
        ``created`` False and no key. Returns account_id, external_ref,
        billing ('partner'), status, created, created_at and, only on the
        call that created the account, api_key (shown once, store it).

        ``controls=True`` switches the account's hosted controls on as it
        opens: their first month is taken from your wallet with the plan's,
        and a wallet that cannot pay both refuses the open. Off by default.
        """
        body: dict[str, Any] = {"external_ref": external_ref}
        if controls:
            body["controls"] = True
        return cast("dict[str, Any]", self._client.post("/v1/partner/accounts", json=body))

    def list(self, external_ref: str | None = None) -> list[dict[str, Any]]:
        """List your accounts, or the one under ``external_ref``. Each carries
        ``invite`` ({status}: none, invited or active) and ``usage``
        ({period, actions}), its own month-to-date actions, and plan (what you
        pay for it a month and where it stands)."""
        path = "/v1/partner/accounts"
        if external_ref is not None:
            path += f"?external_ref={quote(external_ref, safe='')}"
        res = self._client.get(path)
        return list(res.get("accounts", []))

    def get(self, account_id: str) -> dict[str, Any]:
        """Fetch one account (same shape as a ``list`` entry)."""
        return cast("dict[str, Any]", self._client.get(_account(account_id)))

    def set_controls(self, account_id: str, enabled: bool) -> dict[str, Any]:
        """Switch hosted controls on or off for one account. On, its first
        month is taken from your wallet at once (402 INSUFFICIENT_BALANCE when
        it cannot be, and nothing changes); off, the charge ends. Returns
        {account_id, plan}."""
        return cast("dict[str, Any]", self._client.put(f"{_account(account_id)}/controls", json={"enabled": enabled}))

    def revoke(self, account_id: str) -> dict[str, Any]:
        """Close an account. Cascades to its inbound webhooks and passports.

        Returns {transitioned, webhooks_revoked, passports_revoked}.
        Idempotent: a retry finishes a cascade that failed part-way.
        """
        return cast("dict[str, Any]", self._client.delete(_account(account_id)))

    def rotate_key(self, account_id: str) -> dict[str, Any]:
        """A new API key for an account, returned once; the one it replaces
        stops working at once."""
        return cast("dict[str, Any]", self._client.post(f"{_account(account_id)}/rotate-key", json={}))

    def invite(self, account_id: str, email: str, name: str | None = None) -> dict[str, Any]:
        """Invite the customer to see the account, read-only. The invitation
        is mailed to ``email``, which is the customer's only when they accept."""
        body: dict[str, Any] = {"email": email}
        if name is not None:
            body["name"] = name
        return cast("dict[str, Any]", self._client.post(f"{_account(account_id)}/invite", json=body))

    def release(self, account_id: str, email: str | None = None) -> dict[str, Any]:
        """Release the account to its customer: they are mailed a claim link,
        and when they complete the checkout and the sanctions check clears,
        the account is theirs and your access ends. Without ``email`` the
        link goes to the one customer invited to the account. Repeating the
        call inside ten minutes returns the pending release without mailing
        again. Returns the release record."""
        body: dict[str, Any] = {}
        if email is not None:
            body["email"] = email
        res = self._client.post(f"{_account(account_id)}/release", json=body)
        return cast("dict[str, Any]", res["release"])

    def cancel_release(self, account_id: str) -> dict[str, Any]:
        """Withdraw a release you started and the customer has not claimed."""
        return cast("dict[str, Any]", self._client.delete(f"{_account(account_id)}/release"))

    def get_release(self, account_id: str) -> dict[str, Any]:
        """Where the release of one account stands, also after the customer
        claimed it and it is no longer yours. ``status`` is pending, completed,
        returned (the claim did not complete; the account is still yours and
        the reason is never given) or cancelled."""
        res = self._client.get(f"{_account(account_id)}/release")
        return cast("dict[str, Any]", res["release"])

    def list_releases(self) -> builtins.list[dict[str, Any]]:
        """Every release you have a record of."""
        res = self._client.get("/v1/partner/releases")
        return list(res.get("releases", []))

    def create_inbound_webhook(
        self,
        account_id: str,
        provider: Literal["agentmail", "generic"],
        agent_id: str,
        forward_url: str | None = None,
        generic_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"provider": provider, "agent_id": agent_id}
        if forward_url is not None:
            body["forward_url"] = forward_url
        if generic_config is not None:
            body["generic_config"] = generic_config
        return cast(
            "dict[str, Any]",
            self._client.post(f"{_account(account_id)}/inbound-webhooks", json=body),
        )

    def rotate_inbound_webhook_secret(self, account_id: str, webhook_id: str) -> dict[str, Any]:
        """A fresh downstream signing secret for an account's inbound webhook, returned once.

        The secret it replaces keeps signing beside it for 24 hours.
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"{_account(account_id)}/inbound-webhooks/{quote(webhook_id, safe='')}/rotate-secret",
                json={},
            ),
        )

    def set_inbound_webhook_signing_secret(
        self,
        account_id: str,
        webhook_id: str,
        signing_secret: str,
        downstream_signing_secret: str | None = None,
    ) -> dict[str, Any]:
        """Configure signing with direct partner admin authentication; returns status only."""
        body = {"signing_secret": signing_secret}
        if downstream_signing_secret is not None:
            body["downstream_signing_secret"] = downstream_signing_secret
        return cast(
            "dict[str, Any]",
            self._client.put(
                f"{_account(account_id)}/inbound-webhooks/{quote(webhook_id, safe='')}/provider-signing-secret",
                json=body,
            ),
        )

    def issue_passport(
        self,
        account_id: str,
        agent_id: str,
        ttl_seconds: int | None = None,
        services: builtins.list[dict[str, Any]] | None = None,
        named_intents: builtins.list[str] | None = None,
        accountability_mode: Literal["enforced", "logged", "standard"] | None = None,
        mission_ids: builtins.list[str] | None = None,
    ) -> dict[str, Any]:
        """Issue a passport under the account. ``mission_ids`` must hold exactly
        one Mission id the account's agent may use; anything else raises
        ``ValueError`` before any request."""
        body: dict[str, Any] = {"agent_id": agent_id, "mission_ids": _require_one_mission(mission_ids)}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if services is not None:
            body["services"] = services
        if named_intents is not None:
            body["named_intents"] = named_intents
        if accountability_mode is not None:
            body["accountability_mode"] = accountability_mode
        return cast(
            "dict[str, Any]",
            self._client.post(f"{_account(account_id)}/passports/issue", json=body),
        )

    def mint_outbound_passport(
        self,
        account_id: str,
        agent_id: str,
        scopes: builtins.list[str] | None = None,
        ttl_seconds: int = 900,
        accountability_mode: Literal["enforced", "logged", "standard"] = "enforced",
        named_intents: builtins.list[str] | None = None,
        *,
        mission_id: str,
    ) -> dict[str, Any]:
        """convenience helper for the MIME-stamping pattern.

        Mints a passport under the account (signed with the deployment's
        key like every passport; ``stk.operator_id`` names the account)
        with a default-narrow scope, returning the token along with
        the value ready for direct header injection (`X-Stack-Passport:
        <token>`). The receiver verifies offline via verify_passport_header.

        Defaults: 15-minute TTL, accountability_mode='enforced'.
        ``mission_id`` is required: the passport is issued for that one
        Mission and never outlives it.

        Returns dict with keys: token, passport_id, expires_at, header_value.
        """
        services = [{"scopes": scopes}] if scopes else None
        issued = self.issue_passport(
            account_id,
            agent_id,
            ttl_seconds=ttl_seconds,
            accountability_mode=accountability_mode,
            services=services,
            named_intents=named_intents,
            mission_ids=[mission_id],
        )
        token = issued.get("token") or issued.get("passport")
        passport_id = issued.get("passport_id") or issued.get("jti")
        if not token or not passport_id:
            raise RuntimeError("mint_outbound_passport: API response missing token or passport_id")
        expires_at = issued.get("expires_at")
        if not expires_at:
            exp = issued.get("exp")
            if isinstance(exp, (int, float)):
                from datetime import datetime, timezone

                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        return {
            "token": token,
            "passport_id": passport_id,
            "expires_at": expires_at,
            "header_value": token,
        }
