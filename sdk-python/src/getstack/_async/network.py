"""Async NetworkService mirror: the owner's side of the STACK network and the public checks."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from ..client import AsyncHttpClient
from ..network import (
    _add_key_body,
    _approval,
    _reason_body,
    _revocation_body,
    _revocation_params,
    _seg,
    _subscription_body,
    _verified_params,
    _verify_body,
)
from ..network_keys import InstallKey
from ..verify_network import verify_revocation_list


class AsyncNetworkInstallsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def register(self, name: str) -> dict[str, Any]:
        """Register an install. It can sign nothing until it has a key."""
        return cast("dict[str, Any]", await self._client.request("POST", "/v1/network/installs", json={"name": name}))

    async def list(self) -> list[dict[str, Any]]:
        result = await self._client.request("GET", "/v1/network/installs")
        return cast("list[dict[str, Any]]", result["installs"])

    async def get(self, install_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", f"/v1/network/installs/{_seg(install_id)}"))

    async def request_key_challenge(
        self, install_id: str, *, governance_approval_id: str | None = None
    ) -> dict[str, Any]:
        """Ask for the challenge the install signs with the key it is registering. A governance action."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/network/installs/{_seg(install_id)}/key-challenges",
                json={},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    async def add_key(
        self, install_id: str, public_jwk: dict[str, Any], proof: str, rollover_seconds: int | None = None
    ) -> dict[str, Any]:
        """Register a key from its challenge answer (``InstallKey.sign_key_proof``)."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/network/installs/{_seg(install_id)}/keys",
                json=_add_key_body(public_jwk, proof, rollover_seconds),
            ),
        )

    async def register_key(
        self,
        install_id: str,
        key: InstallKey,
        *,
        rollover_seconds: int | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Register a key end to end: a challenge (the governance step), the key's answer to it, then the key."""
        challenge = await self.request_key_challenge(install_id, governance_approval_id=governance_approval_id)
        return await self.add_key(
            install_id, key.public_jwk, key.sign_key_proof(install_id, challenge["nonce"]), rollover_seconds
        )

    async def revoke_key(self, install_id: str, key_id: str, reason: str | None = None) -> dict[str, Any]:
        """Stop one key at once and publish it."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST",
                f"/v1/network/installs/{_seg(install_id)}/keys/{_seg(key_id)}/revoke",
                json=_reason_body(reason),
            ),
        )

    async def revoke(self, install_id: str, reason: str | None = None) -> dict[str, Any]:
        """Stop an install and all its keys at once and publish it."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"/v1/network/installs/{_seg(install_id)}/revoke", json=_reason_body(reason)
            ),
        )


class AsyncNetworkSubscriptionsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create(self, url: str, installs: list[str] | None = None) -> dict[str, Any]:
        """Where STACK posts each new revocation, as a list signed by STACK; the request is signed with the
        ``signing_secret`` returned once (``verify_webhook``)."""
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", "/v1/network/subscriptions", json=_subscription_body(url, installs)),
        )

    async def list(self) -> list[dict[str, Any]]:
        result = await self._client.request("GET", "/v1/network/subscriptions")
        return cast("list[dict[str, Any]]", result["subscriptions"])

    async def delete(self, subscription_id: str) -> None:
        await self._client.request("DELETE", f"/v1/network/subscriptions/{_seg(subscription_id)}")

    async def rotate_secret(self, subscription_id: str) -> dict[str, Any]:
        """A fresh signing secret, returned once; the one it replaces keeps signing for 24 hours."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", f"/v1/network/subscriptions/{_seg(subscription_id)}/rotate-secret", json={}
            ),
        )

    async def resume(self, subscription_id: str) -> dict[str, Any]:
        """Put a paused or failing subscription back to work; it is sent what it missed."""
        return cast(
            "dict[str, Any]",
            await self._client.request("POST", f"/v1/network/subscriptions/{_seg(subscription_id)}/resume", json={}),
        )


class AsyncNetworkLicencesService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def revoke(self, licence_key: str, reason: str | None = None) -> dict[str, Any]:
        """Revoke a licence key before it expires; from the next call the network refuses it everywhere."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", "/v1/network/licences/revoke", json={"licence_key": licence_key, **_reason_body(reason)}
            ),
        )

    async def list(self) -> list[dict[str, Any]]:
        """The keys your account revoked, newest first."""
        result = await self._client.request("GET", "/v1/network/licences/revoked")
        return cast("list[dict[str, Any]]", result["revoked"])


class AsyncNetworkService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client
        self.installs = AsyncNetworkInstallsService(client)
        self.subscriptions = AsyncNetworkSubscriptionsService(client)
        self.licences = AsyncNetworkLicencesService(client)

    async def publish_revocation(
        self, kind: str, subject: str, install: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Publish a revocation of something that is yours; it names the ``install`` it belongs to. Never metered."""
        return cast(
            "dict[str, Any]",
            await self._client.request(
                "POST", "/v1/network/revocations", json=_revocation_body(kind, subject, install, reason)
            ),
        )

    async def jwks(self) -> dict[str, Any]:
        """STACK's public keys, current and retired."""
        return cast("dict[str, Any]", await self._client.public_request("GET", "/v1/network/jwks.json"))

    async def signed_revocations(
        self, after: int | None = None, limit: int | None = None, install: str | None = None
    ) -> dict[str, Any]:
        """The signed list of revocations after a cursor, as served: ``{"list": "<compact JWS>"}``."""
        return cast(
            "dict[str, Any]",
            await self._client.public_request(
                "GET", "/v1/network/revocations", params=_revocation_params(after, limit, install)
            ),
        )

    async def revocations(
        self,
        after: int | None = None,
        limit: int | None = None,
        install: str | None = None,
        *,
        jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """The revocations after a cursor, with the list's signature checked. Resume from ``resume_from``."""
        served = await self.signed_revocations(after, limit, install)
        return verify_revocation_list(served["list"], jwks=jwks if jwks is not None else await self.jwks(), now=now)

    async def verify(self, countersignature: str, passport: str | None = None) -> dict[str, Any]:
        """Check a countersignature now, revocation included. No credential is sent."""
        return cast(
            "dict[str, Any]",
            await self._client.public_request(
                "POST", "/v1/network/verify", json=_verify_body(countersignature, passport)
            ),
        )

    async def verified(
        self, passport_digest: str | None = None, *, install: str | None = None, agent: str | None = None
    ) -> dict[str, Any]:
        """The signed "STACK-verified" statement for a passport (by digest) or an install's agent."""
        return cast(
            "dict[str, Any]",
            await self._client.public_request(
                "GET", "/v1/network/verified", params=_verified_params(passport_digest, install, agent)
            ),
        )
