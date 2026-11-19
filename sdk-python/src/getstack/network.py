"""The STACK network, the owner's side and the public checks.

An install is a self-hosted STACK you registered. It signs its own requests with a key, so it holds no
account credential: see ``getstack.network_install.InstallClient`` for what an install calls. Here you
register installs and their keys, stop a key or an install at once, publish a revocation, follow other
companies' revocations, and check countersigned passports.

Every change is an owner or admin decision, never an agent's. Registering a key lets an install have
passports countersigned in your name, so it takes a person in a browser: outside a dashboard session
``request_key_challenge`` raises ``GovernanceApprovalRequiredError`` first; once a person approves at its
link, send the same call again with ``governance_approval_id``. Revoking never needs approval. None of it
is metered.

Example::

    install = stack.network.installs.register("office")
    key = InstallKey.generate()
    stack.network.installs.register_key(install["id"], key)   # a person approves the key in a browser
    verdict = stack.network.verify(countersignature, passport)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient
from .network_keys import InstallKey
from .verify_network import verify_revocation_list

REVOCATION_KINDS = ("passport", "agent", "key", "install")
REVOCATION_REASONS = (
    "unspecified",
    "key_compromise",
    "agent_decommissioned",
    "superseded",
    "policy_violation",
    "owner_request",
)


def _approval(governance_approval_id: str | None) -> dict[str, str] | None:
    return {"X-Governance-Approval": governance_approval_id} if governance_approval_id is not None else None


def _seg(value: str) -> str:
    return quote(value, safe="")


def _reason_body(reason: str | None) -> dict[str, str]:
    if reason is None:
        return {}
    if reason not in REVOCATION_REASONS:
        raise ValueError(f"reason must be one of {', '.join(REVOCATION_REASONS)}")
    return {"reason": reason}


def _add_key_body(public_jwk: dict[str, Any], proof: str, rollover_seconds: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {"public_jwk": public_jwk, "proof": proof}
    if rollover_seconds is not None:
        body["rollover_seconds"] = rollover_seconds
    return body


def _revocation_body(kind: str, subject: str, install: str, reason: str | None) -> dict[str, Any]:
    if kind not in REVOCATION_KINDS:
        raise ValueError(f"kind must be one of {', '.join(REVOCATION_KINDS)}")
    return {"kind": kind, "subject": subject, "install": install, **_reason_body(reason)}


def _subscription_body(url: str, installs: list[str] | None) -> dict[str, Any]:
    body: dict[str, Any] = {"url": url}
    if installs is not None:
        body["installs"] = list(installs)
    return body


def _verify_body(countersignature: str, passport: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {"countersignature": countersignature}
    if passport is not None:
        body["passport"] = passport
    return body


def _verified_params(passport_digest: str | None, install: str | None, agent: str | None) -> dict[str, Any]:
    if passport_digest is not None and install is None and agent is None:
        return {"passport_digest": passport_digest}
    if passport_digest is None and install is not None and agent is not None:
        return {"install": install, "agent": agent}
    raise ValueError("give either passport_digest, or install and agent together")


def _revocation_params(after: int | None, limit: int | None, install: str | None) -> dict[str, Any] | None:
    params: dict[str, Any] = {}
    if after is not None:
        params["after"] = after
    if limit is not None:
        params["limit"] = limit
    if install is not None:
        params["install"] = install
    return params or None


class NetworkInstallsService:
    """Your installs and their keys."""

    def __init__(self, client: HttpClient):
        self._client = client

    def register(self, name: str) -> dict[str, Any]:
        """Register an install. It can sign nothing until it has a key."""
        return cast("dict[str, Any]", self._client.request("POST", "/v1/network/installs", json={"name": name}))

    def list(self) -> list[dict[str, Any]]:
        """Your installs with their keys (each key: ``id``, ``kid``, ``status``, ``usable``, ``valid_until``...)."""
        result = self._client.request("GET", "/v1/network/installs")
        return cast("list[dict[str, Any]]", result["installs"])

    def get(self, install_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.request("GET", f"/v1/network/installs/{_seg(install_id)}"))

    def request_key_challenge(self, install_id: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Ask for the challenge the install signs with the key it is registering. A governance action.

        The challenge (``nonce``) is single use and good for five minutes.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/network/installs/{_seg(install_id)}/key-challenges",
                json={},
                extra_headers=_approval(governance_approval_id),
            ),
        )

    def add_key(
        self, install_id: str, public_jwk: dict[str, Any], proof: str, rollover_seconds: int | None = None
    ) -> dict[str, Any]:
        """Register a key from its challenge answer (``InstallKey.sign_key_proof``).

        The install's other keys keep working for ``rollover_seconds`` (a day when omitted, at most a week, 0
        for none), then stop; at most three keys are live at once.
        """
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/network/installs/{_seg(install_id)}/keys",
                json=_add_key_body(public_jwk, proof, rollover_seconds),
            ),
        )

    def register_key(
        self,
        install_id: str,
        key: InstallKey,
        *,
        rollover_seconds: int | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Register a key end to end: a challenge (the governance step), the key's answer to it, then the key."""
        challenge = self.request_key_challenge(install_id, governance_approval_id=governance_approval_id)
        return self.add_key(
            install_id, key.public_jwk, key.sign_key_proof(install_id, challenge["nonce"]), rollover_seconds
        )

    def revoke_key(self, install_id: str, key_id: str, reason: str | None = None) -> dict[str, Any]:
        """Stop one key at once and publish it. Every countersignature made under it stops being live."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/network/installs/{_seg(install_id)}/keys/{_seg(key_id)}/revoke",
                json=_reason_body(reason),
            ),
        )

    def revoke(self, install_id: str, reason: str | None = None) -> dict[str, Any]:
        """Stop an install and all its keys at once and publish it."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"/v1/network/installs/{_seg(install_id)}/revoke", json=_reason_body(reason)),
        )


class NetworkSubscriptionsService:
    """Counterparty subscriptions: where STACK posts each new revocation."""

    def __init__(self, client: HttpClient):
        self._client = client

    def create(self, url: str, installs: list[str] | None = None) -> dict[str, Any]:
        """STACK posts ``{"type": "stack.network.revocations", "list": "<signed list>"}`` to ``url`` (https), in
        order and at least once. Check the list with ``verify_revocation_list``. The request is signed as a
        Standard Webhooks message with the ``signing_secret`` this call returns once: check it with
        ``verify_webhook``, which refuses a forged or stale request. An OAuth sign-in gets
        ``signing_secret: None`` and a note."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", "/v1/network/subscriptions", json=_subscription_body(url, installs)),
        )

    def list(self) -> list[dict[str, Any]]:
        result = self._client.request("GET", "/v1/network/subscriptions")
        return cast("list[dict[str, Any]]", result["subscriptions"])

    def delete(self, subscription_id: str) -> None:
        self._client.request("DELETE", f"/v1/network/subscriptions/{_seg(subscription_id)}")

    def rotate_secret(self, subscription_id: str) -> dict[str, Any]:
        """A fresh signing secret, returned once, for an API key or a dashboard session. The one it
        replaces keeps signing beside it for 24 hours (``previous_valid_until``)."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"/v1/network/subscriptions/{_seg(subscription_id)}/rotate-secret", json={}),
        )

    def resume(self, subscription_id: str) -> dict[str, Any]:
        """Put a paused or failing subscription back to work; it is sent what it missed."""
        return cast(
            "dict[str, Any]",
            self._client.request("POST", f"/v1/network/subscriptions/{_seg(subscription_id)}/resume", json={}),
        )


class NetworkLicencesService:
    """The licence keys STACK issued to your account. The network takes a key as your account's credential
    for live detection rules and the hosted classifier, so one that leaks costs you money until it expires:
    revoke it here."""

    def __init__(self, client: HttpClient):
        self._client = client

    def revoke(self, licence_key: str, reason: str | None = None) -> dict[str, Any]:
        """Revoke a licence key before it expires. The key is the proof it is yours (its claims, signed by
        STACK, name your account and carry its id), and from the next call the network refuses it on every
        machine. Revoking a key again returns the first revocation. An owner or admin decision, never an
        agent's; never needs approval and is never charged."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST", "/v1/network/licences/revoke", json={"licence_key": licence_key, **_reason_body(reason)}
            ),
        )

    def list(self) -> list[dict[str, Any]]:
        """The keys your account revoked, newest first."""
        result = self._client.request("GET", "/v1/network/licences/revoked")
        return cast("list[dict[str, Any]]", result["revoked"])


class NetworkService:
    def __init__(self, client: HttpClient):
        self._client = client
        self.installs = NetworkInstallsService(client)
        self.subscriptions = NetworkSubscriptionsService(client)
        self.licences = NetworkLicencesService(client)

    def publish_revocation(self, kind: str, subject: str, install: str, reason: str | None = None) -> dict[str, Any]:
        """Publish a revocation of something that is yours. ``kind`` is passport (subject: its digest), agent,
        key (subject: its thumbprint) or install (subject: its id). Every revocation names the ``install`` it
        belongs to, and the subject must belong to it (an install is itself, a key one of its keys, a passport one
        STACK countersigned for it, an agent whose name STACK countersigned for it; anything else is not found).
        Never metered."""
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST", "/v1/network/revocations", json=_revocation_body(kind, subject, install, reason)
            ),
        )

    def jwks(self) -> dict[str, Any]:
        """STACK's public keys, current and retired, for checking every signed object of the network."""
        return cast("dict[str, Any]", self._client.public_request("GET", "/v1/network/jwks.json"))

    def signed_revocations(
        self, after: int | None = None, limit: int | None = None, install: str | None = None
    ) -> dict[str, Any]:
        """The signed list of revocations after a cursor, as served: ``{"list": "<compact JWS>"}``."""
        return cast(
            "dict[str, Any]",
            self._client.public_request(
                "GET", "/v1/network/revocations", params=_revocation_params(after, limit, install)
            ),
        )

    def revocations(
        self,
        after: int | None = None,
        limit: int | None = None,
        install: str | None = None,
        *,
        jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """The revocations after a cursor, with the list's signature checked against STACK's published keys (or
        the ``jwks`` you pin). Resume from ``resume_from``."""
        served = self.signed_revocations(after, limit, install)
        return verify_revocation_list(served["list"], jwks=jwks if jwks is not None else self.jwks(), now=now)

    def verify(self, countersignature: str, passport: str | None = None) -> dict[str, Any]:
        """Check a countersignature now, revocation included, and with ``passport`` that it is the passport the
        countersignature covers and the install signed it. No credential is sent."""
        return cast(
            "dict[str, Any]",
            self._client.public_request("POST", "/v1/network/verify", json=_verify_body(countersignature, passport)),
        )

    def verified(
        self, passport_digest: str | None = None, *, install: str | None = None, agent: str | None = None
    ) -> dict[str, Any]:
        """The signed "STACK-verified" statement for a passport (by digest) or an install's agent: a five-minute
        snapshot, ``{"status", "statement"}``. Raises ``NotFoundError`` when STACK never countersigned it.
        Check the statement with ``verify_verified_statement``."""
        return cast(
            "dict[str, Any]",
            self._client.public_request(
                "GET", "/v1/network/verified", params=_verified_params(passport_digest, install, agent)
            ),
        )
