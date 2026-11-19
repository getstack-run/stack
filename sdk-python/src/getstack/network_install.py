"""What a self-hosted install calls.

An install holds no account credential: every request carries a fresh proof signed with the install's own key
as its bearer value, so a leaked key can call the network and nothing else, and revoking it ends that at once.
Each proof is good for one request.

Example::

    client = InstallClient(install_id, InstallKey.from_pem(Path("install.pem").read_text()))
    rules = client.rules()                                  # signed rule set, checked against STACK's keys
    verdict = client.classify(retrieved_content)            # the content leaves the install; STACK keeps none of it
    issued = client.countersign(passport, agent="support-bot")
"""

from __future__ import annotations

import os
from typing import Any, cast

import httpx

from .client import DEFAULT_BASE_URL
from .errors import raise_for_status
from .network_keys import InstallKey, passport_digest
from .verify_network import verify_detection_rules

CLASSIFY_CONTEXTS = ("email", "document", "webpage", "chat_log", "api_response", "calendar", "other")


def _countersign_claims(
    passport: str, agent: str | None, passport_id: str | None, ttl_seconds: int | None
) -> dict[str, Any]:
    claims: dict[str, Any] = {"act": "countersign", "pd": passport_digest(passport)}
    if passport_id is not None:
        claims["pjti"] = passport_id
    if agent is not None:
        claims["agent"] = agent
    if ttl_seconds is not None:
        claims["ttl"] = ttl_seconds
    return claims


def _classify_body(content: str | dict[str, Any], context: str | None) -> dict[str, Any]:
    if context is not None and context not in CLASSIFY_CONTEXTS:
        raise ValueError(f"context must be one of {', '.join(CLASSIFY_CONTEXTS)}")
    return {"content": content, **({"context": context} if context is not None else {})}


def _revoke_claims(kind: str, subject: str, reason: str | None) -> dict[str, Any]:
    return {"act": "revoke", "kind": kind, "subject": subject, **({"reason": reason} if reason is not None else {})}


def _raise(response: httpx.Response) -> None:
    if response.status_code >= 400:
        try:
            body = response.json()
        except Exception:
            body = {"error": {"message": response.text}}
        raise_for_status(response.status_code, body)


class InstallClient:
    """The install's side of the network, synchronous. See :class:`AsyncInstallClient` for the async one."""

    def __init__(
        self,
        install_id: str,
        key: InstallKey,
        base_url: str | None = None,
        jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
        timeout: float = 30.0,
    ):
        self.install_id = install_id
        self._key = key
        self._base_url = (base_url or os.environ.get("STACK_API_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._jwks = jwks
        self._http = httpx.Client(timeout=timeout)

    def _keys(self) -> dict[str, Any] | list[dict[str, Any]]:
        if self._jwks is None:
            response = self._http.get(f"{self._base_url}/v1/network/jwks.json")
            _raise(response)
            self._jwks = cast("dict[str, Any]", response.json())
        return self._jwks

    def _call(self, method: str, path: str, claims: dict[str, Any], body: Any) -> Any:
        proof = self._key.sign_proof(self.install_id, claims)
        response = self._http.request(
            method,
            f"{self._base_url}{path}",
            json=body,
            headers={"Authorization": f"Bearer {proof}", "Accept": "application/json"},
        )
        _raise(response)
        return response.json()

    def rules(self, held_revision: int | None = None) -> dict[str, Any]:
        """The current detection rule set, checked against STACK's keys. Pass the highest ``revision`` you
        already run as ``held_revision``: a lower one is refused, and so is an expired set. Metered as one action.
        Returns ``verify_detection_rules``'s result plus the signed ``statement``."""
        response = self._call("POST", "/v1/network/detection/rules", {"act": "rules"}, {})
        rules = verify_detection_rules(response["statement"], held_revision=held_revision, jwks=self._keys())
        return {**rules, "statement": response["statement"]}

    def classify(self, content: str | dict[str, Any], context: str | None = None) -> dict[str, Any]:
        """Send content to STACK's classifier and get a verdict. The content leaves the install: at most its
        first 2,500 and last 1,500 characters reach the model, and STACK keeps none of it. Metered as one
        action, plus the model call at cost."""
        return cast(
            "dict[str, Any]",
            self._call("POST", "/v1/network/detection/classify", {"act": "classify"}, _classify_body(content, context)),
        )

    def grade_intent_deviation(self, declared: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
        """Have STACK grade a checkout for intent deviation: ``declared`` (``summary``, ``services``) against
        ``observed`` (``services_used``, ``tool_calls``, ``actions_count``, ``summary``). They leave the install
        with no identifier and STACK keeps none of it. Metered as one action, plus the model call at cost."""
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                "/v1/network/detection/intent-deviation",
                {"act": "classify"},
                {"declared": declared, "observed": observed},
            ),
        )

    def countersign(
        self,
        passport: str,
        agent: str | None = None,
        passport_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Have STACK countersign a passport this install issued. Only the passport's digest is sent. The
        install's key must be the one that signed the passport. Ask again when you refresh the passport."""
        claims = _countersign_claims(passport, agent, passport_id, ttl_seconds)
        return cast("dict[str, Any]", self._call("POST", "/v1/network/countersignatures", claims, {}))

    def publish_revocation(self, kind: str, subject: str, reason: str | None = None) -> dict[str, Any]:
        """Publish a revocation of one of this install's passports (subject: its digest), agents, its key
        (subject: its thumbprint) or the install. Public: the subject and reason appear on the list counterparties
        read. Never metered."""
        return cast(
            "dict[str, Any]", self._call("POST", "/v1/network/revocations", _revoke_claims(kind, subject, reason), {})
        )

    def close(self) -> None:
        self._http.close()


class AsyncInstallClient:
    """The install's side of the network, asynchronous."""

    def __init__(
        self,
        install_id: str,
        key: InstallKey,
        base_url: str | None = None,
        jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
        timeout: float = 30.0,
    ):
        self.install_id = install_id
        self._key = key
        self._base_url = (base_url or os.environ.get("STACK_API_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._jwks = jwks
        self._http = httpx.AsyncClient(timeout=timeout)

    async def _keys(self) -> dict[str, Any] | list[dict[str, Any]]:
        if self._jwks is None:
            response = await self._http.get(f"{self._base_url}/v1/network/jwks.json")
            _raise(response)
            self._jwks = cast("dict[str, Any]", response.json())
        return self._jwks

    async def _call(self, method: str, path: str, claims: dict[str, Any], body: Any) -> Any:
        proof = self._key.sign_proof(self.install_id, claims)
        response = await self._http.request(
            method,
            f"{self._base_url}{path}",
            json=body,
            headers={"Authorization": f"Bearer {proof}", "Accept": "application/json"},
        )
        _raise(response)
        return response.json()

    async def rules(self, held_revision: int | None = None) -> dict[str, Any]:
        """The current detection rule set, checked against STACK's keys. See :meth:`InstallClient.rules`."""
        response = await self._call("POST", "/v1/network/detection/rules", {"act": "rules"}, {})
        rules = verify_detection_rules(response["statement"], held_revision=held_revision, jwks=await self._keys())
        return {**rules, "statement": response["statement"]}

    async def classify(self, content: str | dict[str, Any], context: str | None = None) -> dict[str, Any]:
        """Send content to STACK's classifier and get a verdict. See :meth:`InstallClient.classify`."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST", "/v1/network/detection/classify", {"act": "classify"}, _classify_body(content, context)
            ),
        )

    async def grade_intent_deviation(self, declared: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
        """Have STACK grade a checkout for intent deviation. See :meth:`InstallClient.grade_intent_deviation`."""
        return cast(
            "dict[str, Any]",
            await self._call(
                "POST",
                "/v1/network/detection/intent-deviation",
                {"act": "classify"},
                {"declared": declared, "observed": observed},
            ),
        )

    async def countersign(
        self,
        passport: str,
        agent: str | None = None,
        passport_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Have STACK countersign a passport this install issued. Only the passport's digest is sent."""
        claims = _countersign_claims(passport, agent, passport_id, ttl_seconds)
        return cast("dict[str, Any]", await self._call("POST", "/v1/network/countersignatures", claims, {}))

    async def publish_revocation(self, kind: str, subject: str, reason: str | None = None) -> dict[str, Any]:
        """Publish a revocation of one of this install's passports, agents, its key or the install. Never metered."""
        return cast(
            "dict[str, Any]",
            await self._call("POST", "/v1/network/revocations", _revoke_claims(kind, subject, reason), {}),
        )

    async def aclose(self) -> None:
        await self._http.aclose()
