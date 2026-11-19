"""Identity verification — providers, claims, and verification flow."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient
from .types import (
    IdentityClaim,
    IdentityProvider,
    IdentitySettings,
    ReplaceServiceRequirementResult,
    ServiceRequirement,
    SetServiceRequirementInput,
    VerificationSession,
)


def _to_provider(data: dict[str, Any]) -> IdentityProvider:
    return IdentityProvider(
        key=data["key"],
        name=data["name"],
        layers=data.get("layers", []),
        assurance=data.get("assurance", ""),
        description=data.get("description", ""),
    )


def _to_claim(data: dict[str, Any]) -> IdentityClaim:
    return IdentityClaim(
        id=data["id"],
        operator_id=data["operator_id"],
        provider_key=data["provider_key"],
        layer=data["layer"],
        claim_type=data["claim_type"],
        claim_ref=data["claim_ref"],
        assurance_level=data["assurance_level"],
        verified_at=data["verified_at"],
        expires_at=data.get("expires_at"),
    )


class IdentityService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get_settings(self) -> IdentitySettings:
        data = self._client.get("/v1/operators/me/identity-settings")
        return IdentitySettings(
            identity_claim_ttl=data["identity_claim_ttl"],
            identity_claim_inheritance=data["identity_claim_inheritance"],
            identity_auto_revoke=data["identity_auto_revoke"],
        )

    def update_settings(
        self,
        *,
        identity_claim_ttl: str | None = None,
        identity_claim_inheritance: str | None = None,
        identity_auto_revoke: bool | None = None,
        governance_approval_id: str | None = None,
    ) -> IdentitySettings:
        body: dict[str, Any] = {}
        if identity_claim_ttl is not None:
            body["identity_claim_ttl"] = identity_claim_ttl
        if identity_claim_inheritance is not None:
            body["identity_claim_inheritance"] = identity_claim_inheritance
        if identity_auto_revoke is not None:
            body["identity_auto_revoke"] = identity_auto_revoke
        data = self._client.patch(
            "/v1/operators/me/identity-settings",
            json=body,
            extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
        )
        return IdentitySettings(
            identity_claim_ttl=data["identity_claim_ttl"],
            identity_claim_inheritance=data["identity_claim_inheritance"],
            identity_auto_revoke=data["identity_auto_revoke"],
        )

    def list_providers(self) -> list[IdentityProvider]:
        data = self._client.get("/v1/identity/providers")
        return [_to_provider(p) for p in data]

    def initiate_verification(
        self,
        provider_key: str,
        *,
        requested_claims: list[str] | None = None,
        return_url: str | None = None,
    ) -> VerificationSession:
        body: dict[str, Any] = {"provider_key": provider_key}
        if requested_claims:
            body["requested_claims"] = requested_claims
        if return_url:
            body["return_url"] = return_url
        data = self._client.post("/v1/identity/verify/initiate", json=body)
        return VerificationSession(
            session_ref=data["session_ref"],
            authorization_url=data.get("authorization_url"),
            status=data.get("status", "pending"),
        )

    def get_verification_session(self, session_id: str) -> dict[str, Any]:
        """One verification session by the ``session_id`` that ``initiate_verification`` returned.

        ``status`` is ``pending`` while the person is at the provider, then ``completed`` or ``failed``; a session
        nobody finished by ``expires_at`` is ``expired``, which is final. The verified claims are read with
        ``list_claims``.
        """
        return cast(
            "dict[str, Any]",
            self._client.get(f"/v1/identity/verify/sessions/{quote(session_id, safe='')}"),
        )

    def complete_verification(
        self,
        provider_key: str,
        session_ref: str,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.post(
                "/v1/identity/verify/complete",
                json={"provider_key": provider_key, "session_ref": session_ref},
            ),
        )

    def grant_delegation(self, delegated_scopes: list[str]) -> IdentityClaim:
        data = self._client.post(
            "/v1/identity/delegate",
            json={"delegated_scopes": delegated_scopes},
        )
        return _to_claim(data)

    def list_claims(self) -> list[IdentityClaim]:
        data = self._client.get("/v1/identity/claims")
        return [_to_claim(c) for c in data]

    def revoke_claim(self, claim_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.delete(f"/v1/identity/claims/{claim_id}"))

    def get_service_requirements(self, service_id: str) -> list[ServiceRequirement]:
        return cast(
            "list[ServiceRequirement]", self._client.get(f"/v1/services/{quote(service_id, safe='')}/requirements")
        )

    def set_service_requirement(self, service_id: str, **kwargs: Any) -> ServiceRequirement:
        return cast(
            "ServiceRequirement",
            self._client.post(
                f"/v1/services/{quote(service_id, safe='')}/requirements",
                json=kwargs,
            ),
        )

    def replace_service_requirement(
        self,
        service_id: str,
        requirement: SetServiceRequirementInput | None,
        governance_approval_id: str | None = None,
    ) -> ReplaceServiceRequirementResult:
        return cast(
            "ReplaceServiceRequirementResult",
            self._client.put(
                f"/v1/services/{quote(service_id, safe='')}/requirements",
                json={"requirement": requirement},
                extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
            ),
        )

    def delete_service_requirement(
        self, service_id: str, requirement_id: str, governance_approval_id: str | None = None
    ) -> None:
        """Remove one requirement. From an API key or an OAuth token this raises GovernanceApprovalRequiredError until
        a person confirmed it: retry with ``governance_approval_id``."""
        self._client.delete(
            f"/v1/services/{quote(service_id, safe='')}/requirements/{quote(requirement_id, safe='')}",
            extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
        )

    # -- Single sign-on: verified e-mail domains --------------------------------
    #
    # Some identity providers (Microsoft Entra ID among them) do not say that a person's address is verified. An
    # account proves it controls an e-mail domain with a DNS TXT record; once it has, an address at exactly that domain
    # counts as verified for a first sign-in when the provider's ID token has no ``email_verified`` claim at all.
    # Owner or admin only, on any plan; an agent is refused.

    def list_sso_domains(self) -> list[dict[str, Any]]:
        """The account's single sign-on domains, each with the TXT record that proves it and where the proof stands."""
        data = cast("dict[str, Any]", self._client.get("/v1/identity/sso-domains"))
        return cast("list[dict[str, Any]]", data["domains"])

    def add_sso_domain(self, domain: str, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Claim a domain such as ``corp.example.com`` and get the TXT record to publish (``record``).

        Nothing counts until ``verify_sso_domain`` finds the record. A person approves adding one in a browser: without
        a dashboard session the first call raises ``GovernanceApprovalRequiredError``; retry with
        ``governance_approval_id``. A domain another account has verified is refused.
        """
        headers = {"X-Governance-Approval": governance_approval_id} if governance_approval_id else None
        return cast(
            "dict[str, Any]",
            self._client.post("/v1/identity/sso-domains", json={"domain": domain}, extra_headers=headers),
        )

    def verify_sso_domain(self, domain_id: str) -> dict[str, Any]:
        """Look the record up now. ``check`` is ``confirmed``, ``missing`` or ``unavailable`` (no answer)."""
        return cast(
            "dict[str, Any]",
            self._client.post(f"/v1/identity/sso-domains/{quote(domain_id, safe='')}/verify", json={}),
        )

    def remove_sso_domain(self, domain_id: str) -> None:
        """Stop claiming a domain. The next sign-in no longer counts addresses at it as verified."""
        self._client.delete(f"/v1/identity/sso-domains/{quote(domain_id, safe='')}")
