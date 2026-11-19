"""Authority principal, proof, binding, receiver, and evidence APIs."""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


def _idempotency_headers(idempotency_key: str) -> dict[str, str]:
    return {"Idempotency-Key": idempotency_key}


def _version_params(version: int | None) -> dict[str, int] | None:
    return {"version": version} if version is not None else None


class AuthorityService:
    """Operator-facing authority management and safe evidence reads.

    Write methods require an explicit idempotency key because the API rejects
    authority mutations without one. Receiver-protocol operations and human
    approval decisions use different authentication ceremonies and are not
    exposed through the operator client.
    """

    def __init__(self, client: HttpClient):
        self._client = client

    def create_enterprise_oidc_request(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        """Create a pending request and return the human approval URL.

        This does not grant authority. An eligible human must review the exact
        request and verify through the operator's configured OIDC provider.
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                "/v1/authority/enterprise-oidc/requests",
                json=input,
                extra_headers=_idempotency_headers(idempotency_key),
            ),
        )

    def get_enterprise_oidc_request(self, request_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/authority/enterprise-oidc/requests/{request_id}"))

    # Principals

    def create_principal(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            "/v1/authority/principals",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["principal"])

    def list_principals(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/authority/principals")["principals"])

    def get_principal(self, principal_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/authority/principals/{principal_id}")["principal"])

    def archive_principal(self, principal_id: str, *, reason_code: str, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/principals/{principal_id}/archive",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["principal"])

    def erase_principal(self, principal_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/principals/{principal_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["tombstone"])

    # Proofs

    def import_proof(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            "/v1/authority/proofs/import",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["proof"])

    def create_proof_collection_session(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            "/v1/authority/proof-collection-sessions",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["session"])

    def get_proof_collection_session(self, session_id: str) -> dict[str, Any]:
        data = self._client.get(f"/v1/authority/proof-collection-sessions/{session_id}")
        return cast("dict[str, Any]", data["session"])

    def list_proofs(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/authority/proofs")["proofs"])

    def get_proof(self, proof_id: str, *, version: int | None = None) -> dict[str, Any]:
        data = self._client.get(f"/v1/authority/proofs/{proof_id}", params=_version_params(version))
        return cast("dict[str, Any]", data["proof"])

    def revoke_proof(self, proof_id: str, *, reason_code: str, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/proofs/{proof_id}/revoke",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["proof"])

    def erase_proof(self, proof_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/proofs/{proof_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["proof"])

    # Bindings and approval requests

    def create_binding(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            "/v1/authority/bindings",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    def list_bindings(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/authority/bindings")["bindings"])

    def get_binding(self, binding_id: str, *, version: int | None = None) -> dict[str, Any]:
        data = self._client.get(f"/v1/authority/bindings/{binding_id}", params=_version_params(version))
        return cast("dict[str, Any]", data["binding"])

    def create_approval_requests(self, binding_id: str, *, idempotency_key: str, **input: Any) -> list[dict[str, Any]]:
        data = self._client.post(
            f"/v1/authority/bindings/{binding_id}/approval-requests",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("list[dict[str, Any]]", data["approval_requests"])

    def list_approval_requests(self, binding_id: str) -> list[dict[str, Any]]:
        data = self._client.get(f"/v1/authority/bindings/{binding_id}/approval-requests")
        return cast("list[dict[str, Any]]", data["approval_requests"])

    def activate_binding(
        self,
        binding_id: str,
        *,
        idempotency_key: str,
        version: int | None = None,
    ) -> dict[str, Any]:
        data = self._client.request(
            "POST",
            f"/v1/authority/bindings/{binding_id}/activate",
            json={},
            params=_version_params(version),
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    def delegate_binding(self, binding_id: str, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/bindings/{binding_id}/delegate",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    def revoke_binding(self, binding_id: str, *, reason_code: str, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/bindings/{binding_id}/revoke",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    def erase_binding(self, binding_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/bindings/{binding_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["tombstone"])

    # Receivers and profiles

    def create_receiver(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            "/v1/authority/receivers",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["receiver"])

    def list_receivers(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/authority/receivers")["receivers"])

    def get_receiver(self, receiver_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/authority/receivers/{receiver_id}")["receiver"])

    def create_receiver_verification_challenge(self, receiver_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/receivers/{receiver_id}/verification-challenges",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["challenge"])

    def verify_receiver(self, receiver_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/receivers/{receiver_id}/verify",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["receiver"])

    def add_receiver_key(self, receiver_id: str, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/receivers/{receiver_id}/keys",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["key"])

    def revoke_receiver_key(
        self,
        receiver_id: str,
        key_id: str,
        *,
        reason_code: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/receivers/{receiver_id}/keys/{key_id}/revoke",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["key"])

    def create_profile_version(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = self._client.post(
            "/v1/authority/profile-versions",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["profile"])

    def activate_profile_version(
        self,
        profile_id: str,
        *,
        profile_kind: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/profile-versions/{profile_id}/activate",
            json={"profile_kind": profile_kind},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["profile"])

    # Safe evidence reads and erasure

    def list_uses(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/authority/uses")["uses"])

    def get_use(self, use_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._client.get(f"/v1/authority/uses/{use_id}")["use"])

    def list_presentations(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self._client.get("/v1/authority/presentations")["presentations"])

    def get_presentation(self, presentation_id: str) -> dict[str, Any]:
        data = self._client.get(f"/v1/authority/presentations/{presentation_id}")
        return cast("dict[str, Any]", data["presentation"])

    def erase_presentation(self, presentation_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = self._client.post(
            f"/v1/authority/presentations/{presentation_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["tombstone"])
