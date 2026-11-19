"""Async authority principal, proof, binding, receiver, and evidence APIs."""

from __future__ import annotations

from typing import Any, cast

from ..authority import _idempotency_headers, _version_params
from ..client import AsyncHttpClient


class AsyncAuthorityService:
    """Async mirror of :class:`getstack.authority.AuthorityService`."""

    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def create_enterprise_oidc_request(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        """Create a pending request and return the human approval URL."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                "/v1/authority/enterprise-oidc/requests",
                json=input,
                extra_headers=_idempotency_headers(idempotency_key),
            ),
        )

    async def get_enterprise_oidc_request(self, request_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.get(f"/v1/authority/enterprise-oidc/requests/{request_id}"))

    async def create_principal(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            "/v1/authority/principals",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["principal"])

    async def list_principals(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", (await self._client.get("/v1/authority/principals"))["principals"])

    async def get_principal(self, principal_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", (await self._client.get(f"/v1/authority/principals/{principal_id}"))["principal"])

    async def archive_principal(self, principal_id: str, *, reason_code: str, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/principals/{principal_id}/archive",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["principal"])

    async def erase_principal(self, principal_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/principals/{principal_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["tombstone"])

    async def import_proof(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            "/v1/authority/proofs/import",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["proof"])

    async def create_proof_collection_session(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            "/v1/authority/proof-collection-sessions",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["session"])

    async def get_proof_collection_session(self, session_id: str) -> dict[str, Any]:
        data = await self._client.get(f"/v1/authority/proof-collection-sessions/{session_id}")
        return cast("dict[str, Any]", data["session"])

    async def list_proofs(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", (await self._client.get("/v1/authority/proofs"))["proofs"])

    async def get_proof(self, proof_id: str, *, version: int | None = None) -> dict[str, Any]:
        data = await self._client.get(f"/v1/authority/proofs/{proof_id}", params=_version_params(version))
        return cast("dict[str, Any]", data["proof"])

    async def revoke_proof(self, proof_id: str, *, reason_code: str, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/proofs/{proof_id}/revoke",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["proof"])

    async def erase_proof(self, proof_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/proofs/{proof_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["proof"])

    async def create_binding(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            "/v1/authority/bindings",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    async def list_bindings(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", (await self._client.get("/v1/authority/bindings"))["bindings"])

    async def get_binding(self, binding_id: str, *, version: int | None = None) -> dict[str, Any]:
        data = await self._client.get(f"/v1/authority/bindings/{binding_id}", params=_version_params(version))
        return cast("dict[str, Any]", data["binding"])

    async def create_approval_requests(
        self, binding_id: str, *, idempotency_key: str, **input: Any
    ) -> list[dict[str, Any]]:
        data = await self._client.post(
            f"/v1/authority/bindings/{binding_id}/approval-requests",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("list[dict[str, Any]]", data["approval_requests"])

    async def list_approval_requests(self, binding_id: str) -> list[dict[str, Any]]:
        data = await self._client.get(f"/v1/authority/bindings/{binding_id}/approval-requests")
        return cast("list[dict[str, Any]]", data["approval_requests"])

    async def activate_binding(
        self, binding_id: str, *, idempotency_key: str, version: int | None = None
    ) -> dict[str, Any]:
        data = await self._client.request(
            "POST",
            f"/v1/authority/bindings/{binding_id}/activate",
            json={},
            params=_version_params(version),
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    async def delegate_binding(self, binding_id: str, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/bindings/{binding_id}/delegate",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    async def revoke_binding(self, binding_id: str, *, reason_code: str, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/bindings/{binding_id}/revoke",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["binding"])

    async def erase_binding(self, binding_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/bindings/{binding_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["tombstone"])

    async def create_receiver(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            "/v1/authority/receivers",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["receiver"])

    async def list_receivers(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", (await self._client.get("/v1/authority/receivers"))["receivers"])

    async def get_receiver(self, receiver_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", (await self._client.get(f"/v1/authority/receivers/{receiver_id}"))["receiver"])

    async def create_receiver_verification_challenge(self, receiver_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/receivers/{receiver_id}/verification-challenges",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["challenge"])

    async def verify_receiver(self, receiver_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/receivers/{receiver_id}/verify",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["receiver"])

    async def add_receiver_key(self, receiver_id: str, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/receivers/{receiver_id}/keys",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["key"])

    async def revoke_receiver_key(
        self, receiver_id: str, key_id: str, *, reason_code: str, idempotency_key: str
    ) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/receivers/{receiver_id}/keys/{key_id}/revoke",
            json={"reason_code": reason_code},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["key"])

    async def create_profile_version(self, *, idempotency_key: str, **input: Any) -> dict[str, Any]:
        data = await self._client.post(
            "/v1/authority/profile-versions",
            json=input,
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["profile"])

    async def activate_profile_version(
        self, profile_id: str, *, profile_kind: str, idempotency_key: str
    ) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/profile-versions/{profile_id}/activate",
            json={"profile_kind": profile_kind},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["profile"])

    async def list_uses(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", (await self._client.get("/v1/authority/uses"))["uses"])

    async def get_use(self, use_id: str) -> dict[str, Any]:
        return cast("dict[str, Any]", (await self._client.get(f"/v1/authority/uses/{use_id}"))["use"])

    async def list_presentations(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", (await self._client.get("/v1/authority/presentations"))["presentations"])

    async def get_presentation(self, presentation_id: str) -> dict[str, Any]:
        data = await self._client.get(f"/v1/authority/presentations/{presentation_id}")
        return cast("dict[str, Any]", data["presentation"])

    async def erase_presentation(self, presentation_id: str, *, idempotency_key: str) -> dict[str, Any]:
        data = await self._client.post(
            f"/v1/authority/presentations/{presentation_id}/erase",
            json={},
            extra_headers=_idempotency_headers(idempotency_key),
        )
        return cast("dict[str, Any]", data["tombstone"])
