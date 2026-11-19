"""Async mirror of CredentialService."""

from __future__ import annotations

from urllib.parse import quote

from ..client import AsyncHttpClient
from ..types import Credential


class AsyncCredentialService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self, provider: str, passport_token: str | None = None) -> Credential:
        extra_headers: dict[str, str] = {}
        if passport_token:
            extra_headers["X-Passport-Token"] = passport_token
        data = await self._client.get(
            f"/v1/credentials/{quote(provider)}",
            extra_headers=extra_headers if extra_headers else None,
        )
        return Credential(
            provider=data["provider"],
            credential=data.get("credential"),
            credentials=data.get("credentials"),
        )

    async def get_by_connection(self, connection_id: str, passport_token: str | None = None) -> Credential:
        extra_headers: dict[str, str] = {}
        if passport_token:
            extra_headers["X-Passport-Token"] = passport_token
        data = await self._client.get(
            f"/v1/credentials/by-connection/{connection_id}",
            extra_headers=extra_headers if extra_headers else None,
        )
        return Credential(
            provider=data["provider"],
            credential=data.get("credential"),
            credentials=data.get("credentials"),
        )
