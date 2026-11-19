"""Credential retrieval."""

from __future__ import annotations

from urllib.parse import quote

from .client import HttpClient
from .types import Credential


class CredentialService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self, provider: str, passport_token: str | None = None) -> Credential:
        """Retrieve credential for a provider. Optionally pass passport token for security signal tracking."""
        extra_headers = {}
        if passport_token:
            extra_headers["X-Passport-Token"] = passport_token
        data = self._client.get(
            f"/v1/credentials/{quote(provider)}",
            extra_headers=extra_headers if extra_headers else None,
        )
        return Credential(
            provider=data["provider"],
            credential=data.get("credential"),
            credentials=data.get("credentials"),
        )

    def get_by_connection(self, connection_id: str, passport_token: str | None = None) -> Credential:
        """Retrieve credential by connection ID."""
        extra_headers = {}
        if passport_token:
            extra_headers["X-Passport-Token"] = passport_token
        data = self._client.get(
            f"/v1/credentials/by-connection/{connection_id}",
            extra_headers=extra_headers if extra_headers else None,
        )
        return Credential(
            provider=data["provider"],
            credential=data.get("credential"),
            credentials=data.get("credentials"),
        )
