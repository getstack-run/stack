"""Shared validation for authority-bound runtime request identifiers."""

from __future__ import annotations

import re
import secrets

AUTHORITY_REQUEST_ID_HEADER = "X-STACK-Authority-Request-Id"
_AUTHORITY_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22,256}$")


def create_authority_request_id() -> str:
    """Create a cryptographically random 24-character base64url handle."""
    return secrets.token_urlsafe(18)


def authority_request_headers(authority_request_id: str | None) -> dict[str, str]:
    """Build the authority request header after validating its wire format."""
    if authority_request_id is None:
        return {}
    if not _AUTHORITY_REQUEST_ID_PATTERN.fullmatch(authority_request_id):
        raise ValueError(
            "authority_request_id must be 22-256 base64url characters and must be reused for exact retries"
        )
    return {AUTHORITY_REQUEST_ID_HEADER: authority_request_id}
