"""Partner-side helper for the X-Stack-Passport convention.

Pulls the passport token from request headers (or accepts the raw
string), looks up STACK's deployment JWKS, and verifies offline.
No network at verify time after the JWKS client has cached the key.

Usage:

    from getstack import verify_passport_header

    claims = verify_passport_header(
        request.headers.get('x-stack-passport'),
        base_url='https://api.getstack.run',
    )
    tenant_id = claims['stk']['operator_id']
    agent_id = claims['stk']['agent_id']

Does NOT check revocation. For revocation-aware verification, layer
a short-window cache on POST /v1/passports/verify.
"""

from __future__ import annotations

from typing import Any, cast

import jwt
from jwt import PyJWKClient

from .types import VerifiedPassportClaims

DEFAULT_BASE_URL = "https://api.getstack.run"
DEFAULT_ISSUER = "getstack.run"
DEFAULT_AUDIENCE = "stack:passport"

# Cache PyJWKClient per JWKS URL so repeat verifies share the key cache.
_jwks_client_cache: dict[str, PyJWKClient] = {}


def _get_jwks_client(jwks_url: str) -> PyJWKClient:
    client = _jwks_client_cache.get(jwks_url)
    if client is None:
        client = PyJWKClient(jwks_url)
        _jwks_client_cache[jwks_url] = client
    return client


def verify_passport_header(
    header_value: str | list[str] | None,
    *,
    base_url: str = DEFAULT_BASE_URL,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
) -> VerifiedPassportClaims:
    """Verify an X-Stack-Passport header value.

    The header value is a STACK passport JWT signed by STACK's deployment
    key. This function resolves the canonical deployment JWKS and verifies
    signature + issuer + audience + expiry before reading claims.

    Raises ValueError on any failure — missing header, malformed JWT,
    missing/mismatched agent or operator claims, signature failure, wrong
    issuer/audience, or expiry.
    The caller should treat any raise as a 401 reject.

    Returns the decoded claims dict on success.
    """
    if header_value is None:
        raise ValueError("verify_passport_header: missing header value")
    if isinstance(header_value, list):
        if not header_value:
            raise ValueError("verify_passport_header: header value is empty list")
        token = header_value[0]
    else:
        token = header_value
    if not isinstance(token, str) or not token:
        raise ValueError("verify_passport_header: header value is empty")

    # Passports use the deployment signing key. Per-operator JWKS endpoints
    # verify customer-managed COSE claims and must not select Passport keys.
    jwks_url = f"{base_url.rstrip('/')}/v1/.well-known/jwks.json"
    jwk_client = _get_jwks_client(jwks_url)

    try:
        signing_key = jwk_client.get_signing_key_from_jwt(token)
    except jwt.PyJWKClientError as err:
        raise ValueError(f"verify_passport_header: jwks lookup failed ({err})") from err

    try:
        verified = jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iat", "jti", "sub", "iss", "aud"]},
        )
    except jwt.InvalidTokenError as err:
        raise ValueError(f"verify_passport_header: signature/claims invalid ({err})") from err

    return _validate_verified_passport_claims(verified, "verify_passport_header")


def _validate_verified_passport_claims(payload: dict[str, Any], helper_name: str) -> VerifiedPassportClaims:
    """Validate the tenant/agent binding after cryptographic verification."""
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError(f"{helper_name}: token missing sub claim")

    stack_claims = payload.get("stk")
    if not isinstance(stack_claims, dict):
        raise ValueError(f"{helper_name}: token missing stk claim")

    operator_id = stack_claims.get("operator_id")
    if not isinstance(operator_id, str) or not operator_id:
        raise ValueError(f"{helper_name}: token missing stk.operator_id claim")

    agent_id = stack_claims.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError(f"{helper_name}: token missing stk.agent_id claim")
    if agent_id != subject:
        raise ValueError(f"{helper_name}: sub does not match stk.agent_id")

    return cast(VerifiedPassportClaims, payload)
