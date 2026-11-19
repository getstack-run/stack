"""Offline passport verification (parity with the JS SDK's
``verifyPassportOffline`` — the SDK's headline feature).

Verify a STACK passport using ONLY the public signing key. Never calls
the STACK API for revocation or freshness — strictly cryptographic
(signature + issuer + audience + expiry). For revocation-aware checks,
layer a short-window cache on ``POST /v1/passports/verify``.

Two key sources, exactly one required:
  - ``jwks_url`` — a URL to ``/v1/.well-known/jwks.json`` (or a per-operator
    ``/v1/operators/<id>/jwks.json``); keys fetched once and cached per URL.
  - ``public_jwk`` — a pre-fetched public key dict for fully air-gapped
    verification (no network at verify time, ever).

Raises ``ValueError`` on any failure (bad signature, wrong issuer/audience,
expired, malformed, missing required claims). Treat any raise as a reject.
"""

from __future__ import annotations

from typing import Any, cast

import jwt
from jwt import PyJWKClient
from jwt.algorithms import OKPAlgorithm

from .passport_header_verify import _validate_verified_passport_claims
from .types import VerifiedPassportClaims

DEFAULT_ISSUER = "getstack.run"
DEFAULT_AUDIENCE = "stack:passport"

# Cache PyJWKClient per JWKS URL so repeat verifies share the key cache
# (mirrors the JS remoteJwksCache).
_jwks_client_cache: dict[str, PyJWKClient] = {}


def _get_jwks_client(jwks_url: str) -> PyJWKClient:
    client = _jwks_client_cache.get(jwks_url)
    if client is None:
        client = PyJWKClient(jwks_url)
        _jwks_client_cache[jwks_url] = client
    return client


def verify_passport_offline(
    token: str,
    *,
    jwks_url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
) -> VerifiedPassportClaims:
    """Verify a STACK passport JWT offline. Returns the decoded claims dict
    (with the STACK-specific fields under ``stk``)."""
    if not jwks_url and public_jwk is None:
        raise ValueError("verify_passport_offline: supply either jwks_url or public_jwk")
    if jwks_url and public_jwk is not None:
        raise ValueError("verify_passport_offline: pass only one of jwks_url or public_jwk")

    # PyJWT types `from_jwk` as returning a public-or-private OKP key, but `jwt.decode` only accepts
    # public keys; this function takes a public JWK, so the key is typed loosely here.
    key: Any
    if public_jwk is not None:
        # Air-gapped: verify against the supplied Ed25519 public JWK.
        key = OKPAlgorithm.from_jwk(public_jwk)
    else:
        try:
            # The guards above leave a non-empty `jwks_url` when `public_jwk` is None.
            key = _get_jwks_client(cast("str", jwks_url)).get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientError as err:
            raise ValueError(f"verify_passport_offline: jwks lookup failed ({err})") from err

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iat", "jti", "sub", "iss", "aud"]},
        )
    except jwt.InvalidTokenError as err:
        raise ValueError(f"verify_passport_offline: signature/claims invalid ({err})") from err

    for claim in ("jti", "sub", "iss", "aud"):
        if not payload.get(claim):
            raise ValueError(f"verify_passport_offline: token missing required claim '{claim}'")

    return _validate_verified_passport_claims(payload, "verify_passport_offline")
