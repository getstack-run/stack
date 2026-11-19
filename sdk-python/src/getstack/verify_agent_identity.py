"""The check of a statement that says who an agent is (spec/agent-identity/SPEC.md section 12), offline.

Public-key crypto only: nothing here calls the STACK API except an optional ``jwks_url`` fetch of STACK's
public keys, which are the issuer's keys at ``/v1/.well-known/jwks.json``, the ones that sign Passports.

A verified statement says that STACK, when it signed, vouched that the agent exists and that these facts about
its owner were true. It cannot say that they are still true, that the request you hold was made by the agent
(check the request's signature first), or that the agent is honest. Ask again rather than keep a statement past
its expiry.

Every function takes the keys as exactly one of ``jwks`` (a JWKS dict or a list of keys), ``jwks_url`` or
``public_jwk``, and ``now`` (a ``datetime``, default the current time) to check expiry against. A failure raises
:class:`AgentIdentityVerificationError`; treat any raise as no statement.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, cast

import jwt
from jwt import PyJWKClient
from jwt.algorithms import OKPAlgorithm

AGENT_IDENTITY_TYP = "stack-agent-identity+jwt"
AGENT_IDENTITY_AUDIENCE = "stack:agent-identity"
ISSUER = "getstack.run"
_MAX_SECONDS = 900
_CLOCK_TOLERANCE_SECONDS = 5

_jwks_clients: dict[str, PyJWKClient] = {}


class AgentIdentityVerificationError(ValueError):
    """A statement did not check out. ``reason`` is ``invalid``, ``expired`` or ``wrong_lookup``."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _invalid(message: str) -> AgentIdentityVerificationError:
    return AgentIdentityVerificationError("invalid", message)


def _signing_key(
    token: str,
    jwks: dict[str, Any] | list[dict[str, Any]] | None,
    jwks_url: str | None,
    public_jwk: dict[str, Any] | None,
    kid: str | None,
) -> Any:
    given = sum(value is not None for value in (jwks, jwks_url, public_jwk))
    if given != 1:
        raise ValueError("Pass exactly one of jwks, jwks_url or public_jwk")
    if jwks_url is not None:
        client = _jwks_clients.get(jwks_url)
        if client is None:
            client = PyJWKClient(jwks_url)
            _jwks_clients[jwks_url] = client
        return client.get_signing_key_from_jwt(token).key
    keys = [public_jwk] if public_jwk is not None else (jwks["keys"] if isinstance(jwks, dict) else jwks)
    matching = [key for key in cast("list[dict[str, Any]]", keys) if key.get("kid") == kid or public_jwk is not None]
    if len(matching) != 1:
        raise _invalid("The statement names a key that is not in the given keys")
    return OKPAlgorithm.from_jwk(json.dumps(matching[0]))


def _facts(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("v") != 1:
        raise _invalid("The statement is not in a known format")
    agent, owner, lookup = value.get("agent"), value.get("owner"), value.get("lookup")
    if (
        not isinstance(agent, dict)
        or not isinstance(agent.get("id"), str)
        or agent.get("status")
        not in (
            "active",
            "suspended",
            "closed",
        )
    ):
        raise _invalid("The statement names no agent")
    if "name" in agent and not isinstance(agent["name"], str):
        raise _invalid("The statement names the agent wrongly")
    if not isinstance(owner, dict) or any(
        not isinstance(owner.get(fact), bool) for fact in ("identity_verified", "good_standing")
    ):
        raise _invalid("The statement says nothing of the owner")
    if (
        not isinstance(lookup, dict)
        or len(lookup) != 1
        or next(iter(lookup)) not in ("key_id", "site", "agent_id")
        or not isinstance(next(iter(lookup.values())), str)
    ):
        raise _invalid("The statement does not say what was asked")
    return value


def verify_agent_identity(
    statement: str,
    *,
    jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
    jwks_url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    now: datetime | None = None,
    issuer: str = ISSUER,
    expect: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Check a statement as the specification says and return its claims.

    EdDSA under STACK's keys, the type and audience of an identity statement (never a Passport's), the issuer,
    the clock, the lifetime, the shape of the claims, that it is about one agent and, with ``expect``
    (``{"key_id": ...}``, ``{"site": ...}`` or ``{"agent_id": ...}``), that it answers what you asked.
    ``claims["identity"]`` holds ``agent``, ``owner`` and ``lookup``.
    """
    try:
        header = jwt.get_unverified_header(statement)
        if header.get("alg") != "EdDSA" or header.get("typ") != AGENT_IDENTITY_TYP:
            raise _invalid("The token is not an identity statement from STACK")
        key = _signing_key(statement, jwks, jwks_url, public_jwk, header.get("kid"))
        claims = jwt.decode(
            statement,
            key,
            algorithms=["EdDSA"],
            audience=AGENT_IDENTITY_AUDIENCE,
            issuer=issuer,
            options={"verify_exp": False, "verify_iat": False, "require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except AgentIdentityVerificationError:
        raise
    except ValueError as error:
        if "exactly one" in str(error):
            raise
        raise _invalid("The token is not a valid identity statement from STACK") from error
    except jwt.PyJWTError as error:
        raise _invalid("The token is not a valid identity statement from STACK") from error
    at = now.timestamp() if now is not None else time.time()
    exp, iat = claims["exp"], claims["iat"]
    if not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
        raise _invalid("The statement has no times")
    if at >= float(exp) + _CLOCK_TOLERANCE_SECONDS:
        raise AgentIdentityVerificationError("expired", "The statement has expired")
    if float(iat) > at + _CLOCK_TOLERANCE_SECONDS:
        raise _invalid("The statement was made in the future")
    if float(exp) - float(iat) > _MAX_SECONDS:
        raise _invalid("The statement is good for too long")
    identity = _facts(claims.get("identity"))
    if claims["sub"] != identity["agent"]["id"]:
        raise _invalid("The statement is about two agents")
    if expect is not None:
        asked = next(iter(expect))
        if identity["lookup"].get(asked) != expect[asked] or len(identity["lookup"]) != 1:
            raise AgentIdentityVerificationError("wrong_lookup", "The statement answers another lookup")
    return claims
