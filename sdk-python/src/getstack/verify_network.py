"""Offline checks of everything STACK signs for the network: a countersignature over a passport, the signed
revocation list, a "STACK-verified" statement and the detection rule set.

Public-key crypto only: nothing here calls the STACK API except an optional ``jwks_url`` fetch of STACK's
public keys. What no offline check can tell you is whether a key, an install, an agent or a passport was
revoked after the token was issued. A countersignature lives 15 minutes by default for that reason; for a
live answer call ``stack.network.verify(...)`` or ``stack.network.verified(...)``, or follow the signed
revocation list.

Every function takes the keys as exactly one of ``jwks`` (a JWKS dict or a list of keys), ``jwks_url`` or
``public_jwk``, and ``now`` (a ``datetime``, default the current time) to check expiry against. A failure
raises :class:`NetworkVerificationError`; treat any raise as a reject.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, cast

import jwt
from jwt import PyJWKClient
from jwt.algorithms import OKPAlgorithm

from .network_keys import install_key_thumbprint, passport_digest

ISSUER = "getstack.run"
_CLOCK_TOLERANCE_SECONDS = 5

_KINDS = {
    "countersignature": ("stack-countersignature+jwt", "stack:countersignature"),
    "revocation_list": ("stack-revocation-list+jwt", "stack:revocation-list"),
    "verified": ("stack-verified+jwt", "stack:verified"),
    "detection_rules": ("stack-detection-rules+jwt", "stack:detection-rules"),
}

_jwks_clients: dict[str, PyJWKClient] = {}


class NetworkVerificationError(ValueError):
    """A network object did not check out. ``reason`` is one of ``invalid``, ``expired``, ``digest_mismatch``,
    ``passport_invalid``, ``passport_expired`` or ``revision_too_old``."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _now(now: datetime | None) -> float:
    return now.timestamp() if now is not None else time.time()


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
        raise NetworkVerificationError("invalid", "The token names a key that is not in the given keys")
    return OKPAlgorithm.from_jwk(json.dumps(matching[0]))


def _verify_statement(
    kind: str,
    token: str,
    *,
    jwks: dict[str, Any] | list[dict[str, Any]] | None,
    jwks_url: str | None,
    public_jwk: dict[str, Any] | None,
    now: datetime | None,
) -> dict[str, Any]:
    typ, audience = _KINDS[kind]
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA" or header.get("typ") != typ:
            raise NetworkVerificationError("invalid", "The token is not this kind of signed object from STACK")
        key = _signing_key(token, jwks, jwks_url, public_jwk, header.get("kid"))
        payload = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            audience=audience,
            issuer=ISSUER,
            options={"verify_exp": False, "verify_iat": False, "require": ["exp", "iat", "aud", "iss"]},
        )
    except NetworkVerificationError:
        raise
    except ValueError as error:
        if "exactly one" in str(error):
            raise
        raise NetworkVerificationError("invalid", "The token is not a valid signed object from STACK") from error
    except jwt.PyJWTError as error:
        raise NetworkVerificationError("invalid", "The token is not a valid signed object from STACK") from error
    if _now(now) > float(payload["exp"]) + _CLOCK_TOLERANCE_SECONDS:
        raise NetworkVerificationError("expired", "The token has expired")
    return payload


def verify_countersigned_passport(
    countersignature: str,
    passport: str,
    *,
    jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
    jwks_url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check a passport an install issued and the countersignature STACK made over it, offline.

    Checks STACK's signature on the countersignature (type, audience, issuer, expiry), that the passport
    hashes to the digest it names, and the install's signature on the passport with the key the
    countersignature carries. Returns ``{"countersignature": claims, "passport": claims, "valid_until": datetime}``.

    It tells you STACK saw this install's key proved by its holder, the owner who registered it, and this
    passport digest, when it issued the countersignature. It cannot tell you the key, install, agent or
    passport was revoked since: see the note at the top of this module.
    """
    claims = _verify_statement(
        "countersignature", countersignature, jwks=jwks, jwks_url=jwks_url, public_jwk=public_jwk, now=now
    )
    cs = claims.get("cs")
    if (
        not isinstance(cs, dict)
        or cs.get("v") != 1
        or cs.get("passport", {}).get("alg") != "sha256"
        or cs.get("key", {}).get("jwk", {}).get("crv") != "Ed25519"
    ):
        raise NetworkVerificationError("invalid", "The countersignature is not in a known format")
    if install_key_thumbprint(cs["key"]["jwk"]) != cs["key"]["kid"]:
        raise NetworkVerificationError("invalid", "The countersignature names a key id that is not its key")
    if passport_digest(passport) != cs["passport"]["digest"]:
        raise NetworkVerificationError("digest_mismatch", "This passport is not the one the countersignature covers")
    try:
        key: Any = OKPAlgorithm.from_jwk(json.dumps(cs["key"]["jwk"]))
        passport_claims = jwt.decode(
            passport,
            key,
            algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_iat": False, "verify_aud": False, "verify_iss": False},
        )
    except (jwt.PyJWTError, ValueError) as error:
        raise NetworkVerificationError("passport_invalid", "The passport is not signed by the install's key") from error
    exp = passport_claims.get("exp")
    if isinstance(exp, (int, float)) and _now(now) > float(exp) + _CLOCK_TOLERANCE_SECONDS:
        raise NetworkVerificationError("passport_expired", "The passport has expired")
    return {
        "countersignature": claims,
        "passport": passport_claims,
        "valid_until": datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc),
    }


def verify_revocation_list(
    list_token: str,
    *,
    jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
    jwks_url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check a signed revocation list (the pollable endpoint's or a webhook's) and read it.

    Returns ``{"after", "head", "next", "entries", "resume_from", "expires_at"}``. Resume polling from
    ``resume_from``: ``next`` when there is one, else ``head``. Each entry has ``seq``, ``id``, ``kind``
    (passport, agent, key, install), ``subject``, ``install``, ``reason``, ``by`` and ``at``.
    """
    payload = _verify_statement(
        "revocation_list", list_token, jwks=jwks, jwks_url=jwks_url, public_jwk=public_jwk, now=now
    )
    rl = payload.get("rl")
    if not isinstance(rl, dict) or rl.get("v") != 1 or not isinstance(rl.get("entries"), list):
        raise NetworkVerificationError("invalid", "The list is not in a known format")
    return {
        "after": rl["after"],
        "head": rl["head"],
        "next": rl["next"],
        "entries": rl["entries"],
        "resume_from": rl["next"] if rl["next"] is not None else rl["head"],
        "expires_at": datetime.fromtimestamp(float(payload["exp"]), tz=timezone.utc),
    }


def revocation_covers(
    entries: list[dict[str, Any]],
    *,
    install: str,
    key_id: str | None = None,
    passport_digest: str | None = None,
    agent: str | None = None,
) -> dict[str, Any] | None:
    """The first entry of a verified revocation list that covers a countersigned passport, or ``None``.

    Pass what the countersignature's ``cs`` claims say: the ``install``, its ``key_id``, the ``passport_digest``
    and the ``agent`` the install named, if any. An entry matches only on the subject AND the install: a
    digest or an agent name that matches while the entry's install is another's (or missing) is somebody
    else's revocation and is ignored, so one company can never have another's agent refused. An entry of
    kind ``install`` names the install itself; ``key``, the install's key id.
    """
    for entry in entries:
        if not isinstance(entry.get("install"), str) or entry["install"] != install:
            continue
        kind, subject = entry.get("kind"), entry.get("subject")
        if (
            (kind == "passport" and passport_digest is not None and subject == passport_digest)
            or (kind == "agent" and agent is not None and subject == agent)
            or (kind == "key" and key_id is not None and subject == key_id)
            or (kind == "install" and subject == install)
        ):
            return entry
    return None


def verify_verified_statement(
    statement: str,
    *,
    jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
    jwks_url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check a signed "STACK-verified" statement. Only ``status == "live"`` earns the mark. A statement is a
    five-minute snapshot: show nothing older."""
    payload = _verify_statement("verified", statement, jwks=jwks, jwks_url=jwks_url, public_jwk=public_jwk, now=now)
    vs = payload.get("vs")
    if not isinstance(vs, dict) or vs.get("v") != 1:
        raise NetworkVerificationError("invalid", "The statement is not in a known format")
    return {
        "subject": payload["sub"],
        "status": vs["status"],
        "mark": vs["mark"],
        "install": vs["install"],
        "countersignature": vs["countersignature"],
        "valid_until": datetime.fromisoformat(str(vs["valid_until"]).replace("Z", "+00:00")),
        "passport_digest": vs["passport_digest"],
        "issued_at": datetime.fromtimestamp(float(payload["iat"]), tz=timezone.utc),
        "expires_at": datetime.fromtimestamp(float(payload["exp"]), tz=timezone.utc),
    }


def verify_detection_rules(
    statement: str,
    *,
    held_revision: int | None = None,
    jwks: dict[str, Any] | list[dict[str, Any]] | None = None,
    jwks_url: str | None = None,
    public_jwk: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check a signed detection rule set. Pass the highest revision you already run as ``held_revision``: a
    lower one is refused, so an old set replayed to you cannot undo a newer one. An expired set is refused.

    Returns ``{"version", "revision", "sha256", "packs", "expires_at"}``; each rule is ``{id, severity,
    pattern, flags}``, an ECMAScript regular expression (``pattern`` and ``flags`` as in ``new RegExp``).
    """
    payload = _verify_statement(
        "detection_rules", statement, jwks=jwks, jwks_url=jwks_url, public_jwk=public_jwk, now=now
    )
    rs = payload.get("rs")
    if not isinstance(rs, dict) or rs.get("v") != 1 or not isinstance(rs.get("packs"), list):
        raise NetworkVerificationError("invalid", "The rule set is not in a known format")
    if held_revision is not None and rs["revision"] < held_revision:
        raise NetworkVerificationError(
            "revision_too_old", f"This rule set is revision {rs['revision']}; revision {held_revision} is already held"
        )
    return {
        "version": rs["version"],
        "revision": rs["revision"],
        "sha256": rs["sha256"],
        "packs": rs["packs"],
        "expires_at": datetime.fromtimestamp(float(payload["exp"]), tz=timezone.utc),
    }
