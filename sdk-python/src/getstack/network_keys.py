"""An install's key, and the two things it signs: the proof of possession that registers it, and the
single-use request (the "install proof") every call from the install to the network carries as its bearer value.

Formats: ``packages/shared/src/schemas/network.ts``, and the test vectors in
``spec/network/test-vectors.json``, both in the STACK repository.

Example::

    key = InstallKey.generate()
    Path("install.pem").write_text(key.to_pem())          # keep it where only the install can read it
    stack.network.installs.register_key(install["id"], key)  # a person approves the key in a browser
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from datetime import datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NETWORK_AUDIENCE = "stack:network"
NETWORK_INSTALL_PROOF_TYP = "stack-install+jwt"
NETWORK_INSTALL_POP_TYP = "stack-install-pop+jwt"

#: A proof lives this long by default, in seconds; the API accepts at most 120.
INSTALL_PROOF_LIFETIME_SECONDS = 60

NETWORK_PROOF_ACTIONS = ("rules", "classify", "countersign", "revoke")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def install_key_thumbprint(public_jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of an Ed25519 public key: the key's id everywhere in the network."""
    canonical = f'{{"crv":"Ed25519","kty":"OKP","x":"{public_jwk["x"]}"}}'
    return _b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def passport_digest(passport: str) -> str:
    """The digest a countersignature binds: base64url SHA-256 of the passport's compact serialisation, as issued."""
    return _b64url(hashlib.sha256(passport.encode("utf-8")).digest())


def _seconds(now: datetime | None) -> int:
    return int(now.timestamp()) if now is not None else int(time.time())


class InstallKey:
    """An install's signing key. The private half never leaves the object except through :meth:`to_pem`."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        #: The public key, as the API takes it.
        self.public_jwk: dict[str, str] = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        #: The key's thumbprint: its id in the network.
        self.kid: str = install_key_thumbprint(self.public_jwk)

    @classmethod
    def generate(cls) -> InstallKey:
        """A new key pair. Write the private half out with :meth:`to_pem`."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: str | bytes) -> InstallKey:
        """Load a key from its PKCS#8 PEM, as written by :meth:`to_pem`."""
        data = pem.encode("ascii") if isinstance(pem, str) else pem
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("An install key is an Ed25519 key")
        return cls(key)

    def to_pem(self) -> str:
        """The private key as PKCS#8 PEM. Secret: write it to a file with mode 0600 and never log it."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def sign_key_proof(self, install_id: str, nonce: str, now: datetime | None = None) -> str:
        """The proof of possession that registers this key: a JWS over STACK's challenge, signed with this key."""
        iat = _seconds(now)
        return jwt.encode(
            {
                "iss": self.kid,
                "aud": NETWORK_AUDIENCE,
                "install": install_id,
                "nonce": nonce,
                "iat": iat,
                "exp": iat + 120,
            },
            self._private_key,
            algorithm="EdDSA",
            headers={"typ": NETWORK_INSTALL_POP_TYP, "kid": self.kid},
        )

    def sign_proof(
        self,
        install_id: str,
        claims: dict[str, Any],
        now: datetime | None = None,
        lifetime_seconds: int = INSTALL_PROOF_LIFETIME_SECONDS,
    ) -> str:
        """One signed request, with a fresh ``jti`` every time so a proof is good for exactly one call.

        ``claims`` carries ``act`` (one of ``rules``, ``classify``, ``countersign``, ``revoke``) and the fields
        that action needs.
        """
        if claims.get("act") not in NETWORK_PROOF_ACTIONS:
            raise ValueError(f"act must be one of {', '.join(NETWORK_PROOF_ACTIONS)}")
        iat = _seconds(now)
        payload = {
            **claims,
            "iss": install_id,
            "sub": install_id,
            "aud": NETWORK_AUDIENCE,
            "iat": iat,
            "exp": iat + lifetime_seconds,
            "jti": _b64url(uuid.uuid4().bytes + uuid.uuid4().bytes[:2]),
        }
        return jwt.encode(
            payload,
            self._private_key,
            algorithm="EdDSA",
            headers={"typ": NETWORK_INSTALL_PROOF_TYP, "kid": self.kid},
        )
