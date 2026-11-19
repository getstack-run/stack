"""Customer-side COSE_Sign1 signer for ``customer_managed`` agents
(parity with the JS SDK's ``signClaimEnvelope``).

``customer_managed`` mode keeps the agent's private key on customer
infrastructure; STACK stores only the enrolled pubkey. When the agent
produces a STACK claim envelope, it is signed locally with this helper
and submitted pre-signed. The wire format is a base64url-encoded
COSE_Sign1 message, byte-compatible with what ``@stack/vault``'s
``ClaimSigner``/``AgentSigner.verifyPreSigned`` accepts (proven by the
cross-language round-trip in
``sdk-python/scripts/verify_sign_claim_crosslang.py``: Python signs, the TS
vault verifier accepts).

EdDSA / Ed25519 only in v1 (matches the JS SDK).
"""

from __future__ import annotations

from typing import Any

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm

# ── COSE constants per RFC 9052 / 9053 (must match sign-claim.ts) ──────
COSE_ALG_EDDSA = -8
COSE_HEADER_ALG = 1
COSE_HEADER_KID = 4
COSE_HEADER_TYP = 16
STACK_CLAIM_TYP = "stack/claim+cose"
SIG_STRUCTURE_CONTEXT = "Signature1"


def _ed25519_from_jwk(private_jwk: dict[str, Any]) -> Ed25519PrivateKey:
    # Reuse pyjwt's OKP JWK loader (already a dependency), then hand the
    # PEM to cryptography so we get an Ed25519PrivateKey we can sign with.
    key = OKPAlgorithm.from_jwk(private_jwk)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("sign_claim_envelope: JWK is not an Ed25519 private key")
    return key


def sign_claim_envelope(
    envelope: dict[str, Any],
    *,
    private_key: dict[str, Any],
    agent_id: str,
    alg: str = "EdDSA",
) -> str:
    """Sign a STACK claim envelope locally, returning a base64url COSE_Sign1
    string. ``private_key`` is the agent's Ed25519 private key as a JWK
    (e.g. the ``privateKey`` persisted at ``~/.stack/agents/<id>.json``).
    The COSE ``kid`` is ``agent:<agent_id>:v1``."""
    if alg != "EdDSA":
        raise ValueError(
            f"sign_claim_envelope: algorithm '{alg}' is reserved but not yet "
            "implemented. Only 'EdDSA' is supported in v1."
        )

    kid = f"agent:{agent_id}:v1"
    signer = _ed25519_from_jwk(private_key)

    # Payload bytes — CBOR-encoded envelope.
    payload_bytes = cbor2.dumps(envelope)

    # Protected header — {alg, kid, typ}. kid is a byte string (matches
    # the JS Buffer.from(kid)).
    protected_bytes = cbor2.dumps(
        {
            COSE_HEADER_ALG: COSE_ALG_EDDSA,
            COSE_HEADER_KID: kid.encode("utf-8"),
            COSE_HEADER_TYP: STACK_CLAIM_TYP,
        }
    )

    # Sig_structure1 per RFC 9052 §4.4 — the bytes actually signed.
    # external_aad is empty. This array encoding is what must byte-match
    # the verifier's re-encoding (definite-length [text, bytes, bytes,
    # bytes] — standard CBOR, agrees across cbor2 / cbor-x).
    sig_structure_bytes = cbor2.dumps([SIG_STRUCTURE_CONTEXT, protected_bytes, b"", payload_bytes])

    signature = signer.sign(sig_structure_bytes)

    # COSE_Sign1 = [protected, unprotected(empty map), payload, signature]
    cose = cbor2.dumps([protected_bytes, {}, payload_bytes, signature])

    import base64

    return base64.urlsafe_b64encode(cose).rstrip(b"=").decode("ascii")
