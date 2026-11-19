"""COSE_Sign1 claim-signing tests (sign_claim_envelope).

Two levels of proof:

1. Python self-verify (this file) — signs an envelope and verifies the
   Ed25519 signature over the reconstructed Sig_structure, proving the
   signer produces an internally-consistent COSE_Sign1.

2. Cross-language byte-compat (sdk-python/scripts/verify_sign_claim_crosslang.py +
   a Node verifier) — Python signs, the JS SDK's cbor-x + node:crypto
   verify logic (identical to @stack/vault AgentSigner.verifyPreSigned)
   accepts the signature. Proven for all 5 claim types. This is the load-
   bearing guarantee: cbor2 and cbor-x agree on the Sig_structure wire
   bytes, so a customer_managed agent signing in Python is accepted by
   STACK server-side.

Run: python -m pytest sdk-python/tests/  (or python sdk-python/tests/test_sign_claim.py)
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from getstack.sign_claim import (
    COSE_ALG_EDDSA,
    COSE_HEADER_ALG,
    COSE_HEADER_KID,
    COSE_HEADER_TYP,
    STACK_CLAIM_TYP,
    sign_claim_envelope,
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _keypair() -> tuple[dict, Ed25519PrivateKey]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": _b64url(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "x": _b64url(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
    }
    return jwk, priv


def _envelope(claim_type: str = "intent_claim") -> dict:
    return {
        "envelope_version": 1,
        "issuer": "op_cust",
        "subject": "stack://operator/op_cust/passport/ppt_abc",
        "issued_at": 1778600000000,
        "claim_type": claim_type,
        "claim_version": 1,
        "payload": {"intent_type": "http_call", "target": "https://api.example.com"},
        "receipt": None,
        "co_signatures": [],
    }


def _verify_cose(cose_b64: str, priv: Ed25519PrivateKey) -> dict:
    """Decode a COSE_Sign1 and verify the Ed25519 signature over the
    reconstructed Sig_structure — the same check @stack/vault does."""
    cose = cbor2.loads(_b64url_decode(cose_b64))
    assert isinstance(cose, list) and len(cose) == 4, "COSE_Sign1 must be a 4-element array"
    protected_bytes, _unprotected, payload_bytes, signature = cose

    header = cbor2.loads(protected_bytes)
    assert header[COSE_HEADER_ALG] == COSE_ALG_EDDSA
    assert header[COSE_HEADER_TYP] == STACK_CLAIM_TYP
    kid = header[COSE_HEADER_KID]
    kid_str = kid.decode() if isinstance(kid, (bytes, bytearray)) else kid

    sig_structure = cbor2.dumps(["Signature1", protected_bytes, b"", payload_bytes])
    # raises InvalidSignature on mismatch
    priv.public_key().verify(signature, sig_structure)

    return {"kid": kid_str, "envelope": cbor2.loads(payload_bytes)}


def test_signs_and_self_verifies():
    jwk, priv = _keypair()
    cose = sign_claim_envelope(_envelope(), private_key=jwk, agent_id="ag_cust")
    assert isinstance(cose, str) and cose
    result = _verify_cose(cose, priv)
    assert result["kid"] == "agent:ag_cust:v1"
    assert result["envelope"]["claim_type"] == "intent_claim"
    assert result["envelope"]["payload"]["intent_type"] == "http_call"


def test_all_standard_claim_types():
    jwk, priv = _keypair()
    for ct in ["intent_claim", "intent_outcome", "detector_signal", "intent_denial", "intent_simulation"]:
        cose = sign_claim_envelope(_envelope(ct), private_key=jwk, agent_id="ag_cust")
        result = _verify_cose(cose, priv)
        assert result["envelope"]["claim_type"] == ct


def test_wrong_key_does_not_verify():
    from cryptography.exceptions import InvalidSignature

    jwk, _ = _keypair()
    _, other_priv = _keypair()
    cose = sign_claim_envelope(_envelope(), private_key=jwk, agent_id="ag_cust")
    raised = False
    try:
        _verify_cose(cose, other_priv)
    except InvalidSignature:
        raised = True
    assert raised, "a different key must NOT verify"


def test_rejects_unsupported_alg():
    jwk, _ = _keypair()
    raised = False
    try:
        sign_claim_envelope(_envelope(), private_key=jwk, agent_id="ag_cust", alg="ML-DSA-65")
    except ValueError:
        raised = True
    assert raised


if __name__ == "__main__":
    test_signs_and_self_verifies()
    test_all_standard_claim_types()
    test_wrong_key_does_not_verify()
    test_rejects_unsupported_alg()
    print("all sign_claim tests passed")
