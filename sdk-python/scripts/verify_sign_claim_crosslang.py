"""Cross-language COSE byte-compat proof for sign_claim_envelope.

Python signs claim envelopes; the JS SDK's cbor-x + node:crypto verify
logic (identical to @stack/vault AgentSigner.verifyPreSigned) must accept
them. This is the load-bearing guarantee that a customer_managed agent
signing claims in Python is accepted by STACK server-side.

Run from the repo root (needs the JS SDK's node_modules for cbor-x):
    python sdk-python/scripts/verify_sign_claim_crosslang.py

Exit 0 = all claim types round-tripped; non-zero = a byte-compat mismatch.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "sdk-python" / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from getstack.sign_claim import sign_claim_envelope  # noqa: E402

NODE_VERIFIER = r"""
import { readFileSync } from 'node:fs';
import { encode as cborEncode, decode as cborDecode } from 'cbor-x';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
const rows = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const getH = (h, k) => (h instanceof Map ? h.get(k) : h?.[k]);
let allPass = true;
for (const { cose, publicJwk, claim_type } of rows) {
  const [protectedBytes, , payloadBytes, sig] = cborDecode(Buffer.from(cose, 'base64url'));
  const pm = cborDecode(protectedBytes);
  const kidRaw = getH(pm, 4);
  const kid = kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : kidRaw;
  const ssb = cborEncode(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]);
  const valid = cryptoVerify(null, ssb, createPublicKey({ key: publicJwk, format: 'jwk' }), sig);
  const env = cborDecode(payloadBytes);
  const ok = valid && getH(pm, 1) === -8 && getH(pm, 16) === 'stack/claim+cose'
    && kid === 'agent:ag_cust:v1' && env.claim_type === claim_type;
  console.log((ok ? 'PASS' : 'FAIL') + ' ' + claim_type + ' sigValid=' + valid);
  if (!ok) allPass = false;
}
process.exit(allPass ? 0 : 1);
"""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main() -> int:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    x = _b64url(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
    priv_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": _b64url(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "x": x,
    }
    pub_jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}

    env = {
        "envelope_version": 1,
        "issuer": "op_cust",
        "subject": "s",
        "issued_at": 1778600000000,
        "claim_type": "intent_claim",
        "claim_version": 1,
        "payload": {"intent_type": "http_call"},
        "receipt": None,
        "co_signatures": [],
    }
    rows = []
    for ct in ["intent_claim", "intent_outcome", "detector_signal", "intent_denial", "intent_simulation"]:
        env["claim_type"] = ct
        rows.append(
            {
                "cose": sign_claim_envelope(env, private_key=priv_jwk, agent_id="ag_cust"),
                "publicJwk": pub_jwk,
                "claim_type": ct,
            }
        )

    # Node resolves modules relative to the SCRIPT FILE, so the verifier
    # must live inside packages/sdk/ for its cbor-x import to resolve. Write
    # it there transiently and clean up.
    sdk_dir = REPO / "packages" / "sdk"
    verifier_path = sdk_dir / "_crosslang_verify.mjs"
    data_path = sdk_dir / "_crosslang_rows.json"
    try:
        data_path.write_text(json.dumps(rows))
        verifier_path.write_text(NODE_VERIFIER)
        proc = subprocess.run(
            ["node", str(verifier_path), str(data_path)],
            cwd=str(sdk_dir),
            capture_output=True,
            text=True,
        )
        print(proc.stdout, end="")
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            print("\n  [FAIL] CROSS-LANGUAGE BYTE-COMPAT FAILED", file=sys.stderr)
            return proc.returncode
    finally:
        verifier_path.unlink(missing_ok=True)
        data_path.unlink(missing_ok=True)
    print("\n  [OK] Python-signed COSE verifies under the JS/vault logic for all claim types.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
