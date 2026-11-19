"""Agent wallet key helpers: byte-compatible with packages/sdk/src/wallet-key.ts."""

from __future__ import annotations

import base64
import copy
import pickle
import re
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack.wallet_key import (
    AgentWalletKey,
    WalletKeyInSandboxError,
    WalletPaymentTarget,
    canonicalize,
    generate_agent_wallet_key,
    load_agent_wallet_key,
    sign_wallet_payment,
    wallet_payment_authorization_payload,
)

# The regexes the API applies: wallet.agent_public_key (agent-account.ts
# OpenAgentAccountInput) and agent_signature (WalletPaymentInput).
PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{86,90}={0,2}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9+/]{60,120}={0,2}$")

TYPED_DATA = {
    "primary_type": "TransferWithAuthorization",
    "types": {
        "TransferWithAuthorization": [{"name": "from", "type": "address"}],
        "EIP712Domain": [{"name": "name", "type": "string"}],
    },
    "message": {
        "value": "1000000",
        "validBefore": 1999999999,
        "validAfter": 0,
        "to": "0xdef",
        "nonce": "0x01",
        "from": "0xabc",
    },
    "domain": {
        "version": "2",
        "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "name": "USD Coin",
        "chainId": 8453,
    },
}

# Derived by hand from the TS rules: keys sorted by UTF-16 code unit at every
# level, no whitespace, integers as JSON integers, the wallet id passed through
# encodeURIComponent ("/" -> %2F, " " -> %20).
EXPECTED_PAYLOAD = (
    '{"body":{"method":"eth_signTypedData_v4","params":{"typed_data":{'
    '"domain":{"chainId":8453,"name":"USD Coin","verifyingContract":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",'
    '"version":"2"},'
    '"message":{"from":"0xabc","nonce":"0x01","to":"0xdef","validAfter":0,"validBefore":1999999999,'
    '"value":"1000000"},'
    '"primary_type":"TransferWithAuthorization",'
    '"types":{"EIP712Domain":[{"name":"name","type":"string"}],'
    '"TransferWithAuthorization":[{"name":"from","type":"address"}]}}}},'
    '"headers":{"privy-app-id":"app_test"},'
    '"method":"POST",'
    '"url":"https://api.privy.io/v1/wallets/w%2F1%20x/rpc",'
    '"version":1}'
)

TARGET = WalletPaymentTarget(app_id="app_test", wallet_id="w/1 x", typed_data=TYPED_DATA)


@pytest.fixture(autouse=True)
def _outside_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STACK_SANDBOX", raising=False)


def _verify(public_key_b64: str, signature_b64: str, payload: str) -> None:
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(public_key_b64))
    public_key.verify(base64.b64decode(signature_b64), payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))


def test_authorization_payload_matches_the_typescript_canonical_form() -> None:
    assert wallet_payment_authorization_payload(TARGET) == EXPECTED_PAYLOAD


def test_canonicalize_follows_rfc8785_for_the_supported_values() -> None:
    assert canonicalize({"b": 1, "a": [True, None, 'x\n\u0001é"\\'], "B": -0.0, "c": False}) == (
        '{"B":0,"a":[true,null,"x\\n\\u0001é\\"\\\\"],"b":1,"c":false}'
    )
    # UTF-16 code unit order, as JS sorts: U+1F600 is D83D DE00, below U+FF61.
    assert canonicalize({"｡": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"｡":1}'
    # A lone surrogate is escaped, as JSON.stringify does.
    assert canonicalize("\ud800") == '"\\ud800"'
    assert canonicalize(2.0) == "2"
    assert canonicalize(2**53 - 1) == "9007199254740991"


@pytest.mark.parametrize("value", [1.5, 2**53, -(2**53), float("nan"), float("inf")])
def test_canonicalize_refuses_non_safe_integers(value: float) -> None:
    with pytest.raises(TypeError, match="only integers"):
        canonicalize({"amount": value})


@pytest.mark.parametrize("value", [{1: "x"}, {"a": {1, 2}}, b"bytes"])
def test_canonicalize_refuses_unsupported_values(value: object) -> None:
    with pytest.raises(TypeError):
        canonicalize(value)


def test_generated_key_signs_a_payment_that_verifies_with_its_public_key() -> None:
    key = generate_agent_wallet_key()
    assert PUBLIC_KEY_RE.match(key.public_key)
    raw = base64.b64decode(key.public_key)
    assert len(raw) == 65 and raw[0] == 0x04

    body = sign_wallet_payment(key, TARGET)
    assert set(body) == {"typed_data", "agent_signature"}
    assert body["typed_data"] is TYPED_DATA
    assert SIGNATURE_RE.match(body["agent_signature"])
    _verify(key.public_key, body["agent_signature"], EXPECTED_PAYLOAD)


def test_export_and_load_round_trip() -> None:
    key = generate_agent_wallet_key()
    exported = key.export_private_key()
    assert exported.startswith("wallet-auth:")
    der = base64.b64decode(exported[len("wallet-auth:") :])
    loaded = load_agent_wallet_key(exported)
    assert loaded.public_key == key.public_key
    assert loaded.export_private_key() == exported
    _verify(key.public_key, loaded.sign("payload"), "payload")
    # PKCS#8 DER, as Node exports it.
    expected_der = loaded._private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    assert der == expected_der


def test_load_refuses_keys_in_the_wrong_form() -> None:
    with pytest.raises(TypeError, match="wallet-auth: form"):
        load_agent_wallet_key("MIGHAgEAMBMG")
    with pytest.raises(TypeError, match="not a valid PKCS#8 key"):
        load_agent_wallet_key("wallet-auth:" + base64.b64encode(b"not a key").decode())
    other_curve = ec.generate_private_key(ec.SECP384R1())
    der = other_curve.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    with pytest.raises(TypeError, match="must be P-256"):
        load_agent_wallet_key("wallet-auth:" + base64.b64encode(der).decode())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = rsa_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    with pytest.raises(TypeError, match="must be P-256"):
        load_agent_wallet_key("wallet-auth:" + base64.b64encode(der).decode())


def test_key_never_shows_its_private_half() -> None:
    key = generate_agent_wallet_key()
    secret = key.export_private_key()[len("wallet-auth:") :]
    assert repr(key) == "[AgentWalletKey]"
    assert str(key) == "[AgentWalletKey]"
    assert f"{key}" == "[AgentWalletKey]"
    assert secret not in repr(key)
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(key)
    with pytest.raises(TypeError, match="cannot be pickled"):
        copy.deepcopy(key)
    assert not hasattr(key, "__dict__")


def test_constructor_refuses_a_non_p256_key() -> None:
    with pytest.raises(TypeError, match="must be P-256"):
        AgentWalletKey(ec.generate_private_key(ec.SECP384R1()))


@pytest.mark.parametrize("flag", ["1", "true", "false", "yes", " "])
def test_every_entry_point_refuses_inside_the_sandbox(monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    key = generate_agent_wallet_key()
    exported = key.export_private_key()
    monkeypatch.setenv("STACK_SANDBOX", flag)
    with pytest.raises(WalletKeyInSandboxError):
        generate_agent_wallet_key()
    with pytest.raises(WalletKeyInSandboxError):
        load_agent_wallet_key(exported)
    with pytest.raises(WalletKeyInSandboxError):
        key.sign("payload")
    with pytest.raises(WalletKeyInSandboxError):
        key.export_private_key()
    with pytest.raises(WalletKeyInSandboxError):
        sign_wallet_payment(key, TARGET)
    # The public half and the payload hold nothing secret.
    assert PUBLIC_KEY_RE.match(key.public_key)
    assert wallet_payment_authorization_payload(TARGET) == EXPECTED_PAYLOAD


@pytest.mark.parametrize("flag", ["", "0"])
def test_empty_or_zero_flag_counts_as_outside(monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    monkeypatch.setenv("STACK_SANDBOX", flag)
    key = generate_agent_wallet_key()
    _verify(key.public_key, key.sign("x"), "x")


def test_sandbox_error_names_the_reason() -> None:
    assert "no machine of STACK may make or keep it" in str(WalletKeyInSandboxError())
