"""The agent's wallet key: the wallet's only signer.

The key pair is generated and kept on the agent's side; only the public half
goes into the open request (``wallet.agent_public_key``). To pay, the agent
signs Privy's signing request with this key and sends the signature to STACK,
which checks its controls and then passes the request to Privy. STACK holds no
key to any wallet.

The key must never exist inside STACK's sandbox: STACK runs that machine, and
no machine of STACK may make or keep it. Every entry point refuses when
``STACK_SANDBOX`` is set (the sandbox sets it).

Byte-compatible with ``packages/sdk/src/wallet-key.ts``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import quote

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
)

AUTHORIZATION_KEY_PREFIX = "wallet-auth:"
PRIVY_API_BASE = "https://api.privy.io"
_MAX_SAFE_INTEGER = 2**53 - 1
_REDACTED = "[AgentWalletKey]"
# encodeURIComponent leaves A-Z a-z 0-9 - _ . ! ~ * ' ( ) as they are.
_URI_COMPONENT_SAFE = "!~*'()"
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


class WalletKeyInSandboxError(Exception):
    """Raised when a wallet key is created, loaded or used inside the STACK sandbox."""

    def __init__(self) -> None:
        super().__init__(
            "Refusing to load or create a wallet key inside the STACK sandbox. The agent wallet key stays "
            "on your own machine; no machine of STACK may make or keep it."
        )


def _assert_outside_sandbox() -> None:
    flag = os.environ.get("STACK_SANDBOX")
    # Fail closed: any value other than empty or "0" counts as inside.
    if flag is not None and flag not in ("", "0"):
        raise WalletKeyInSandboxError()


class AgentWalletKey:
    """A P-256 wallet key. ``repr`` and ``str`` never show the private half, and it cannot be pickled."""

    __slots__ = ("_private_key", "_public_key")

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise TypeError("wallet key must be P-256")
        self._private_key = private_key
        point = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self._public_key = base64.b64encode(point).decode("ascii")

    @property
    def public_key(self) -> str:
        """Base64 uncompressed P-256 point: the ``wallet.agent_public_key`` of the open request."""
        return self._public_key

    def sign(self, payload: str) -> str:
        """Sign a Privy authorization payload; base64 DER ECDSA P-256 SHA-256."""
        _assert_outside_sandbox()
        signature = self._private_key.sign(payload.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode("ascii")

    def export_private_key(self) -> str:
        """The private key in Privy's ``wallet-auth:`` form, for your own secret store."""
        _assert_outside_sandbox()
        der = self._private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        return AUTHORIZATION_KEY_PREFIX + base64.b64encode(der).decode("ascii")

    def __repr__(self) -> str:
        return _REDACTED

    def __str__(self) -> str:
        return _REDACTED

    def __reduce__(self) -> NoReturn:
        raise TypeError("AgentWalletKey cannot be pickled or copied; store export_private_key() in a secret store")


def generate_agent_wallet_key() -> AgentWalletKey:
    """Create a new agent wallet key pair on this machine."""
    _assert_outside_sandbox()
    return AgentWalletKey(ec.generate_private_key(ec.SECP256R1()))


def load_agent_wallet_key(private_key: str) -> AgentWalletKey:
    """Load a key saved with ``export_private_key()``."""
    _assert_outside_sandbox()
    if not isinstance(private_key, str) or not private_key.startswith(AUTHORIZATION_KEY_PREFIX):
        raise TypeError("wallet key must be in wallet-auth: form")
    try:
        der = base64.b64decode(private_key[len(AUTHORIZATION_KEY_PREFIX) :], validate=True)
        key = load_der_private_key(der, password=None)
    except (binascii.Error, ValueError, TypeError, UnsupportedAlgorithm):
        raise TypeError("wallet key is not a valid PKCS#8 key") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("wallet key must be P-256")
    return AgentWalletKey(key)


def _json_string(value: str) -> str:
    # JSON.stringify semantics: a surrogate pair is one character, a lone
    # surrogate is escaped as \\uXXXX (lower-case hex).
    joined = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
    return _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", json.dumps(joined, ensure_ascii=False))


def _utf16_order(key: str) -> bytes:
    # JS sorts object keys by UTF-16 code unit; big-endian bytes compare the same way.
    return key.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> str:
    """RFC 8785 canonical JSON for the strings, integers, arrays and objects a payment carries."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not value.is_integer():
            raise TypeError("only integers are supported in a wallet payment")
        if abs(value) > _MAX_SAFE_INTEGER:
            raise TypeError("only integers are supported in a wallet payment")
        return str(int(value))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise TypeError("wallet payment object keys must be strings")
        keys = sorted(value, key=_utf16_order)
        return "{" + ",".join(f"{_json_string(key)}:{canonicalize(value[key])}" for key in keys) + "}"
    raise TypeError("unsupported value in a wallet payment")


@dataclass(frozen=True)
class WalletPaymentTarget:
    """Where a payment goes and what it is.

    ``app_id`` and ``wallet_id`` come from the account's wallet piece details
    (``privy_app_id`` and ``wallet_id``). ``typed_data`` is the EIP-712
    TransferWithAuthorization (x402 style) as Privy takes it: domain, types,
    primary_type, message.
    """

    app_id: str
    wallet_id: str
    typed_data: Mapping[str, Any]


def wallet_payment_authorization_payload(target: WalletPaymentTarget) -> str:
    """The exact string the agent signs: Privy's authorization payload for the signing request."""
    return canonicalize(
        {
            "version": 1,
            "method": "POST",
            "url": f"{PRIVY_API_BASE}/v1/wallets/{quote(target.wallet_id, safe=_URI_COMPONENT_SAFE)}/rpc",
            "body": {"method": "eth_signTypedData_v4", "params": {"typed_data": target.typed_data}},
            "headers": {"privy-app-id": target.app_id},
        }
    )


def sign_wallet_payment(key: AgentWalletKey, target: WalletPaymentTarget) -> dict[str, Any]:
    """The body for ``POST /v1/accounts/:id/wallet/payments`` (``stack.accounts.wallet.pay``)."""
    _assert_outside_sandbox()
    return {"typed_data": target.typed_data, "agent_signature": key.sign(wallet_payment_authorization_payload(target))}
