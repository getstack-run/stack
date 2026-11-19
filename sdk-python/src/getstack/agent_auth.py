"""agent-keypair runtime auth (Python).

Mirror of packages/sdk/src/agent-auth.ts. When ``Stack(agent_id=...)`` is
constructed, the SDK enters agent-runtime mode: every request is signed
with a fresh 60-second EdDSA JWT minted from the agent's local privkey
at ~/.stack/agents/<agent_id>.json.

First run: open the dashboard /sdk-bootstrap page in the user's browser
for explicit approval (interactive only — TTY + not CI), generate the
Ed25519 keypair locally, sign the API's challenge, POST /enroll with
the operator-approved enrollment ticket as Bearer. Persist privkey
locally (mode 0600). Subsequent runs read from disk.

Headless / CI runs (no TTY, or STACK_AUTH_INTERACTIVE=false) skip the
browser step and fall through to the developer's OAuth bearer (or
sk_live_* via STACK_API_KEY) for silent enrollment — same endpoints,
same proof-of-possession, no human in the loop.
"""

from __future__ import annotations

import base64
import contextlib
import http.server
import json
import os
import secrets
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, cast

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .auth import AuthStrategy
from .browser_bootstrap import should_run_browser_bootstrap

AGENT_JWT_TTL = 60
AGENT_JWT_ISSUER = "stack-sdk"
AGENT_JWT_AUDIENCE = "stack:agent"

ENROLLMENT_AUTH_TIMEOUT_S = 5 * 60  # matches enrollment-ticket TTL


def _dashboard_url(api_base_url: str) -> str:
    """Origin to which the SDK opens the browser for the approval screen.

    Override via STACK_DASHBOARD_URL for self-hosted/test environments.
    Dev shortcut: api on localhost ⇒ dashboard on :3100.
    """
    override = os.environ.get("STACK_DASHBOARD_URL")
    if override:
        return override
    if api_base_url.startswith(("http://127.0.0.1", "http://localhost")):
        return "http://localhost:3100"
    return "https://getstack.run"


def _ticket_via_browser_approval(agent_id: str, api_base_url: str) -> str:
    """Spawn a one-shot loopback HTTP listener, open the dashboard
    /sdk-bootstrap page in the user's browser, and return the ticket
    once the user approves. Raises RuntimeError on deny / timeout / any
    failure — caller decides whether to surface or fall back.
    """
    state = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")
    machine = socket.gethostname()[:80]
    proc_label = f"python {Path(sys.argv[0]).name}"[:80] if sys.argv else "python"

    holder: dict[str, object | None] = {"ticket": None, "error": None}
    handler_event = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/cb":
                self.send_response(404)
                self.end_headers()
                return
            params = urllib.parse.parse_qs(parsed.query)
            cb_state = params.get("state", [None])[0]
            err = params.get("error", [None])[0]
            ticket = params.get("ticket", [None])[0]
            if cb_state != state:
                holder["error"] = "state mismatch"
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px'><h1>State mismatch</h1></body></html>"
                )
            elif err:
                holder["error"] = err
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px'>"
                    b"<h1>Enrollment denied</h1><p>You can close this tab.</p></body></html>"
                )
            elif not ticket:
                holder["error"] = "missing ticket"
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px'><h1>Missing ticket</h1></body></html>"
                )
            else:
                holder["ticket"] = ticket
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px;text-align:center'>"
                    b"<h1>Approved</h1><p>You can close this tab and return to your terminal.</p></body></html>"
                )
            handler_event.set()

        def log_message(self, *_a: object, **_kw: object) -> None:
            return

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        callback = f"http://127.0.0.1:{port}/cb"
        dash = _dashboard_url(api_base_url)
        url = f"{dash}/sdk-bootstrap?" + urllib.parse.urlencode(
            {
                "agent_id": agent_id,
                "callback": callback,
                "state": state,
                "machine": machine,
                "process": proc_label,
            }
        )

        sys.stderr.write("\n  STACK SDK agent enrollment\n")
        sys.stderr.write("  ──────────────────────────\n\n")
        sys.stderr.write(f"  Approve in your browser: {url}\n\n")

        with contextlib.suppress(Exception):
            webbrowser.open(url)

        if not handler_event.wait(timeout=ENROLLMENT_AUTH_TIMEOUT_S):
            raise RuntimeError("enrollment approval timed out (5 min). Re-run to try again.")
        if holder["error"]:
            raise RuntimeError(f"enrollment {holder['error']}")
        ticket = holder["ticket"]
        if not isinstance(ticket, str):
            raise RuntimeError("enrollment callback produced no ticket")
        return ticket
    finally:
        server.shutdown()
        server.server_close()


def _unix_seconds(value: Any) -> int:
    """The API answers the enrolment time as ISO 8601; the file keeps whole unix seconds, as the other clients do."""
    if isinstance(value, str):
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        except ValueError:
            pass
    return int(time.time())


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _key_path(agent_id: str) -> Path:
    return Path(os.path.expanduser("~")) / ".stack" / "agents" / f"{agent_id}.json"


def _load_stored(agent_id: str) -> dict[str, Any] | None:
    path = _key_path(agent_id)
    if not path.exists():
        return None
    try:
        return cast("dict[str, Any] | None", json.loads(path.read_text(encoding="utf8")))
    except (OSError, json.JSONDecodeError):
        return None


def _persist_stored(agent_id: str, payload: dict[str, Any]) -> None:
    import tempfile

    path = _key_path(agent_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, pending = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf8") as stream:
            json.dump(payload, stream, indent=2)
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)
    # Windows / unsupported FS: ignore.
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def _generate_keypair() -> tuple[Ed25519PrivateKey, dict[str, Any], dict[str, Any]]:
    """Generate an Ed25519 keypair and return (privkey_obj, public_jwk,
    private_jwk_with_d)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url_no_pad(pub_raw)}
    private_jwk = {**public_jwk, "d": _b64url_no_pad(priv_raw)}
    return priv, public_jwk, private_jwk


def _privkey_from_jwk(jwk: dict[str, Any]) -> Ed25519PrivateKey:
    pad = "=" * (-len(jwk["d"]) % 4)
    raw = base64.urlsafe_b64decode(jwk["d"] + pad)
    return Ed25519PrivateKey.from_private_bytes(raw)


def _enroll(
    agent_id: str,
    base_url: str,
    bearer_provider: Callable[[], str],
) -> dict[str, Any]:
    """Run the proof-of-possession enrollment dance. Returns the stored
    payload (with private JWK) ready to persist.

    Two paths converge on the same /enrollment-challenge + /enroll calls:

      - Interactive: open the dashboard /sdk-bootstrap page in the user's
        browser, get a single-use enrollment ticket, use it as the bearer.
      - Headless: call ``bearer_provider`` (developer's OAuth or
        STACK_API_KEY) directly. No browser, no human in the loop.
    """
    if should_run_browser_bootstrap():
        try:
            bearer = _ticket_via_browser_approval(agent_id, base_url)
        except RuntimeError as e:
            raise RuntimeError(
                f"Browser approval for SDK agent enrollment failed ({e}). Fix the issue and re-run."
            ) from e
    else:
        bearer = bearer_provider()
    base = base_url.rstrip("/")

    # Step 1 — request challenge.
    r = httpx.post(
        f"{base}/v1/agents/{agent_id}/enrollment-challenge",
        headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
        timeout=15.0,
    )
    r.raise_for_status()
    challenge_body = r.json()
    challenge: str = challenge_body["challenge"]
    challenge_id: str = challenge_body["challenge_id"]

    # Step 2 — generate keypair locally.
    priv_obj, public_jwk, private_jwk = _generate_keypair()

    # Step 3 — sign the challenge bytes.
    sig = priv_obj.sign(challenge.encode("utf8"))
    signed_challenge = _b64url_no_pad(sig)

    # Step 4 — POST /enroll.
    r2 = httpx.post(
        f"{base}/v1/agents/{agent_id}/enroll",
        headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
        json={
            "public_key": public_jwk,
            "challenge_id": challenge_id,
            "signed_challenge": signed_challenge,
        },
        timeout=15.0,
    )
    r2.raise_for_status()
    enrolled = r2.json()

    return {
        "agent_id": agent_id,
        "publicKey": public_jwk,
        "privateKey": private_jwk,
        "enrolled_at": _unix_seconds(enrolled.get("enrolled_at")),
    }


def _sign_agent_jwt(stored: dict[str, Any], agent_id: str) -> str:
    """Mint a fresh 60-second EdDSA JWT signed with the agent privkey."""
    priv_obj = _privkey_from_jwk(stored["privateKey"])
    now = int(time.time())
    payload = {
        "iss": AGENT_JWT_ISSUER,
        "sub": agent_id,
        "aud": AGENT_JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + AGENT_JWT_TTL,
        "jti": f"aj_{now}_{os.urandom(6).hex()}",
    }
    # PyJWT accepts a raw cryptography Ed25519 key when algorithm='EdDSA'.
    return jwt.encode(payload, priv_obj, algorithm="EdDSA")


class AgentKeypairAuth(AuthStrategy):
    """agent-runtime auth strategy.

    Constructed with an agent_id and a fallback bearer provider (used
    only for the one-time enrollment dance). Once enrolled, every
    request mints a fresh 60-second JWT signed by the locally-stored
    privkey — the bearer provider is no longer consulted.
    """

    def __init__(
        self,
        agent_id: str,
        api_base_url: str,
        bearer_provider: Callable[[], str],
    ):
        self.agent_id = agent_id
        self.api_base_url = api_base_url
        self.bearer_provider = bearer_provider
        self._stored: dict[str, Any] | None = None

    def _ensure_stored(self) -> dict[str, Any]:
        if self._stored is not None:
            return self._stored
        stored = _load_stored(self.agent_id)
        if stored is None:
            stored = _enroll(self.agent_id, self.api_base_url, self.bearer_provider)
            _persist_stored(self.agent_id, stored)
        self._stored = stored
        return stored

    def get_headers(self) -> dict[str, str]:
        stored = self._ensure_stored()
        token = _sign_agent_jwt(stored, self.agent_id)
        return {"Authorization": f"Bearer {token}"}
