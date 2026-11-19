"""SDK first-run browser-spawn bootstrap (Python).

Mirror of packages/sdk/src/browser-bootstrap.ts. When ``Stack()`` is
constructed with no api_key, no STACK_API_KEY env, and no
~/.stack/credentials.json — instead of raising, the SDK can spawn the
user's browser and run the OAuth Authorization Code + PKCE dance
itself.

Triggered ONLY when the process is interactive (TTY + not CI). In
production agent runtimes (Lambda, Vercel, K8s) the SDK falls through
to the standard "no credentials" error and the operator must set
STACK_API_KEY (or use agent_id mode).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
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
from pathlib import Path
from typing import Any

import httpx

DEFAULT_AUTH_TIMEOUT_S = 5 * 60  # matches the auth-code TTL


def _credentials_path() -> Path:
    return Path(os.path.expanduser("~")) / ".stack" / "credentials.json"


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def should_run_browser_bootstrap() -> bool:
    """Conservative gate: only spawn if we're at an interactive terminal."""
    if not sys.stdout.isatty():
        return False
    if os.environ.get("STACK_AUTH_INTERACTIVE", "").lower() == "false":
        return False
    return not os.environ.get("CI")


def browser_bootstrap(base_url: str) -> dict[str, Any]:
    """Run the full OAuth Authorization-Code + PKCE flow.

    Returns ``{"access_token", "refresh_token", "expires_in", "client_id"}``.
    Raises RuntimeError on any step failure.
    """
    base = base_url.rstrip("/")

    # 1. DCR a public PKCE client. We re-register with the loopback URI
    #    once we know the bound port (DCR is open; the second register
    #    supersedes for redirect_uri matching).
    name = f"STACK Python SDK on {socket.gethostname()[:40]}"

    # 2. Pick a free port + spin up the callback server first, so we can
    #    register the client with the actual loopback URI.
    code_holder: dict[str, Any] = {"code": None, "error": None, "expected_state": None}
    handler_event = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            params = urllib.parse.parse_qs(parsed.query)
            err = params.get("error", [None])[0]
            code = params.get("code", [None])[0]
            state = params.get("state", [None])[0]
            if err:
                code_holder["error"] = err
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px'>"
                    b"<h1>Sign-in failed</h1><p>You can close this tab.</p></body></html>"
                )
            elif not code or state != code_holder["expected_state"]:
                code_holder["error"] = "invalid callback (state mismatch or missing code)"
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px'><h1>Invalid callback</h1></body></html>"
                )
            else:
                code_holder["code"] = code
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:system-ui;padding:40px;text-align:center'>"
                    b"<h1>Signed in</h1><p>You can close this tab and return to your terminal.</p></body></html>"
                )
            handler_event.set()

        def log_message(self, *_args: object, **_kwargs: object) -> None:
            return  # silence access logs

    # Bind to port 0 to get a free port.
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        redirect_uri = f"http://127.0.0.1:{port}/callback"

        # DCR with the actual loopback URI.
        r = httpx.post(
            f"{base}/oauth/register",
            json={
                "client_name": name,
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "software_id": "getstackrun.sdk-python.bootstrap",
            },
            timeout=15.0,
        )
        if r.status_code != 201:
            raise RuntimeError(
                f"STACK SDK: client registration failed ({r.status_code}). "
                f"Try running `npx @getstackrun/cli auth login`."
            )
        client_id = r.json()["client_id"]

        # 3. PKCE pair + state.
        verifier = _b64url_no_pad(secrets.token_bytes(32))
        challenge = _b64url_no_pad(hashlib.sha256(verifier.encode()).digest())
        state = _b64url_no_pad(secrets.token_bytes(16))
        code_holder["expected_state"] = state

        scope = (
            "passports:read passports:write agents:read agents:write services:read "
            "services:connect credentials:read proxy:read proxy:write audit:read"
        )
        authorize_url = f"{base}/oauth/authorize?" + urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "resource": "https://api.getstack.run",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
            }
        )

        sys.stderr.write("\n  STACK SDK first-run sign-in\n")
        sys.stderr.write("  ──────────────────────────\n\n")
        sys.stderr.write("  Opening your browser to approve.\n")
        sys.stderr.write(f"  If it doesn't open, paste this URL:\n\n  {authorize_url}\n\n")

        # Best-effort.
        with contextlib.suppress(Exception):
            webbrowser.open(authorize_url)

        # 4. Wait for the callback.
        if not handler_event.wait(timeout=DEFAULT_AUTH_TIMEOUT_S):
            raise RuntimeError("Sign-in timed out (5 min). Re-run to try again.")
        if code_holder["error"]:
            raise RuntimeError(f"OAuth error: {code_holder['error']}")
        code = code_holder["code"]

        # 5. Exchange code for tokens.
        r2 = httpx.post(
            f"{base}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
            timeout=15.0,
        )
        if r2.status_code != 200:
            raise RuntimeError(f"STACK SDK: token exchange failed ({r2.status_code}) {r2.text}")
        tokens = r2.json()

        # 6. Persist for subsequent runs. Same file the CLI + the TS SDK write.
        path = _credentials_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        stored = {
            "client_id": client_id,
            "refresh_token": tokens["refresh_token"],
            "issued_at": int(time.time()),
            "refresh_expires_at": int(time.time()) + 30 * 24 * 60 * 60,
            "scope": scope,
        }
        # Created readable by the owner only: the refresh token is a bearer secret.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as stream:
            stream.write(json.dumps(stored, indent=2))
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)

        sys.stderr.write(f"  Signed in. Credentials saved to {path}\n\n")

        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "expires_in": tokens.get("expires_in", 300),
            "client_id": client_id,
        }
    finally:
        server.shutdown()
        server.server_close()
