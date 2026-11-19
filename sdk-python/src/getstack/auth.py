"""Authentication strategies for the STACK SDK."""

from __future__ import annotations

import contextlib
import json
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

import httpx

LOCK_ACQUIRE_TIMEOUT_S = 5.0
LOCK_RETRY_INTERVAL_S = 0.05
LOCK_STALE_S = 30.0


@contextlib.contextmanager
def credentials_lock(directory: Path) -> Iterator[None]:
    """Hold `credentials.lock` in `directory` (spec/credentials-files, section 5).

    Renewing the sign-in rotates the refresh token, so two processes must not post the same one. The lock is an
    exclusive create holding the process id; one older than 30 seconds is a dead holder's. A client that cannot take
    it (a permission, the wait of 5 seconds) goes on without it. The caller reads the credentials file again once it
    holds it.
    """
    lock = directory / "credentials.lock"
    held = False
    deadline = time.monotonic() + LOCK_ACQUIRE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE_S:
                    with contextlib.suppress(OSError):
                        lock.unlink()
                    continue
            except FileNotFoundError:
                continue  # it went away between the failed create and the look: take it
            time.sleep(LOCK_RETRY_INTERVAL_S)
            continue
        except OSError:
            break
        with os.fdopen(fd, "w", encoding="utf8") as stream:
            stream.write(str(os.getpid()))
        held = True
        break
    try:
        yield
    finally:
        if held:
            with contextlib.suppress(OSError):
                lock.unlink()


class AuthStrategy(ABC):
    """Base class for auth strategies."""

    @abstractmethod
    def get_headers(self) -> dict[str, str]:
        """Return auth headers for API requests."""
        ...


class ApiKeyAuth(AuthStrategy):
    """Authenticate with a STACK API key (sk_live_...)."""

    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}


class SessionAuth(AuthStrategy):
    """Authenticate with a session JWT (dashboard integrations)."""

    def __init__(self, session_token: str):
        self.session_token = session_token

    def get_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.session_token}"}


class OAuthAuth(AuthStrategy):
    """Authenticate with OAuth tokens. Auto-refreshes when expired.

    For OAuth 2.1 public PKCE clients (the default), pass
       ``client_secret=""``. The token endpoint accepts public clients with
       no secret.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        access_token: str,
        refresh_token: str,
        token_endpoint: str = "https://api.getstack.run/oauth/token",
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_endpoint = token_endpoint
        self.expires_at: float | None = None

    def get_headers(self) -> dict[str, str]:
        if self.expires_at and time.time() > self.expires_at - 30:
            self._refresh()
        return {"Authorization": f"Bearer {self.access_token}"}

    def _refresh(self) -> None:
        """Exchange refresh_token for a new access_token."""
        body: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            body["client_secret"] = self.client_secret
        resp = httpx.post(self.token_endpoint, data=body)
        resp.raise_for_status()
        data = resp.json()
        self.access_token = data["access_token"]
        self.refresh_token = data.get("refresh_token", self.refresh_token)
        self.expires_at = time.time() + data.get("expires_in", 300)


class CredentialsFileAuth(AuthStrategy):
    """Read OAuth credentials from ~/.stack/credentials.json.

    Mirror of the TS SDK's lazy refresh-from-file path. The CLI's
    ``stack-cli auth login`` (Device flow) writes this file; both SDKs
    read it. On every request we exchange the stored refresh for a fresh
    access token (5-minute TTL, rotation-on-use), then cache it in
    memory until 30 seconds before expiry.

    Raises ``FileNotFoundError`` (re-raised as ``RuntimeError``) on
    construction if the file is missing — callers should fall back to
    ``ApiKeyAuth`` from ``STACK_API_KEY`` first.
    """

    def __init__(
        self,
        credentials_path: Path | None = None,
        api_base_url: str = "https://api.getstack.run",
    ):
        self.path = credentials_path or (Path(os.path.expanduser("~")) / ".stack" / "credentials.json")
        self.token_endpoint = f"{api_base_url.rstrip('/')}/oauth/token"
        if not self.path.exists():
            raise RuntimeError(f"No STACK credentials at {self.path}. Run `npx @getstackrun/cli auth login`.")
        self._load()
        self._access_token: str | None = None
        self._access_expires_at: float = 0.0

    def _load(self) -> None:
        with self.path.open("r", encoding="utf8") as f:
            data = json.load(f)
        # A file that cannot sign anyone in is no sign-in at all (spec/credentials-files).
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("client_id"), str)
            or not data["client_id"]
            or not isinstance(data.get("refresh_token"), str)
            or not data["refresh_token"]
        ):
            raise RuntimeError(
                f"STACK credentials at {self.path} have no client_id and refresh_token. Run `stack-cli auth login`."
            )
        self.client_id: str = data["client_id"]
        self.refresh_token: str = data["refresh_token"]
        self.scope: str = data.get("scope", "")

    def _refresh(self) -> None:
        with credentials_lock(self.path.parent):
            self._refresh_locked()

    def _refresh_locked(self) -> None:
        # Another process may have rotated the token while this one waited for the lock: read the file again.
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            self._load()
        resp = httpx.post(
            self.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": self.client_id,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._access_expires_at = time.time() + data.get("expires_in", 300)
        self.refresh_token = data.get("refresh_token", self.refresh_token)
        # Persist the rotated refresh.
        try:
            current = json.loads(self.path.read_text(encoding="utf8"))
            current["refresh_token"] = self.refresh_token
            current["issued_at"] = int(time.time())
            current["refresh_expires_at"] = int(time.time()) + 30 * 24 * 60 * 60
            # Created readable by the owner only: the refresh token is a bearer secret.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as stream:
                stream.write(json.dumps(current, indent=2))
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get_headers(self) -> dict[str, str]:
        if not self._access_token or time.time() > self._access_expires_at - 30:
            self._refresh()
        assert self._access_token is not None
        return {"Authorization": f"Bearer {self._access_token}"}
