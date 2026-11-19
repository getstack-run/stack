"""The local files of spec/credentials-files: what this client reads, what it writes and with which mode."""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from getstack import agent_auth
from getstack.auth import CredentialsFileAuth, credentials_lock

CREDENTIALS = {
    "client_id": "oclient_example",
    "refresh_token": "refresh-one",
    "issued_at": 1_790_000_000,
    "refresh_expires_at": 1_792_592_000,
    "operator_email": "owner@example.test",
    "scope": "agents:read",
}


def _write(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf8")
    return path


def test_a_file_that_cannot_sign_anyone_in_is_no_sign_in(tmp_path: Path) -> None:
    for body in (
        {},
        {"client_id": "x"},
        {"refresh_token": "x"},
        {"client_id": "", "refresh_token": "x"},
        {"client_id": "x", "refresh_token": 5},
        [],
        "text",
    ):
        path = _write(tmp_path / "credentials.json", body)
        with pytest.raises(RuntimeError):
            CredentialsFileAuth(credentials_path=path)


def test_a_file_with_a_client_and_a_refresh_token_is_read(tmp_path: Path) -> None:
    auth = CredentialsFileAuth(credentials_path=_write(tmp_path / "credentials.json", CREDENTIALS))
    assert auth.client_id == "oclient_example"
    assert auth.refresh_token == "refresh-one"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_the_rotated_refresh_token_is_written_back_for_the_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "credentials.json", CREDENTIALS)
    path.chmod(0o644)
    auth = CredentialsFileAuth(credentials_path=path, api_base_url="https://api.example.test")

    def fake_post(url: str, data: dict[str, str]) -> httpx.Response:
        assert url == "https://api.example.test/oauth/token"
        assert data == {"grant_type": "refresh_token", "refresh_token": "refresh-one", "client_id": "oclient_example"}
        return httpx.Response(
            200,
            json={"access_token": "access", "refresh_token": "refresh-two", "expires_in": 300},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    assert auth.get_headers() == {"Authorization": "Bearer access"}
    stored = json.loads(path.read_text(encoding="utf8"))
    assert stored["refresh_token"] == "refresh-two"
    # What the exchange did not change stays as it was.
    assert (
        stored["client_id"] == "oclient_example"
        and stored["operator_email"] == "owner@example.test"
        and stored["scope"] == "agents:read"
    )
    assert stored["refresh_expires_at"] > stored["issued_at"] >= CREDENTIALS["issued_at"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_enrolment_time_is_kept_as_whole_unix_seconds() -> None:
    assert agent_auth._unix_seconds("2026-10-24T09:30:00.000Z") == 1_792_834_200
    assert agent_auth._unix_seconds("2026-10-24T09:30:00+00:00") == 1_792_834_200
    assert isinstance(agent_auth._unix_seconds(None), int)
    assert isinstance(agent_auth._unix_seconds("not a time"), int)


def test_a_renewal_reads_the_file_again_after_it_holds_the_lock_and_releases_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "credentials.json", CREDENTIALS)
    auth = CredentialsFileAuth(credentials_path=path, api_base_url="https://api.example.test")
    # Another process rotated the token after this client read the file.
    _write(path, {**CREDENTIALS, "refresh_token": "refresh-from-another-process"})
    seen: list[str] = []

    def fake_post(url: str, data: dict[str, str]) -> httpx.Response:
        seen.append(data["refresh_token"])
        assert (tmp_path / "credentials.lock").read_text(encoding="utf8") == str(os.getpid())
        return httpx.Response(
            200,
            json={"access_token": "a", "refresh_token": "next", "expires_in": 300},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    auth.get_headers()
    assert seen == ["refresh-from-another-process"]
    assert not (tmp_path / "credentials.lock").exists()


def test_the_lock_waits_for_a_holder_and_takes_the_lock_of_a_dead_one(tmp_path: Path) -> None:
    lock = tmp_path / "credentials.lock"
    lock.write_text("12345", encoding="utf8")
    old = lock.stat().st_mtime - 60
    os.utime(lock, (old, old))
    with credentials_lock(tmp_path):
        assert lock.read_text(encoding="utf8") == str(os.getpid())
    assert not lock.exists()

    # A live holder: the lock is taken once it lets go.
    lock.write_text("999", encoding="utf8")
    threading.Timer(0.3, lambda: lock.unlink()).start()
    started = time.monotonic()
    with credentials_lock(tmp_path):
        assert time.monotonic() - started >= 0.25
    assert not lock.exists()
