"""Agent drive calls: request shapes, sync and async alike, and the refusals made before any request."""

from __future__ import annotations

import asyncio
import inspect
import io
import json
import sys
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack import AsyncDriveService, DriveService
from getstack import drive as drive_module
from getstack._async.dropoffs import AsyncDropoffService
from getstack.auth import ApiKeyAuth
from getstack.client import AsyncHttpClient, HttpClient
from getstack.drive import content_type_for
from getstack.dropoffs import DropoffService
from getstack.errors import StackError

FILE = "drv_one/two"
Q = "drv_one%2Ftwo"
PASSPORT = {"X-Passport-Token": "ppt"}


class Capture:
    """Records (method, path, json, params, headers) of every call, answering what the API would."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any, Any, Any]] = []

    def _record(self, method: str, path: str, json: Any, params: Any, headers: Any) -> Any:
        self.calls.append((method, path, json, params, headers))
        return {"links": [{"id": "dsl_1"}]} if path.endswith("/links") and method == "GET" else {"ok": True}

    def request(self, method: str, path: str, json: Any = None, params: Any = None, extra_headers: Any = None) -> Any:
        return self._record(method, path, json, params, extra_headers)

    def get(self, path: str, params: Any = None, extra_headers: Any = None) -> Any:
        return self._record("GET", path, None, params, extra_headers)

    def post(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:
        return self._record("POST", path, json, None, extra_headers)

    def delete(self, path: str, extra_headers: Any = None) -> Any:
        return self._record("DELETE", path, None, None, extra_headers)


class AsyncCapture(Capture):
    async def request(  # type: ignore[override]
        self, method: str, path: str, json: Any = None, params: Any = None, extra_headers: Any = None
    ) -> Any:
        return super().request(method, path, json, params, extra_headers)

    async def get(self, path: str, params: Any = None, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().get(path, params, extra_headers)

    async def post(self, path: str, json: Any = None, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().post(path, json, extra_headers)

    async def delete(self, path: str, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().delete(path, extra_headers)


EXPECTED = [
    (
        "POST",
        "/v1/drive/files",
        {"name": "notes.md", "content_type": "text/markdown", "content_text": "# Notes"},
        None,
        None,
    ),
    (
        "POST",
        "/v1/drive/files",
        {
            "name": "notes.md",
            "content_type": "text/markdown",
            "content_text": "# Notes",
            "visibility": "account",
            "expires_in_seconds": 3600,
        },
        None,
        PASSPORT,
    ),
    ("GET", "/v1/drive/files", None, None, None),
    ("GET", "/v1/drive/files", None, {"limit": 10, "cursor": "abc"}, PASSPORT),
    ("GET", f"/v1/drive/files/{Q}", None, None, None),
    ("GET", f"/v1/drive/files/{Q}/content", None, None, PASSPORT),
    ("PATCH", f"/v1/drive/files/{Q}", {"visibility": "agent", "expires_in_seconds": 60}, None, None),
    ("PATCH", f"/v1/drive/files/{Q}", {"expires_in_seconds": None}, None, PASSPORT),
    ("POST", f"/v1/drive/files/{Q}/copy", {}, None, None),
    (
        "POST",
        f"/v1/drive/files/{Q}/copy",
        {"name": "kept.pdf", "visibility": "account", "expires_in_seconds": 86400},
        None,
        PASSPORT,
    ),
    ("DELETE", f"/v1/drive/files/{Q}", None, None, None),
    ("POST", f"/v1/drive/files/{Q}/links", {}, None, None),
    ("POST", f"/v1/drive/files/{Q}/links", {"ttl_seconds": 600, "max_downloads": 2}, None, PASSPORT),
    ("GET", f"/v1/drive/files/{Q}/links", None, None, None),
    ("DELETE", f"/v1/drive/files/{Q}/links/dsl_a%2Fb", None, None, PASSPORT),
]


def _drive_sync(drive: DriveService) -> None:
    drive.upload("notes.md", "text/markdown", content_text="# Notes")
    drive.upload(
        "notes.md",
        "text/markdown",
        content_text="# Notes",
        visibility="account",
        expires_in_seconds=3600,
        passport_token="ppt",
    )
    drive.list()
    drive.list(limit=10, cursor="abc", passport_token="ppt")
    drive.get(FILE)
    drive.read(FILE, passport_token="ppt")
    drive.update(FILE, visibility="agent", expires_in_seconds=60)
    drive.update(FILE, remove_expiry=True, passport_token="ppt")
    drive.copy(FILE)
    drive.copy(FILE, name="kept.pdf", visibility="account", expires_in_seconds=86400, passport_token="ppt")
    drive.delete(FILE)
    drive.share(FILE)
    drive.share(FILE, ttl_seconds=600, max_downloads=2, passport_token="ppt")
    assert drive.links(FILE) == [{"id": "dsl_1"}]
    drive.revoke_link(FILE, "dsl_a/b", passport_token="ppt")


async def _drive_async(drive: AsyncDriveService) -> None:
    await drive.upload("notes.md", "text/markdown", content_text="# Notes")
    await drive.upload(
        "notes.md",
        "text/markdown",
        content_text="# Notes",
        visibility="account",
        expires_in_seconds=3600,
        passport_token="ppt",
    )
    await drive.list()
    await drive.list(limit=10, cursor="abc", passport_token="ppt")
    await drive.get(FILE)
    await drive.read(FILE, passport_token="ppt")
    await drive.update(FILE, visibility="agent", expires_in_seconds=60)
    await drive.update(FILE, remove_expiry=True, passport_token="ppt")
    await drive.copy(FILE)
    await drive.copy(FILE, name="kept.pdf", visibility="account", expires_in_seconds=86400, passport_token="ppt")
    await drive.delete(FILE)
    await drive.share(FILE)
    await drive.share(FILE, ttl_seconds=600, max_downloads=2, passport_token="ppt")
    assert await drive.links(FILE) == [{"id": "dsl_1"}]
    await drive.revoke_link(FILE, "dsl_a/b", passport_token="ppt")


def test_sync_drive_wire_contract() -> None:
    capture = Capture()
    _drive_sync(DriveService(capture))  # type: ignore[arg-type]
    assert capture.calls == EXPECTED


def test_async_drive_wire_contract() -> None:
    capture = AsyncCapture()
    asyncio.run(_drive_async(AsyncDriveService(capture)))  # type: ignore[arg-type]
    assert capture.calls == EXPECTED


@pytest.mark.parametrize(
    "call",
    [
        lambda d: d.upload("a.txt", "text/plain"),
        lambda d: d.upload("a.txt", "text/plain", content_text="x", content=b"x"),
        lambda d: d.update(FILE),
        lambda d: d.update(FILE, expires_in_seconds=60, remove_expiry=True),
    ],
)
def test_refuses_a_bad_request_before_any_request(call: Any) -> None:
    capture = Capture()
    with pytest.raises(ValueError):
        call(DriveService(capture))  # type: ignore[arg-type]
    assert capture.calls == []


class DropoffCapture:
    def __init__(self) -> None:
        self.body: dict[str, Any] | None = None

    def post(self, path: str, json: dict[str, Any] | None = None, extra_headers: Any = None) -> Any:
        self.body = json
        return {}


class AsyncDropoffCapture(DropoffCapture):
    async def post(self, path: str, json: dict[str, Any] | None = None, extra_headers: Any = None) -> Any:  # type: ignore[override]
        return super().post(path, json, extra_headers)


def test_deposit_hands_drive_files_over_on_both_clients() -> None:
    sync = DropoffCapture()
    DropoffService(sync).deposit("dof_1", {"note": "x"}, "agt_a", drive_files=["drv_a", "drv_b"])  # type: ignore[arg-type]
    assert sync.body == {"agent_id": "agt_a", "payload": {"note": "x"}, "drive_files": ["drv_a", "drv_b"]}

    not_async = AsyncDropoffCapture()
    asyncio.run(AsyncDropoffService(not_async).deposit("dof_1", {"note": "x"}, "agt_a", drive_files=["drv_a"]))  # type: ignore[arg-type]
    assert not_async.body == {"agent_id": "agt_a", "payload": {"note": "x"}, "drive_files": ["drv_a"]}

    plain = DropoffCapture()
    DropoffService(plain).deposit("dof_1", {"note": "x"}, "agt_a")  # type: ignore[arg-type]
    assert plain.body == {"agent_id": "agt_a", "payload": {"note": "x"}}


# Uploads in one request. A fake STACK answers through httpx's MockTransport, so the real HTTP clients run end to
# end and the requests can be read back.

API = "https://api.test"
LINK_TOKEN = "SECRETLINKTOKEN"
LINK_URL = f"{API}/v1/drive/uploads/{LINK_TOKEN}"
DATA = bytes(range(25))
FILE_VIEW = {"id": "drv_big", "name": "big.zip", "size_bytes": 25}
LINK_VIEW = {
    "id": "dul_1",
    "url": LINK_URL,
    "method": "PUT",
    "name": "big.zip",
    "content_type": "application/zip",
    "max_bytes": 1073741824,
    "expires_at": "2026-10-30T12:30:00.000Z",
}


def api_error(status: int, code: str, details: dict[str, Any] | None = None) -> Callable[[], httpx.Response]:
    return lambda: httpx.Response(
        status, json={"error": {"code": code, "message": code.lower(), "details": details or {}}}
    )


class FakeStack:
    """Records every request (method, path, query, headers, body) and answers each as the API would."""

    def __init__(self, refuse: Callable[[], httpx.Response] | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.refuse = refuse

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.url.params),
                "headers": request.headers,
                "body": request.read(),
                "url": str(request.url),
            }
        )
        if self.refuse is not None:
            return self.refuse()
        if request.url.path == "/v1/drive/uploads" and request.method == "POST":
            return httpx.Response(201, json=LINK_VIEW)
        return httpx.Response(201, json=FILE_VIEW)

    @property
    def only(self) -> dict[str, Any]:
        assert len(self.requests) == 1
        return self.requests[0]


class Rig:
    """One drive service, sync or async, on a fake STACK; ``call`` runs a method either way."""

    def __init__(self, kind: str, fake: FakeStack) -> None:
        self.fake = fake
        auth = ApiKeyAuth("sk_test_secret")
        if kind == "sync":
            # Built without __init__, which would load a TLS context the mock transport never uses.
            client = object.__new__(HttpClient)
            client.auth, client.base_url = auth, API
            client._client = httpx.Client(transport=httpx.MockTransport(fake.handle))
            self.drive: Any = DriveService(client)
        else:
            aclient = object.__new__(AsyncHttpClient)
            aclient.auth, aclient.base_url = auth, API
            aclient._client = httpx.AsyncClient(transport=httpx.MockTransport(fake.handle))
            self.drive = AsyncDriveService(aclient)

    def call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        result = getattr(self.drive, name)(*args, **kwargs)
        return asyncio.run(result) if inspect.iscoroutine(result) else result


@pytest.fixture(params=["sync", "async"])
def rig(request: pytest.FixtureRequest) -> Rig:
    return Rig(request.param, FakeStack())


class CountingFile(io.BytesIO):
    """A binary file object that records the size of every read, to show the body is read in pieces."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads: list[int] = []

    def read(self, size: int | None = -1) -> bytes:
        out = super().read(size)
        self.reads.append(len(out))
        return out


class PipeFile(io.RawIOBase):
    """A binary stream that cannot seek, like a pipe."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: Any) -> int:
        chunk = self._inner.read(len(buffer))
        buffer[: len(chunk)] = chunk
        return len(chunk)


def test_bytes_are_one_put_with_the_raw_body_and_a_length(rig: Rig) -> None:
    out = rig.call(
        "upload",
        "big report.zip",
        "application/zip",
        content=DATA,
        visibility="account",
        expires_in_seconds=3600,
        passport_token="ppt",
    )
    assert out == FILE_VIEW
    sent = rig.fake.only
    assert (sent["method"], sent["path"]) == ("PUT", "/v1/drive/files")
    assert sent["query"] == {
        "name": "big report.zip",
        "content_type": "application/zip",
        "visibility": "account",
        "expires_in_seconds": "3600",
    }
    assert sent["body"] == DATA
    assert sent["headers"]["content-length"] == "25"
    assert sent["headers"]["content-type"] == "application/octet-stream"
    assert sent["headers"]["authorization"] == "Bearer sk_test_secret"
    assert sent["headers"]["x-passport-token"] == "ppt"


def test_the_query_names_only_what_is_given_and_declares_no_hash_or_size(rig: Rig) -> None:
    rig.call("upload", "a.zip", "application/zip", content=DATA)
    sent = rig.fake.only
    assert sent["query"] == {"name": "a.zip", "content_type": "application/zip"}
    assert "x-passport-token" not in sent["headers"]
    for key in sent["query"]:
        assert key not in ("sha256", "size_bytes", "part")


def test_a_path_is_streamed_in_chunks_with_its_size(rig: Rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drive_module, "READ_CHUNK_BYTES", 10)
    file = tmp_path / "big.zip"
    file.write_bytes(DATA)
    assert rig.call("upload", "big.zip", "application/zip", path=file) == FILE_VIEW
    sent = rig.fake.only
    assert sent["body"] == DATA
    assert sent["headers"]["content-length"] == "25"
    assert "transfer-encoding" not in sent["headers"]


def test_upload_file_takes_the_name_and_type_from_the_file(rig: Rig, tmp_path: Path) -> None:
    file = tmp_path / "clip.WAV"
    file.write_bytes(b"RIFF----WAVE")
    rig.call("upload_file", file)
    sent = rig.fake.only
    assert sent["query"] == {"name": "clip.WAV", "content_type": "audio/wav"}
    assert sent["body"] == b"RIFF----WAVE"


def test_a_file_object_is_read_in_pieces_from_where_it_is(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drive_module, "READ_CHUNK_BYTES", 10)
    handle = CountingFile(b"skipped" + DATA)
    handle.seek(7)
    rig.call("upload", "big.zip", "application/zip", content=handle)
    sent = rig.fake.only
    assert sent["body"] == DATA
    assert sent["headers"]["content-length"] == "25"
    assert max(handle.reads) <= 10
    assert len([n for n in handle.reads if n]) == 3


def test_a_bytearray_and_a_memoryview_are_sent_as_they_are(rig: Rig) -> None:
    rig.call("upload", "a.zip", "application/zip", content=bytearray(DATA))
    rig.call("upload", "b.zip", "application/zip", content=memoryview(DATA))
    assert [r["body"] for r in rig.fake.requests] == [DATA, DATA]
    assert [r["headers"]["content-length"] for r in rig.fake.requests] == ["25", "25"]


def test_a_stream_that_cannot_seek_is_sent_chunked(rig: Rig) -> None:
    rig.call("upload", "a.zip", "application/zip", content=PipeFile(DATA))
    sent = rig.fake.only
    assert sent["body"] == DATA
    assert "content-length" not in sent["headers"]
    assert sent["headers"]["transfer-encoding"] == "chunked"


def test_a_text_file_from_bytes_goes_the_same_way_and_content_text_stays_json(rig: Rig) -> None:
    rig.call("upload", "notes.md", "text/markdown", content=b"# Notes")
    rig.call("upload", "notes.md", "text/markdown", content_text="# Notes")
    put, post = rig.fake.requests
    assert (put["method"], put["body"]) == ("PUT", b"# Notes")
    assert (post["method"], post["path"]) == ("POST", "/v1/drive/files")
    assert json.loads(post["body"]) == {"name": "notes.md", "content_type": "text/markdown", "content_text": "# Notes"}


@pytest.mark.parametrize(
    "code,status",
    [
        ("DRIVE_TOO_MANY_UPLOADS", 429),
        ("DRIVE_READ_ONLY", 409),
        ("DRIVE_FILE_TOO_LARGE", 413),
        ("DRIVE_FILE_EMPTY", 400),
        ("INSUFFICIENT_BALANCE", 402),
    ],
)
def test_the_apis_refusals_are_raised_by_code(code: str, status: int) -> None:
    for kind in ("sync", "async"):
        rig = Rig(kind, FakeStack(refuse=api_error(status, code)))
        with pytest.raises(StackError) as raised:
            rig.call("upload", "a.zip", "application/zip", content=DATA)
        assert raised.value.code == code
        assert raised.value.status_code == status


def test_a_failed_upload_is_not_sent_twice(rig: Rig) -> None:
    rig.fake.refuse = api_error(429, "DRIVE_TOO_MANY_UPLOADS", {"limit": 2})
    with pytest.raises(StackError) as raised:
        rig.call("upload", "a.zip", "application/zip", content=DATA)
    assert raised.value.details == {"limit": 2}
    assert len(rig.fake.requests) == 1


def test_the_link_is_one_post_with_the_file_named_and_no_bytes(rig: Rig) -> None:
    view = rig.call(
        "create_upload_link",
        "big.zip",
        "application/zip",
        size_bytes=25,
        visibility="agent",
        expires_in_seconds=60,
        passport_token="ppt",
    )
    assert view == LINK_VIEW
    sent = rig.fake.only
    assert (sent["method"], sent["path"]) == ("POST", "/v1/drive/uploads")
    assert json.loads(sent["body"]) == {
        "name": "big.zip",
        "content_type": "application/zip",
        "size_bytes": 25,
        "visibility": "agent",
        "expires_in_seconds": 60,
    }
    assert sent["headers"]["x-passport-token"] == "ppt"


def test_the_link_body_holds_only_what_is_given(rig: Rig) -> None:
    rig.call("create_upload_link", "big.zip", "application/zip")
    assert json.loads(rig.fake.only["body"]) == {"name": "big.zip", "content_type": "application/zip"}


def test_a_link_upload_sends_the_bytes_with_no_credential(rig: Rig, tmp_path: Path) -> None:
    file = tmp_path / "big.zip"
    file.write_bytes(DATA)
    assert rig.call("upload_to_link", LINK_VIEW, path=file) == FILE_VIEW
    assert rig.call("upload_to_link", LINK_URL, content=DATA) == FILE_VIEW
    assert len(rig.fake.requests) == 2
    for sent in rig.fake.requests:
        assert (sent["method"], sent["path"]) == ("PUT", f"/v1/drive/uploads/{LINK_TOKEN}")
        assert sent["body"] == DATA
        assert sent["headers"]["content-length"] == "25"
        assert "authorization" not in sent["headers"]
        assert "x-passport-token" not in sent["headers"]


def test_a_link_that_does_not_work_is_raised_by_code_without_its_url() -> None:
    for kind in ("sync", "async"):
        rig = Rig(kind, FakeStack(refuse=api_error(404, "DRIVE_UPLOAD_LINK_INVALID")))
        with pytest.raises(StackError) as raised:
            rig.call("upload_to_link", LINK_URL, content=DATA)
        assert raised.value.code == "DRIVE_UPLOAD_LINK_INVALID"
        assert raised.value.status_code == 404
        assert LINK_TOKEN not in str(raised.value)
        assert LINK_TOKEN not in repr(raised.value.details)


def test_a_link_upload_that_never_arrives_names_no_url(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}")

    for kind in ("sync", "async"):
        rig = Rig(kind, FakeStack())
        if kind == "sync":
            rig.drive._client._client = httpx.Client(transport=httpx.MockTransport(broken))
        else:
            rig.drive._client._client = httpx.AsyncClient(transport=httpx.MockTransport(broken))
        with pytest.raises(StackError) as raised:
            rig.call("upload_to_link", LINK_URL, content=DATA)
        assert raised.value.code == "DRIVE_UPLOAD_FAILED"
        assert LINK_TOKEN not in str(raised.value)
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__


def test_an_upload_that_never_arrives_is_a_stack_error_not_a_raw_transport_error() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.WriteError(f"connection dropped to {request.url}")

    for kind in ("sync", "async"):
        rig = Rig(kind, FakeStack())
        if kind == "sync":
            rig.drive._client._client = httpx.Client(transport=httpx.MockTransport(broken))
        else:
            rig.drive._client._client = httpx.AsyncClient(transport=httpx.MockTransport(broken))
        with pytest.raises(StackError) as raised:
            rig.call("upload", "a.zip", "application/zip", content=DATA)
        assert raised.value.code == "DRIVE_UPLOAD_FAILED"
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__


def test_a_link_that_is_not_a_url_is_a_value_error_that_does_not_hold_it() -> None:
    for kind in ("sync", "async"):
        rig = Rig(kind, FakeStack())
        with pytest.raises(ValueError) as raised:
            rig.call("upload_to_link", "http://api.test:notaport/uploads/secret-token-123456789012", content=DATA)
        assert "secret-token" not in str(raised.value)


@pytest.mark.parametrize(
    "call",
    [
        lambda d: d.upload("a.zip", "application/zip", content=DATA, path="x.zip"),
        lambda d: d.upload("a.zip", "application/zip", content="not bytes"),
        lambda d: d.upload("a.zip", "application/zip", content=io.StringIO("text")),
        lambda d: d.create_upload_link("a.zip", "application/zip", size_bytes=0),
        lambda d: d.create_upload_link("a.txt", "text/plain", size_bytes=11),
        lambda d: d.upload_to_link(LINK_URL),
        lambda d: d.upload_to_link(LINK_URL, content=DATA, path="x.zip"),
        lambda d: d.upload_to_link({"id": "dul_1"}, content=DATA),
    ],
)
def test_a_bad_request_is_refused_before_any_request(rig: Rig, call: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drive_module, "MAX_TEXT_BYTES", 10)
    with pytest.raises((ValueError, TypeError)):
        outcome = call(rig.drive)
        if inspect.iscoroutine(outcome):
            asyncio.run(outcome)
    assert rig.fake.requests == []


def test_a_file_over_the_limit_is_refused_before_any_request(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drive_module, "MAX_FILE_BYTES", 20)
    with pytest.raises(ValueError):
        rig.call("upload", "big.zip", "application/zip", content=DATA)
    with pytest.raises(ValueError):
        rig.call("upload_to_link", LINK_URL, content=DATA)
    assert rig.fake.requests == []


def test_a_text_file_over_ten_mib_is_refused_before_any_request(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drive_module, "MAX_TEXT_BYTES", 10)
    with pytest.raises(ValueError):
        rig.call("upload", "a.txt", "text/plain", content=b"x" * 11)
    assert rig.fake.requests == []
    rig.call("upload", "a.txt", "text/plain", content=b"x" * 10)
    assert len(rig.fake.requests) == 1


def test_the_content_type_follows_the_extension_and_any_file_is_taken() -> None:
    assert content_type_for("notes.MD") == "text/markdown"
    assert content_type_for(Path("a") / "clip.wav") == "audio/wav"
    assert content_type_for("housing.stl") == "model/stl"
    # The drive takes a file of any type: an extension it has no label for is application/octet-stream.
    assert content_type_for("run.exe") == "application/octet-stream"
    assert content_type_for("README") == "application/octet-stream"


def test_the_multipart_calls_are_gone() -> None:
    for name in ("start_upload", "upload_status", "complete_upload", "cancel_upload", "resume_upload"):
        assert not hasattr(DriveService, name)
        assert not hasattr(AsyncDriveService, name)


def test_sync_and_async_expose_the_same_upload_calls() -> None:
    for name in ("upload", "upload_file", "create_upload_link", "upload_to_link"):
        sync = inspect.signature(getattr(DriveService, name))
        asynchronous = inspect.signature(getattr(AsyncDriveService, name))
        assert list(sync.parameters) == list(asynchronous.parameters), name
        assert inspect.iscoroutinefunction(getattr(AsyncDriveService, name))
