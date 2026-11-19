"""The agent drive: an account's files, kept for them.

An agent's upload is private to that agent unless it says ``account``; the owner (an API key or a
session, no agent) sees every file. Every file is untrusted content to whoever reads it, and each
view says so (``trust``).

Calls an agent makes take the Passport as ``passport_token``, sent as ``X-Passport-Token``, and run
under the Passport's Mission. The owner calls without one. A share link's own URL
(``GET /v1/drive/links/<token>``) needs no credential: it is the credential.

``upload`` is one request. Text given as ``content_text`` goes in a JSON body (``POST /v1/drive/files``,
10 MB or less). Bytes, a binary file object or a path (``content=`` or ``path=``) are the whole body of
``PUT /v1/drive/files?name=...&content_type=...``: the file is read in 1 MiB chunks as it is sent, so a
1 GB file is never held in memory, and the API computes the hash itself. The drive takes a file of any type
and stores it as it is: ``content_type`` is only a label (``application/octet-stream`` when left out), and
a file typed as plain text, Markdown, CSV or JSON is 10 MB or less in every path. ``create_upload_link`` asks
for a one-time URL (the metered action) for a program that cannot send credentials with the file;
``upload_to_link`` sends the bytes there with no credential at all.

A drive whose storage charge went unpaid is read-only (``DRIVE_READ_ONLY``, 409): uploads, edits and new
share links are refused, while reading, downloading, listing and deleting still work. Topping up the wallet
or deleting files until the drive is within its free amount lifts it at once; ``list``'s ``usage`` shows it
as ``storage_unpaid``.
"""

from __future__ import annotations

import base64
import builtins
import os
from collections.abc import Iterator
from typing import Any, BinaryIO, cast
from urllib.parse import quote

import httpx

from .client import HttpClient
from .errors import StackError

MAX_TEXT_BYTES = 10 * 1024 * 1024
"""A file typed as text, Markdown, CSV or JSON is this many bytes or less, in every path."""
MAX_FILE_BYTES = 1024**3
TEXT_TYPES = frozenset({"text/plain", "text/markdown", "text/csv", "application/json"})
READ_CHUNK_BYTES = 1024 * 1024
UPLOAD_TIMEOUT = httpx.Timeout(30.0, read=6 * 60 * 60, write=300.0)
"""The API gives an upload up to six hours; the read wait covers the API sealing the file after the last byte."""

_EXTENSION_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".zip": "application/zip",
    ".log": "text/plain",
    ".svg": "image/svg+xml",
    ".gz": "application/gzip",
    ".stl": "model/stl",
    ".3mf": "model/3mf",
    ".step": "model/step",
    ".stp": "model/step",
    ".dxf": "image/vnd.dxf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
DEFAULT_CONTENT_TYPE = "application/octet-stream"


def _seg(value: str) -> str:
    return quote(value, safe="")


def _file(file_id: str) -> str:
    return f"/v1/drive/files/{_seg(file_id)}"


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def upload_body(
    name: str,
    content_type: str | None,
    *,
    content_text: str | None = None,
    content: bytes | None = None,
    visibility: str | None = None,
    expires_in_seconds: int | None = None,
) -> dict[str, Any]:
    """The body of an upload. Send the file as ``content_text`` (stored as UTF-8) or as ``content`` bytes."""
    if (content_text is None) == (content is None):
        raise ValueError("send exactly one of content_text and content")
    body: dict[str, Any] = {"name": name}
    if content_type is not None:
        body["content_type"] = content_type
    if content_text is not None:
        body["content_text"] = content_text
    else:
        body["content_base64"] = base64.b64encode(cast("bytes", content)).decode("ascii")
    if visibility is not None:
        body["visibility"] = visibility
    if expires_in_seconds is not None:
        body["expires_in_seconds"] = expires_in_seconds
    return body


def list_params(limit: int | None, cursor: str | None) -> dict[str, Any] | None:
    params: dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if cursor is not None:
        params["cursor"] = cursor
    return params or None


def update_body(visibility: str | None, expires_in_seconds: int | None, remove_expiry: bool) -> dict[str, Any]:
    if expires_in_seconds is not None and remove_expiry:
        raise ValueError("name an expiry or remove it, not both")
    body: dict[str, Any] = {}
    if visibility is not None:
        body["visibility"] = visibility
    if expires_in_seconds is not None:
        body["expires_in_seconds"] = expires_in_seconds
    if remove_expiry:
        body["expires_in_seconds"] = None
    if not body:
        raise ValueError("change the visibility, the expiry or both")
    return body


def copy_body(name: str | None, visibility: str | None, expires_in_seconds: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if name is not None:
        body["name"] = name
    if visibility is not None:
        body["visibility"] = visibility
    if expires_in_seconds is not None:
        body["expires_in_seconds"] = expires_in_seconds
    return body


def share_body(ttl_seconds: int | None, max_downloads: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if ttl_seconds is not None:
        body["ttl_seconds"] = ttl_seconds
    if max_downloads is not None:
        body["max_downloads"] = max_downloads
    return body


def content_type_for(path: str | os.PathLike[str]) -> str:
    """The label a file name's extension suggests, else ``application/octet-stream``: the drive takes any file."""
    ext = os.path.splitext(os.fspath(path))[1].lower()
    return _EXTENSION_TYPES.get(ext, DEFAULT_CONTENT_TYPE)


class UploadSource:
    """The bytes of one file to send as a request body: bytes in memory, a path, or a binary file object.

    A file object is read from its current position to its end.
    """

    def __init__(self, content: Any = None, path: str | os.PathLike[str] | None = None):
        self._data: bytes | bytearray | memoryview | None = None
        self._path: str | None = None
        self._file: BinaryIO | None = None
        if path is not None:
            self._path = os.fspath(path)
        elif isinstance(content, (bytes, bytearray, memoryview)):
            self._data = content
        elif hasattr(content, "read"):
            if not isinstance(content.read(0), bytes):
                raise ValueError("a file object must be opened in binary mode")
            self._file = cast("BinaryIO", content)
        else:
            raise TypeError("content must be bytes, bytearray, memoryview or a binary file object")

    def size(self) -> int | None:
        """The number of bytes, without reading them; ``None`` for a file object that cannot seek."""
        if self._data is not None:
            return len(memoryview(self._data).cast("B"))
        if self._path is not None:
            return os.path.getsize(self._path)
        file = cast("BinaryIO", self._file)
        if not file.seekable():
            return None
        here = file.tell()
        end = file.seek(0, os.SEEK_END)
        file.seek(here)
        return end - here

    def reader(self) -> tuple[BinaryIO, bool]:
        """``(file, close_after)``: what to read the body from. Not for bytes held in memory."""
        if self._path is not None:
            return open(self._path, "rb"), True
        return cast("BinaryIO", self._file), False

    def memory(self) -> bytes | memoryview | None:
        """The bytes when they are already in memory, else ``None``."""
        if self._data is None:
            return None
        return self._data if isinstance(self._data, bytes) else memoryview(self._data).cast("B")

    def body(self) -> bytes | Iterator[bytes]:
        """The request body: the bytes as they are, or an iterator that reads the file in 1 MiB chunks."""
        data = self.memory()
        if isinstance(data, bytes):
            return data
        return self._chunks(data)

    def _chunks(self, data: memoryview | None) -> Iterator[bytes]:
        if data is not None:
            for offset in range(0, len(data), READ_CHUNK_BYTES):
                yield bytes(data[offset : offset + READ_CHUNK_BYTES])
            return
        handle, close = self.reader()
        try:
            while True:
                chunk = handle.read(READ_CHUNK_BYTES)
                if not chunk:
                    return
                yield chunk
        finally:
            if close:
                handle.close()


def check_upload(content_type: str | None, size: int | None) -> None:
    """Refuse before any request what the API would refuse for its size."""
    if size is None:
        return
    if content_type in TEXT_TYPES and size > MAX_TEXT_BYTES:
        raise ValueError(f"a {content_type} file is at most {MAX_TEXT_BYTES} bytes")
    if size > MAX_FILE_BYTES:
        raise ValueError(f"a file is at most {MAX_FILE_BYTES} bytes")


def stream_params(
    name: str, content_type: str | None, visibility: str | None, expires_in_seconds: int | None
) -> dict[str, Any]:
    """The query of ``PUT /v1/drive/files``: what names the file. The bytes are the body; no hash, no size."""
    params: dict[str, Any] = {"name": name}
    if content_type is not None:
        params["content_type"] = content_type
    if visibility is not None:
        params["visibility"] = visibility
    if expires_in_seconds is not None:
        params["expires_in_seconds"] = expires_in_seconds
    return params


def link_body(
    name: str,
    content_type: str | None,
    size_bytes: int | None,
    visibility: str | None,
    expires_in_seconds: int | None,
) -> dict[str, Any]:
    """The body of ``POST /v1/drive/uploads``. ``size_bytes``, when given, is the most the upload may send."""
    body: dict[str, Any] = {"name": name}
    if content_type is not None:
        body["content_type"] = content_type
    if size_bytes is not None:
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or not 1 <= size_bytes <= MAX_FILE_BYTES:
            raise ValueError(f"size_bytes must be 1 to {MAX_FILE_BYTES}")
        check_upload(content_type, size_bytes)
        body["size_bytes"] = size_bytes
    if visibility is not None:
        body["visibility"] = visibility
    if expires_in_seconds is not None:
        body["expires_in_seconds"] = expires_in_seconds
    return body


def link_url(link: Any) -> str:
    """The URL of an upload link: the view ``create_upload_link`` answered, or the URL itself."""
    url = link.get("url") if isinstance(link, dict) else link
    if not isinstance(url, str) or not url:
        raise ValueError("link must be an upload link or its url")
    return url


def upload_failure(exc: Exception) -> StackError:
    """The error for an upload whose request never completed (a dropped connection, a timeout): it carries no URL."""
    return StackError(f"The upload did not reach STACK ({type(exc).__name__})", "DRIVE_UPLOAD_FAILED", 0)


def link_failure(exc: httpx.HTTPError | httpx.InvalidURL) -> Exception:
    """An error for a failed upload to a link that never holds the link's URL, which is a credential."""
    if isinstance(exc, httpx.InvalidURL):
        return ValueError("the upload link is not a valid URL")
    return upload_failure(exc)


class DriveService:
    """Files of the account: private to one agent or shared with the account, with signed share links."""

    def __init__(self, client: HttpClient):
        self._client = client

    def upload(
        self,
        name: str,
        content_type: str | None = None,
        *,
        content_text: str | None = None,
        content: bytes | bytearray | memoryview | BinaryIO | None = None,
        path: str | os.PathLike[str] | None = None,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Store one file of up to 1 GB (10 MB when it is typed as text, Markdown, CSV or JSON) in one request.

        One metered action, put to the account's controls.

        Send exactly one of ``content_text``, ``content`` (bytes, bytearray, memoryview or a binary file
        object, read from its current position) and ``path``. ``content_text`` goes in a JSON body;
        ``content`` and ``path`` are the raw body of ``PUT /v1/drive/files`` and are read in 1 MiB chunks
        as they are sent, with ``Content-Length`` when the size is known. The API computes the SHA-256
        itself; nothing is hashed or declared here. A file the drive refuses raises ``StackError`` with the
        API's code (``DRIVE_FILE_TOO_LARGE``, ``DRIVE_FILE_EMPTY``,
        ``DRIVE_TOO_MANY_UPLOADS``, ``DRIVE_READ_ONLY``, ``INSUFFICIENT_BALANCE``). A failed upload is not
        retried: the body may be a stream that cannot be replayed.

        A file of any type is taken and stored as it is. ``content_type`` is only the label it carries, any media
        type such as ``model/stl`` (``application/octet-stream`` when left out); the bytes are not checked against it.
        ``visibility`` is ``agent`` (the default for an agent) or ``account``; the owner's upload is always
        the account's. Returns the file's facts, never its content.
        """
        if sum(item is not None for item in (content_text, content, path)) != 1:
            raise ValueError("send exactly one of content_text, content and path")
        if content_text is not None:
            body = upload_body(
                name,
                content_type,
                content_text=content_text,
                visibility=visibility,
                expires_in_seconds=expires_in_seconds,
            )
            return cast(
                "dict[str, Any]",
                self._client.post("/v1/drive/files", json=body, extra_headers=_passport(passport_token)),
            )
        source = UploadSource(content, path)
        size = source.size()
        check_upload(content_type, size)
        try:
            return cast(
                "dict[str, Any]",
                self._client.put_stream(
                    "/v1/drive/files",
                    source.body(),
                    params=stream_params(name, content_type, visibility, expires_in_seconds),
                    extra_headers=_passport(passport_token),
                    content_length=size,
                    timeout=UPLOAD_TIMEOUT,
                ),
            )
        except httpx.HTTPError as exc:
            raise upload_failure(exc) from None

    def upload_file(
        self,
        path: str | os.PathLike[str],
        *,
        name: str | None = None,
        content_type: str | None = None,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """``upload`` for a file on disk: ``name`` defaults to its file name and ``content_type`` to its extension."""
        return self.upload(
            name or os.path.basename(os.fspath(path)),
            content_type or content_type_for(path),
            path=path,
            visibility=visibility,
            expires_in_seconds=expires_in_seconds,
            passport_token=passport_token,
        )

    def create_upload_link(
        self,
        name: str,
        content_type: str | None = None,
        *,
        size_bytes: int | None = None,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Ask for a one-time upload URL: the metered action, for a program that cannot send the file itself.

        ``size_bytes``, when given, is the most the upload may send. Returns ``{"id", "url", "method": "PUT",
        "name", "content_type", "max_bytes", "expires_at"}``. The URL works once, for 30 minutes, with no
        credential on the request (``upload_to_link``, or ``curl -T ./file '<url>'``); it is a bearer URL, so keep
        it out of logs. Making the URL takes no upload slot: ``DRIVE_TOO_MANY_UPLOADS`` (429) is what the ``PUT`` to
        it answers when the account's uploads are already running, and ``DRIVE_READ_ONLY`` (409) answers here.
        """
        body = link_body(name, content_type, size_bytes, visibility, expires_in_seconds)
        return cast(
            "dict[str, Any]",
            self._client.post("/v1/drive/uploads", json=body, extra_headers=_passport(passport_token)),
        )

    def upload_to_link(
        self,
        link: dict[str, Any] | str,
        *,
        content: bytes | bytearray | memoryview | BinaryIO | None = None,
        path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Send a file to an upload link: one ``PUT`` of the raw bytes, with no Authorization header.

        Returns the file's facts.

        ``link`` is what ``create_upload_link`` answered, or its URL. Send exactly one of ``content`` and
        ``path``; the file is read in 1 MiB chunks as it is sent. The URL is never put in an error. A link
        that is used, expired or not the account's is ``DRIVE_UPLOAD_LINK_INVALID`` (404).
        """
        url = link_url(link)
        if (content is None) == (path is None):
            raise ValueError("send exactly one of content and path")
        source = UploadSource(content, path)
        size = source.size()
        if size is not None and size > MAX_FILE_BYTES:
            raise ValueError(f"a file is at most {MAX_FILE_BYTES} bytes")
        try:
            return cast(
                "dict[str, Any]",
                self._client.put_to_url(url, source.body(), content_length=size, timeout=UPLOAD_TIMEOUT),
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise link_failure(exc) from None

    def list(
        self, *, limit: int | None = None, cursor: str | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """``{"files": [...], "next_cursor": ..., "usage": {...}}``, newest first. Free."""
        return cast(
            "dict[str, Any]",
            self._client.get(
                "/v1/drive/files", params=list_params(limit, cursor), extra_headers=_passport(passport_token)
            ),
        )

    def get(self, file_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One file's facts. Free."""
        return cast("dict[str, Any]", self._client.get(_file(file_id), extra_headers=_passport(passport_token)))

    def read(self, file_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The content of a file of 256 KB or less. Free. The content is untrusted.

        ``{"file", "encoding" (utf8 or base64), "content", "withheld", "flag"}``.
        """
        return cast(
            "dict[str, Any]", self._client.get(f"{_file(file_id)}/content", extra_headers=_passport(passport_token))
        )

    def update(
        self,
        file_id: str,
        *,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        remove_expiry: bool = False,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Change who sees a file or when it ends. The agent that wrote it, or the owner.

        ``DRIVE_READ_ONLY`` (409) while the drive is read-only. A file that arrived with an email changes like any file.
        """
        body = update_body(visibility, expires_in_seconds, remove_expiry)
        return cast(
            "dict[str, Any]",
            self._client.request("PATCH", _file(file_id), json=body, extra_headers=_passport(passport_token)),
        )

    def copy(
        self,
        file_id: str,
        *,
        name: str | None = None,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Copy a file you can see into a new file of your own, with its own id.

        The copy never ends unless ``expires_in_seconds`` is given, and is private to the caller unless
        ``visibility`` is ``"account"``. It counts as an upload: one metered action, put to the account's
        controls; ``DRIVE_READ_ONLY`` (409) while the drive is read-only.
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"{_file(file_id)}/copy",
                json=copy_body(name, visibility, expires_in_seconds),
                extra_headers=_passport(passport_token),
            ),
        )

    def delete(self, file_id: str, *, passport_token: str | None = None) -> None:
        """Delete a file, its bytes and every link to it."""
        self._client.delete(_file(file_id), extra_headers=_passport(passport_token))

    def share(
        self,
        file_id: str,
        *,
        ttl_seconds: int | None = None,
        max_downloads: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Make a signed download link: 60 seconds to 7 days (default 15 minutes), never past the file.

        One metered action. The URL is in ``"url"`` once and cannot be read back. ``max_downloads`` is at
        most 100 and is 100 when omitted; ``DRIVE_LINKS_PAUSED`` (409) while links are paused, ``DRIVE_READ_ONLY``
        (409) while the drive is read-only.
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"{_file(file_id)}/links",
                json=share_body(ttl_seconds, max_downloads),
                extra_headers=_passport(passport_token),
            ),
        )

    def links(self, file_id: str, *, passport_token: str | None = None) -> builtins.list[dict[str, Any]]:
        """The file's links with their download counts; the URLs are never returned."""
        out = cast(
            "dict[str, Any]", self._client.get(f"{_file(file_id)}/links", extra_headers=_passport(passport_token))
        )
        return cast("builtins.list[dict[str, Any]]", out["links"])

    def revoke_link(self, file_id: str, link_id: str, *, passport_token: str | None = None) -> None:
        """End a link at once."""
        self._client.delete(f"{_file(file_id)}/links/{_seg(link_id)}", extra_headers=_passport(passport_token))
