"""Async agent drive: the awaitable mirror of ``getstack.drive``, with uploads of large files in one request."""

from __future__ import annotations

import asyncio
import builtins
import os
from collections.abc import AsyncIterator
from typing import Any, BinaryIO, cast

import httpx

from .. import drive as shared
from ..client import AsyncHttpClient
from ..drive import (
    UploadSource,
    _file,
    _passport,
    _seg,
    check_upload,
    content_type_for,
    copy_body,
    link_body,
    link_failure,
    link_url,
    list_params,
    share_body,
    stream_params,
    update_body,
    upload_body,
)


async def _chunks(source: UploadSource) -> AsyncIterator[bytes]:
    """The body of an upload read from a path or file object a chunk at a time, off the event loop."""
    data = source.memory()
    if data is not None:
        for offset in range(0, len(data), shared.READ_CHUNK_BYTES):
            yield bytes(data[offset : offset + shared.READ_CHUNK_BYTES])
        return
    handle, close = await asyncio.to_thread(source.reader)
    try:
        while True:
            chunk = await asyncio.to_thread(handle.read, shared.READ_CHUNK_BYTES)
            if not chunk:
                return
            yield chunk
    finally:
        if close:
            handle.close()


def _body(source: UploadSource) -> bytes | AsyncIterator[bytes]:
    data = source.memory()
    return data if isinstance(data, bytes) else _chunks(source)


class AsyncDriveService:
    """Files of the account: private to one agent or shared with the account, with signed share links."""

    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def upload(
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
        """Store one file of up to 1 GB (10 MB typed as text, Markdown, CSV or JSON) in one request. One metered action.

        See ``DriveService.upload``.

        A path or file object is read in 1 MiB chunks as the body is sent, off the event loop.
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
                await self._client.post("/v1/drive/files", json=body, extra_headers=_passport(passport_token)),
            )
        source = await asyncio.to_thread(UploadSource, content, path)
        size = await asyncio.to_thread(source.size)
        check_upload(content_type, size)
        try:
            return cast(
                "dict[str, Any]",
                await self._client.put_stream(
                    "/v1/drive/files",
                    _body(source),
                    params=stream_params(name, content_type, visibility, expires_in_seconds),
                    extra_headers=_passport(passport_token),
                    content_length=size,
                    timeout=shared.UPLOAD_TIMEOUT,
                ),
            )
        except httpx.HTTPError as exc:
            raise shared.upload_failure(exc) from None

    async def upload_file(
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
        return await self.upload(
            name or os.path.basename(os.fspath(path)),
            content_type or content_type_for(path),
            path=path,
            visibility=visibility,
            expires_in_seconds=expires_in_seconds,
            passport_token=passport_token,
        )

    async def create_upload_link(
        self,
        name: str,
        content_type: str | None = None,
        *,
        size_bytes: int | None = None,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Ask for a one-time upload URL: the metered action. See ``DriveService.create_upload_link``."""
        body = link_body(name, content_type, size_bytes, visibility, expires_in_seconds)
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/drive/uploads", json=body, extra_headers=_passport(passport_token)),
        )

    async def upload_to_link(
        self,
        link: dict[str, Any] | str,
        *,
        content: bytes | bytearray | memoryview | BinaryIO | None = None,
        path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Send a file to an upload link with no Authorization header. See ``DriveService.upload_to_link``."""
        url = link_url(link)
        if (content is None) == (path is None):
            raise ValueError("send exactly one of content and path")
        source = await asyncio.to_thread(UploadSource, content, path)
        size = await asyncio.to_thread(source.size)
        if size is not None and size > shared.MAX_FILE_BYTES:
            raise ValueError(f"a file is at most {shared.MAX_FILE_BYTES} bytes")
        try:
            return cast(
                "dict[str, Any]",
                await self._client.put_to_url(url, _body(source), content_length=size, timeout=shared.UPLOAD_TIMEOUT),
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise link_failure(exc) from None

    async def list(
        self, *, limit: int | None = None, cursor: str | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """``{"files": [...], "next_cursor": ..., "usage": {...}}``, newest first. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.get(
                "/v1/drive/files", params=list_params(limit, cursor), extra_headers=_passport(passport_token)
            ),
        )

    async def get(self, file_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One file's facts. Free."""
        return cast("dict[str, Any]", await self._client.get(_file(file_id), extra_headers=_passport(passport_token)))

    async def read(self, file_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The content of a file of 256 KB or less. Free. The content is untrusted."""
        return cast(
            "dict[str, Any]",
            await self._client.get(f"{_file(file_id)}/content", extra_headers=_passport(passport_token)),
        )

    async def update(
        self,
        file_id: str,
        *,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        remove_expiry: bool = False,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Change who sees a file or when it ends. The agent that wrote it, or the owner.

        ``DRIVE_READ_ONLY`` (409) while the drive is read-only. The end of a file that arrived with an email cannot
        be changed (409): copy it to keep it.
        """
        body = update_body(visibility, expires_in_seconds, remove_expiry)
        return cast(
            "dict[str, Any]",
            await self._client.request("PATCH", _file(file_id), json=body, extra_headers=_passport(passport_token)),
        )

    async def copy(
        self,
        file_id: str,
        *,
        name: str | None = None,
        visibility: str | None = None,
        expires_in_seconds: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Copy a file you can see into a new file of your own, with its own id.

        How a file that arrived with an email, which is deleted with its message, is kept. The copy
        never ends unless ``expires_in_seconds`` is given, and is private to the caller unless ``visibility`` is
        ``"account"``. It counts as an upload: one metered action, put to the account's controls;
        ``DRIVE_READ_ONLY`` (409) while the drive is read-only.
        """
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"{_file(file_id)}/copy",
                json=copy_body(name, visibility, expires_in_seconds),
                extra_headers=_passport(passport_token),
            ),
        )

    async def delete(self, file_id: str, *, passport_token: str | None = None) -> None:
        """Delete a file, its bytes and every link to it."""
        await self._client.delete(_file(file_id), extra_headers=_passport(passport_token))

    async def share(
        self,
        file_id: str,
        *,
        ttl_seconds: int | None = None,
        max_downloads: int | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Make a signed download link. One metered action. The URL is in ``"url"`` once and cannot be read back.

        ``max_downloads`` is 1 or more and is 100 when omitted; ``DRIVE_LINKS_PAUSED`` (409) while links are
        paused, ``DRIVE_READ_ONLY`` (409) while the drive is read-only.
        """
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"{_file(file_id)}/links",
                json=share_body(ttl_seconds, max_downloads),
                extra_headers=_passport(passport_token),
            ),
        )

    async def links(self, file_id: str, *, passport_token: str | None = None) -> builtins.list[dict[str, Any]]:
        """The file's links with their download counts; the URLs are never returned."""
        out = cast(
            "dict[str, Any]",
            await self._client.get(f"{_file(file_id)}/links", extra_headers=_passport(passport_token)),
        )
        return cast("builtins.list[dict[str, Any]]", out["links"])

    async def revoke_link(self, file_id: str, link_id: str, *, passport_token: str | None = None) -> None:
        """End a link at once."""
        await self._client.delete(f"{_file(file_id)}/links/{_seg(link_id)}", extra_headers=_passport(passport_token))
