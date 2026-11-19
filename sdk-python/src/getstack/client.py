"""HTTP client for the STACK API."""

from __future__ import annotations

import contextlib
import copy
from typing import Any, TypeVar

import httpx

from .auth import AuthStrategy
from .errors import raise_for_status

DEFAULT_BASE_URL = "https://api.getstack.run"

CONTROL_REF_HEADER = "X-Control-Ref"

_C = TypeVar("_C", "HttpClient", "AsyncHttpClient")


def _scoped_to_ref(client: _C, ref: str) -> _C:
    """A copy of the client that sends `X-Control-Ref: <ref>` on every request it makes.

    It shares the connection and the credential with the original, so a token refresh happens once.
    """
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("control_ref must be the non-empty ref the refusal named")
    scoped = copy.copy(client)
    scoped._control_ref = ref
    return scoped


def _answer(resp: httpx.Response) -> Any:
    """The JSON of a successful answer, or the API's error raised; ``None`` for ``204``."""
    if resp.status_code >= 400:
        try:
            body = resp.json()
        except Exception:
            body = {"error": {"message": resp.text}}
        raise_for_status(resp.status_code, body)
    if resp.status_code == 204:
        return None
    return resp.json()


class HttpClient:
    """Synchronous HTTP client wrapping httpx."""

    _control_ref: str | None = None

    def _ref_headers(self) -> dict[str, str]:
        return {CONTROL_REF_HEADER: self._control_ref} if self._control_ref else {}

    def with_control_ref(self, ref: str) -> HttpClient:
        """A client that sends ``X-Control-Ref`` on every request: the retry of an action the owner approved."""
        return _scoped_to_ref(self, ref)

    def __init__(self, auth: AuthStrategy, base_url: str = DEFAULT_BASE_URL, timeout: float = 30.0):
        self.auth = auth
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        headers = {
            "Content-Type": "application/json",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }

        url = f"{self.base_url}{path}"
        resp = self._client.request(method, url, json=json, params=params, headers=headers)

        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)

        if resp.status_code == 204:
            return None

        return resp.json()

    def request_with_headers(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, httpx.Headers, Any]:
        """Like ``request`` for a read whose answer is also in its headers or may be ``304``.

        Returns ``(status_code, headers, body)``; ``body`` is ``None`` for ``204`` and ``304``.
        """
        headers = {
            "Content-Type": "application/json",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        resp = self._client.request(method, f"{self.base_url}{path}", params=params, headers=headers)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        if resp.status_code in (204, 304):
            return resp.status_code, resp.headers, None
        return resp.status_code, resp.headers, resp.json()

    def public_request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """A call to a public endpoint: no credential is resolved or sent, so it works with none configured."""
        resp = self._client.request(method, f"{self.base_url}{path}", json=json, params=params)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.json()

    def get(self, path: str, params: dict[str, Any] | None = None, extra_headers: dict[str, str] | None = None) -> Any:
        return self.request("GET", path, params=params, extra_headers=extra_headers)

    def request_bytes(self, method: str, path: str) -> bytes:
        """Return an authenticated response body without JSON decoding."""
        url = f"{self.base_url}{path}"
        resp = self._client.request(method, url, headers=self.auth.get_headers())
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.content

    def request_raw(
        self,
        method: str,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, str | None, bytes]:
        """Any method, the answer as exact bytes: ``(status, content type, bytes)``, for an answer that is a file."""
        headers = {
            "Content-Type": "application/json",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        resp = self._client.request(method, f"{self.base_url}{path}", json=json, headers=headers)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.status_code, resp.headers.get("content-type"), resp.content

    def post(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> Any:
        return self.request("POST", path, json=json, extra_headers=extra_headers)

    def post_public(self, path: str, json: Any = None) -> Any:
        """POST to a route that takes no credential (a public form): no Authorization header is sent."""
        resp = self._client.request(
            "POST", f"{self.base_url}{path}", json=json, headers={"Content-Type": "application/json"}
        )
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.json()

    def stream_post(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> contextlib.AbstractContextManager[httpx.Response]:
        """streaming POST for the LLM gateway. Returns an
        httpx Response context manager; caller iterates `.iter_lines()`
        and yields parsed SSE events. The caller MUST use this as a
        context manager (`with client.stream_post(...) as resp:`) so the
        underlying connection releases on exit.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        url = f"{self.base_url}{path}"
        return self._client.stream("POST", url, json=json, headers=headers)

    def put_stream(
        self,
        path: str,
        content: Any,
        *,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        content_length: int | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> Any:
        """PUT raw bytes as the whole request body: ``content`` is bytes or an iterator of bytes.

        ``content_length`` is sent when the size is known; without it the body goes chunked.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        if content_length is not None:
            headers["Content-Length"] = str(content_length)
        resp = self._client.request(
            "PUT",
            f"{self.base_url}{path}",
            content=content,
            params=params,
            headers=headers,
            timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
        )
        return _answer(resp)

    def put_to_url(
        self,
        url: str,
        content: Any,
        *,
        content_length: int | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> Any:
        """PUT raw bytes to an absolute URL that is its own credential: no Authorization header is sent."""
        headers = {"Content-Type": "application/octet-stream"}
        if content_length is not None:
            headers["Content-Length"] = str(content_length)
        resp = self._client.request(
            "PUT",
            url,
            content=content,
            headers=headers,
            timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
        )
        return _answer(resp)

    def patch(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> Any:
        return self.request("PATCH", path, json=json, extra_headers=extra_headers)

    def put(self, path: str, json: Any = None, extra_headers: dict[str, str] | None = None) -> Any:
        return self.request("PUT", path, json=json, extra_headers=extra_headers)

    def delete(self, path: str, extra_headers: dict[str, str] | None = None) -> Any:
        return self.request("DELETE", path, extra_headers=extra_headers)

    def close(self) -> None:
        self._client.close()


class AsyncHttpClient:
    """Asynchronous HTTP client wrapping httpx.

    regression-fixed `extra_headers` parameter (was
       missing on async side; sync HttpClient had it from day one). The
       new approval-gate header (`X-Intent-Approval-Id`) and the existing
       passport-token header (`X-Passport-Token`) both ride on this
       parameter from typed async service modules.
    """

    _control_ref: str | None = None

    def _ref_headers(self) -> dict[str, str]:
        return {CONTROL_REF_HEADER: self._control_ref} if self._control_ref else {}

    def with_control_ref(self, ref: str) -> AsyncHttpClient:
        """A client that sends ``X-Control-Ref`` on every request: the retry of an action the owner approved."""
        return _scoped_to_ref(self, ref)

    def __init__(self, auth: AuthStrategy, base_url: str = DEFAULT_BASE_URL, timeout: float = 30.0):
        self.auth = auth
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    async def request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        headers = {
            "Content-Type": "application/json",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }

        url = f"{self.base_url}{path}"
        resp = await self._client.request(method, url, json=json, params=params, headers=headers)

        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)

        if resp.status_code == 204:
            return None

        return resp.json()

    async def request_with_headers(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, httpx.Headers, Any]:
        """Like ``request`` for a read whose answer is also in its headers or may be ``304``.

        Returns ``(status_code, headers, body)``; ``body`` is ``None`` for ``204`` and ``304``.
        """
        headers = {
            "Content-Type": "application/json",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        resp = await self._client.request(method, f"{self.base_url}{path}", params=params, headers=headers)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        if resp.status_code in (204, 304):
            return resp.status_code, resp.headers, None
        return resp.status_code, resp.headers, resp.json()

    async def public_request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """A call to a public endpoint: no credential is resolved or sent, so it works with none configured."""
        resp = await self._client.request(method, f"{self.base_url}{path}", json=json, params=params)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.json()

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        return await self.request("GET", path, params=params, extra_headers=extra_headers)

    async def request_bytes(self, method: str, path: str) -> bytes:
        """Return an authenticated response body without JSON decoding."""
        url = f"{self.base_url}{path}"
        resp = await self._client.request(method, url, headers=self.auth.get_headers())
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.content

    async def request_raw(
        self,
        method: str,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, str | None, bytes]:
        """Any method, the answer as exact bytes: ``(status, content type, bytes)``, for an answer that is a file."""
        headers = {
            "Content-Type": "application/json",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        resp = await self._client.request(method, f"{self.base_url}{path}", json=json, headers=headers)
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.status_code, resp.headers.get("content-type"), resp.content

    async def post(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        return await self.request("POST", path, json=json, extra_headers=extra_headers)

    async def post_public(self, path: str, json: Any = None) -> Any:
        """POST to a route that takes no credential (a public form): no Authorization header is sent."""
        resp = await self._client.request(
            "POST", f"{self.base_url}{path}", json=json, headers={"Content-Type": "application/json"}
        )
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"error": {"message": resp.text}}
            raise_for_status(resp.status_code, body)
        return resp.json()

    async def put_stream(
        self,
        path: str,
        content: Any,
        *,
        params: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        content_length: int | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> Any:
        """PUT raw bytes as the whole request body: ``content`` is bytes or an async iterator of bytes.

        ``content_length`` is sent when the size is known; without it the body goes chunked.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        if content_length is not None:
            headers["Content-Length"] = str(content_length)
        resp = await self._client.request(
            "PUT",
            f"{self.base_url}{path}",
            content=content,
            params=params,
            headers=headers,
            timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
        )
        return _answer(resp)

    async def put_to_url(
        self,
        url: str,
        content: Any,
        *,
        content_length: int | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> Any:
        """PUT raw bytes to an absolute URL that is its own credential: no Authorization header is sent."""
        headers = {"Content-Type": "application/octet-stream"}
        if content_length is not None:
            headers["Content-Length"] = str(content_length)
        resp = await self._client.request(
            "PUT",
            url,
            content=content,
            headers=headers,
            timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
        )
        return _answer(resp)

    async def patch(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        return await self.request("PATCH", path, json=json, extra_headers=extra_headers)

    async def put(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        return await self.request("PUT", path, json=json, extra_headers=extra_headers)

    async def delete(
        self,
        path: str,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        return await self.request("DELETE", path, extra_headers=extra_headers)

    def stream_post(
        self,
        path: str,
        json: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> contextlib.AbstractAsyncContextManager[httpx.Response]:
        """streaming POST for the LLM gateway (async).
        Returns an httpx async context manager; caller uses
        `async with client.stream_post(...) as resp:` then
        `async for line in resp.aiter_lines():`. Connection releases on
        exit.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            **self.auth.get_headers(),
            **self._ref_headers(),
            **(extra_headers or {}),
        }
        url = f"{self.base_url}{path}"
        return self._client.stream("POST", url, json=json, headers=headers)

    async def close(self) -> None:
        await self._client.aclose()
