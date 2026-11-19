"""Async mirror of ProxyService."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable
from typing import Any, Callable, cast

from .._authority_request import authority_request_headers, create_authority_request_id
from ..client import AsyncHttpClient
from ..proxy import ProxyOperation, ProxyResponse
from ..service_mcp import service_mcp_request, service_mcp_url_of, tool_list_of, tool_result_of


class AsyncProxyService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def request(
        self,
        service: str,
        url: str,
        method: str = "GET",
        *,
        headers: dict[str, str] | None = None,
        body: Any | None = None,
        query: dict[str, str] | None = None,
        connection: str | None = None,
        passport_token: str | None = None,
        approval_id: str | None = None,
        authority_request_id: str | None = None,
        on_operation_id: Callable[[str], Awaitable[None] | None] | None = None,
    ) -> ProxyResponse:
        operation_id = authority_request_id
        if operation_id is None and method.upper() != "GET":
            operation_id = create_authority_request_id()
        if operation_id is not None and on_operation_id is not None:
            persisted = on_operation_id(operation_id)
            if inspect.isawaitable(persisted):
                await persisted

        extra_headers: dict[str, str] = {}
        if passport_token:
            extra_headers["X-Passport-Token"] = passport_token
        if approval_id:
            extra_headers["X-Intent-Approval-Id"] = approval_id
        extra_headers.update(authority_request_headers(operation_id))

        payload: dict[str, Any] = {
            "service": service,
            "url": url,
            "method": method,
        }
        if headers:
            payload["headers"] = headers
        if body is not None:
            payload["body"] = body
        if query:
            payload["query"] = query
        if connection is not None:
            payload["connection"] = connection

        try:
            data = await self._client.request(
                "POST",
                "/v1/proxy",
                json=payload,
                extra_headers=extra_headers if extra_headers else None,
            )
        except Exception as error:
            if operation_id is not None:
                cast("Any", error).operation_id = operation_id
            raise
        return ProxyResponse(
            status=data.get("status", 0),
            headers=data.get("headers", {}),
            body=data.get("body"),
            operation_id=operation_id,
        )

    async def service_tools(
        self,
        service: str,
        *,
        connection: str | None = None,
        passport_token: str | None = None,
        approval_id: str | None = None,
        authority_request_id: str | None = None,
    ) -> dict[str, Any]:
        """The tools a connected service that speaks MCP over HTTP offers; see ``ProxyService.service_tools``."""
        response = await self.request(
            service,
            service_mcp_url_of(await self._client.get("/v1/services/connected"), service, connection),
            "POST",
            connection=connection,
            body=service_mcp_request("tools/list"),
            passport_token=passport_token,
            approval_id=approval_id,
            authority_request_id=authority_request_id,
        )
        return tool_list_of(service, response.status, response.body)

    async def service_call_tool(
        self,
        service: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        connection: str | None = None,
        passport_token: str | None = None,
        approval_id: str | None = None,
        authority_request_id: str | None = None,
    ) -> dict[str, Any]:
        """Call one tool of a connected service; see ``ProxyService.service_call_tool``."""
        response = await self.request(
            service,
            service_mcp_url_of(await self._client.get("/v1/services/connected"), service, connection),
            "POST",
            connection=connection,
            body=service_mcp_request("tools/call", {"name": tool, "arguments": arguments or {}}),
            passport_token=passport_token,
            approval_id=approval_id,
            authority_request_id=authority_request_id,
        )
        return tool_result_of(service, tool, response.status, response.body)

    async def get_operation(
        self,
        operation_id: str,
        *,
        passport_token: str,
        include_response: bool = False,
    ) -> ProxyOperation:
        authority_request_headers(operation_id)
        return cast(
            "ProxyOperation",
            await self._client.request(
                "POST",
                "/v1/proxy/operations/get",
                json={"operation_id": operation_id, "include_response": include_response},
                extra_headers={"X-Passport-Token": passport_token},
            ),
        )

    async def get(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        return await self.request(service, url, "GET", **kwargs)

    async def post(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        return await self.request(service, url, "POST", **kwargs)

    async def put(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        return await self.request(service, url, "PUT", **kwargs)

    async def patch(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        return await self.request(service, url, "PATCH", **kwargs)

    async def delete(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        return await self.request(service, url, "DELETE", **kwargs)

    async def usage(self) -> dict[str, Any]:
        return cast("dict[str, Any]", await self._client.request("GET", "/v1/proxy/usage"))
