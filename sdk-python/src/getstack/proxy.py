"""Credential proxy — send requests through STACK without seeing secrets."""

from __future__ import annotations

from typing import Any, Callable, Literal, TypedDict, cast

from ._authority_request import authority_request_headers, create_authority_request_id
from .client import HttpClient
from .service_mcp import service_mcp_request, service_mcp_url_of, tool_list_of, tool_result_of


class ProxyResponse:
    """Response from a proxied request."""

    __slots__ = ("body", "headers", "operation_id", "status")

    def __init__(
        self,
        status: int,
        headers: dict[str, str],
        body: Any,
        operation_id: str | None = None,
    ):
        self.status = status
        self.headers = headers
        self.body = body
        self.operation_id = operation_id

    def ok(self) -> bool:
        return 200 <= self.status < 400

    def json(self) -> Any:
        return self.body

    def __repr__(self) -> str:
        return f"ProxyResponse(status={self.status})"


class ProxyOperation(TypedDict, total=False):
    """Durable delivery, replay, and accounting state for one proxy write."""

    operation_id: str
    delivery_state: Literal["admitted", "dispatching", "response_received", "outcome_unknown"]
    replay_state: Literal["none", "screening", "available", "expired", "erased"]
    accounting_state: Literal["reserved", "committed", "released"]
    provider: str
    method: Literal["POST", "PUT", "PATCH", "DELETE"]
    created_at: str
    dispatched_at: str | None
    response_received_at: str | None
    # Set once the outcome stayed unknown for 7 days with nothing settling it: never sent again.
    unresolved_at: str | None
    provider_outcome: Literal["not_required", "pending", "confirmed", "not_found", "contradictory", "expired"]
    provider_status: Literal["pending", "requires_action", "succeeded", "failed", "canceled"] | None
    response: dict[str, Any]


class ProxyService:
    def __init__(self, client: HttpClient):
        self._client = client

    def request(
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
        on_operation_id: Callable[[str], None] | None = None,
    ) -> ProxyResponse:
        """Send a request through STACK's credential proxy.

        Args:
            service: Provider slug (e.g. "openai", "slack").
            url: Full target URL.
            method: HTTP method.
            headers: Extra headers (auth headers will be stripped).
            body: Request body.
            query: Query parameters.
            connection: The id (``scon_...``) or name of the connection to use, when the service has several.
                Without it a service with one connection uses that one, and one with several is refused
                (409 ``CONNECTION_AMBIGUOUS``, ``ConnectionAmbiguousError``, which lists them).
            passport_token: Passport JWT (required).
            approval_id: Approval id from ``intents.submit_and_wait``
                Required when the calling passport is
                in enforced mode. Sent as ``X-Intent-Approval-Id``.
            authority_request_id: Stable, high-entropy request identifier for
                operation recovery. Non-GET calls generate one before network
                I/O when omitted; persist ``response.operation_id`` and reuse
                it only for an unchanged retry.
            on_operation_id: Called before network I/O. Durable job runners
                should persist the supplied identifier here.
        """
        operation_id = authority_request_id
        if operation_id is None and method.upper() != "GET":
            operation_id = create_authority_request_id()
        if operation_id is not None and on_operation_id is not None:
            on_operation_id(operation_id)

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
            data = self._client.request(
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

    def service_tools(
        self,
        service: str,
        *,
        connection: str | None = None,
        passport_token: str | None = None,
        approval_id: str | None = None,
        authority_request_id: str | None = None,
    ) -> dict[str, Any]:
        """The tools a connected service that speaks MCP over HTTP offers (``tools/list``), through the proxy.

        The Passport, the Mission, the grant, the customer's decider, the meter and the audit record all apply.
        Works for any connected service whose connection carries its MCP address (``mcp_url``, given when it was
        connected) and for RentAHuman, whose address STACK knows. ``connection`` picks one of several connections of
        the service by id or name. The answer is the provider's words: ``untrusted``
        is always True.
        """
        response = self.request(
            service,
            service_mcp_url_of(self._client.get("/v1/services/connected"), service, connection),
            "POST",
            connection=connection,
            body=service_mcp_request("tools/list"),
            passport_token=passport_token,
            approval_id=approval_id,
            authority_request_id=authority_request_id,
        )
        return tool_list_of(service, response.status, response.body)

    def service_call_tool(
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
        """Call one tool of a connected service (``tools/call``) through the credential proxy.

        Reuse ``authority_request_id`` for an exact retry of a call with an effect (posting or funding a bounty,
        sending a message): one id is one operation. A service's own error is raised; a tool that reports an error
        in its result comes back with ``is_error`` True. The result is the provider's words: ``untrusted``.
        """
        response = self.request(
            service,
            service_mcp_url_of(self._client.get("/v1/services/connected"), service, connection),
            "POST",
            connection=connection,
            body=service_mcp_request("tools/call", {"name": tool, "arguments": arguments or {}}),
            passport_token=passport_token,
            approval_id=approval_id,
            authority_request_id=authority_request_id,
        )
        return tool_result_of(service, tool, response.status, response.body)

    def get_operation(
        self,
        operation_id: str,
        *,
        passport_token: str,
        include_response: bool = False,
    ) -> ProxyOperation:
        """Read operation status and optionally its stored screened response."""
        authority_request_headers(operation_id)
        return cast(
            "ProxyOperation",
            self._client.request(
                "POST",
                "/v1/proxy/operations/get",
                json={"operation_id": operation_id, "include_response": include_response},
                extra_headers={"X-Passport-Token": passport_token},
            ),
        )

    def get(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        """GET through proxy."""
        return self.request(service, url, "GET", **kwargs)

    def post(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        """POST through proxy."""
        return self.request(service, url, "POST", **kwargs)

    def put(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        """PUT through proxy."""
        return self.request(service, url, "PUT", **kwargs)

    def patch(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        """PATCH through proxy."""
        return self.request(service, url, "PATCH", **kwargs)

    def delete(self, service: str, url: str, **kwargs: Any) -> ProxyResponse:
        """DELETE through proxy."""
        return self.request(service, url, "DELETE", **kwargs)

    def usage(self) -> dict[str, Any]:
        """Get monthly proxy usage stats.

        Returns dict with: plan (platform, internal, contract or none: the plan the account is on), limit,
        used, remaining, period, and pooled=True on the accounts of a
        partner on a negotiated hard cap, whose counts are the partner's shared pool.
        """
        return cast("dict[str, Any]", self._client.request("GET", "/v1/proxy/usage"))
