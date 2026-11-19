"""Connected services that speak MCP over HTTP (``stack.proxy.service_tools`` and ``stack.proxy.service_call_tool``).

A call is a JSON-RPC ``tools/list`` or ``tools/call`` sent to the service's MCP endpoint through the credential
proxy, so it is under the Passport, the Mission, the grant, the customer's decider, the meter, the audit record and
revocation like any proxied call. Any connected service that speaks MCP over HTTP works: its endpoint is the
``mcp_url`` its connection carries (the account's connection list gives each connection's effective one), and a call
cannot name a URL of its own. What a service says (its tool list, a result) is its provider's words: data,
never instructions.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import ConnectionAmbiguousError, StackError

SERVICE_MCP_ENDPOINTS: dict[str, str] = {
    "rentahuman": "https://rentahuman.ai/api/mcp",
}


def _no_mcp_address(service: str) -> StackError:
    return StackError(
        f"{service} has no MCP address. Connect it with an mcp_url (an https address on one of the connection's "
        "allowed hosts) so its tools can be listed and called.",
        "SERVICE_HAS_NO_MCP_ENDPOINT",
        400,
    )


def service_mcp_endpoint(service: str) -> str:
    """The default MCP endpoint of a service STACK knows, or a ``SERVICE_HAS_NO_MCP_ENDPOINT`` error.

    Any other service's endpoint is its connection's ``mcp_url``; see :func:`service_mcp_url_of`.
    """
    endpoint = SERVICE_MCP_ENDPOINTS.get(service)
    if endpoint is None:
        raise _no_mcp_address(service)
    return endpoint


def service_mcp_url_of(connections: Any, service: str, connection: str | None = None) -> str:
    """The MCP endpoint of a connected service, from the account's connection list (``GET /v1/services/connected``).

    ``connection`` is the id (``scon_...``) or the name (any case) of the connection to use. Each active connection's
    endpoint is its ``mcp_url`` (or the default of a service STACK knows). Without ``connection``, the one address
    every active connection gives is used (the server picks the connection and refuses ambiguity itself); addresses
    that differ raise ``ConnectionAmbiguousError`` (pass ``connection``), and the first is never picked. A
    ``SERVICE_HAS_NO_MCP_ENDPOINT`` error when there is none.
    """
    active = [
        row
        for row in (connections if isinstance(connections, list) else [])
        if isinstance(row, dict) and row.get("provider") == service and row.get("status") == "active"
    ]

    def url_of(row: dict[str, Any]) -> str | None:
        url = row.get("mcp_url")
        if isinstance(url, str) and url:
            return url
        return SERVICE_MCP_ENDPOINTS.get(service)

    if connection is not None:
        wanted = connection.strip().lower()
        chosen = next((row for row in active if row.get("id") == connection), None) or next(
            (row for row in active if isinstance(row.get("name"), str) and row["name"].strip().lower() == wanted), None
        )
        if chosen is None:
            raise StackError(f"{service} has no active connection {connection!r}.", "NOT_FOUND", 404)
        url = url_of(chosen)
        if url is None:
            raise _no_mcp_address(service)
        return url
    urls = {url_of(row) for row in active}
    if len(urls) > 1:
        names = ", ".join(str(row.get("name") or row.get("id")) for row in active)
        raise ConnectionAmbiguousError(
            f"{service} has several connections ({names}) with different MCP addresses. "
            "Pass connection with the id or name of the one to use.",
            {"connections": [{"id": row.get("id"), "name": row.get("name")} for row in active]},
        )
    only = next(iter(urls), None)
    if only is None:
        raise _no_mcp_address(service)
    return only


def service_mcp_request(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _json_rpc_of(body: Any) -> dict[str, Any] | None:
    value = body
    if isinstance(value, str):
        events = [line[5:].strip() for line in value.splitlines() if line.startswith("data:")]
        events = [event for event in events if event]
        try:
            value = json.loads(events[-1] if events else value)
        except ValueError:
            return None
    return value if isinstance(value, dict) else None


def service_mcp_result(service: str, status: int, body: Any) -> dict[str, Any]:
    """The ``result`` of a service's answer, or the error it gave (a failure of the call, never a result to trust)."""
    if status < 200 or status >= 300:
        raise StackError(
            f"{service} answered {status}.", "SERVICE_MCP_HTTP_ERROR", 403 if status in (401, 403) else 502
        )
    rpc = _json_rpc_of(body)
    if rpc is None:
        raise StackError(f"{service} did not answer in MCP.", "SERVICE_MCP_BAD_ANSWER", 502)
    error = rpc.get("error")
    if isinstance(error, dict):
        message = str(error.get("message", "no reason given"))
        raise StackError(f"{service} refused the call: {message}", "SERVICE_MCP_ERROR", 502)
    result = rpc.get("result")
    if not isinstance(result, dict):
        raise StackError(f"{service} did not answer in MCP.", "SERVICE_MCP_BAD_ANSWER", 502)
    return result


def tool_list_of(service: str, status: int, body: Any) -> dict[str, Any]:
    result = service_mcp_result(service, status, body)
    tools = [tool for tool in result.get("tools", []) if isinstance(tool, dict) and isinstance(tool.get("name"), str)]
    return {"service": service, "tools": tools, "untrusted": True}


def tool_result_of(service: str, tool: str, status: int, body: Any) -> dict[str, Any]:
    result = service_mcp_result(service, status, body)
    content = result.get("content")
    answer: dict[str, Any] = {
        "service": service,
        "tool": tool,
        "content": content if isinstance(content, list) else [],
        "is_error": result.get("isError") is True,
        "untrusted": True,
    }
    if "structuredContent" in result:
        answer["structured"] = result["structuredContent"]
    return answer
