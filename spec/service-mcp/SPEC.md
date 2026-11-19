# STACK Service MCP Calls

**Specification:** STACK Service MCP Calls
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

An agent can list and call the tools of a service its owner connected to STACK, when the service has an MCP endpoint (the MCP tools `stack_service_tools` and `stack_service_call_tool`, and the same calls in the SDKs). STACK makes those calls for the agent through its credential proxy. This document defines what STACK sends to the service's endpoint and what it expects back, so that a service can make sure it works with STACK. It is a profile of the Streamable HTTP transport of the [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).

Contents: 1 Conventions, 2 Model, 3 What STACK sends, 4 What STACK expects back, 5 Limits, 6 What this version does not define, 7 Security considerations, 8 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **service** is the party that runs the MCP endpoint. The **connection** is the owner's connection to the service in STACK: its credential, the hosts the credential may be sent to (`allowed_hosts`), and the endpoint's address (`mcp_url`). An endpoint conforms if it satisfies the MUSTs of section 4. The conformance kit (the `service-mcp` suite) tests them.

## 2. Model

- The endpoint is the connection's `mcp_url`: an `https` address on one of the connection's allowed hosts. An agent cannot name another address. For a few services STACK knows the endpoint itself; the connection then needs none.
- Each call from an agent is one MCP session: STACK opens it, sends the one request the agent asked for (`tools/list` or `tools/call`), and ends it. A session is never reused for a second call.
- STACK checks the call before it sends anything: the agent's Passport, its Mission, its grant to the connection, and the owner's own controls. A call that fails any check sends nothing to the service.
- The call is one action for STACK's meter and one entry in the owner's record, however many requests the session takes.

## 3. What STACK sends

Every request is an HTTP request to the endpoint's address, with these headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` (every request, the `DELETE` too) |
| `Accept` | `application/json, text/event-stream` |
| The credential | From the connection, in the header its credential template names (for example `X-API-Key: <key>`), else `Authorization: Bearer <token>` |
| `MCP-Protocol-Version` | The version the service answered to `initialize` (every request after it); `2025-06-18` when that answer is not visible ASCII of at most 64 characters |
| `Mcp-Session-Id` | The session id the service gave, when it gave one (every request after `initialize`) |
| `Signature`, `Signature-Input`, `Signature-Agent` | For an agent that has a STACK account: the request signed as the [Web Bot Auth Profile](../web-bot-auth/SPEC.md) defines |

A header the agent offers in place of the credential (`Authorization`, `X-API-Key`, `Api-Key`) is removed: the service only ever sees the connection's credential.

The requests of one call, in order:

1. `POST` with the body
   ```json
   {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"STACK","version":"1.0.0"}}}
   ```
2. `POST` with the body `{"jsonrpc":"2.0","method":"notifications/initialized"}`.
3. `POST` with the agent's request: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` or `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"<tool>","arguments":{...}}}`.
4. `DELETE`, only when the service gave a session id. STACK does not wait for its answer.

When step 1 or 2 fails (no answer, an answer that is not `2xx`, a JSON-RPC error, or a session id that is not visible ASCII), STACK does not send step 3. The agent is told the call was not sent (`SERVICE_MCP_SESSION_FAILED`), and may try again.

STACK sends step 3 at most once. When its answer is lost (a timeout or a dropped connection), STACK does not send it again; the agent is told the outcome is unknown.

## 4. What STACK expects back

An endpoint:

- MUST answer `initialize` with `2xx` and a JSON-RPC result that names a `protocolVersion`.
- MUST, when it gives a session id (`Mcp-Session-Id` on its answer to `initialize`), give one of visible ASCII (`0x21` to `0x7E`), at most 1,024 characters long.
- MUST answer `notifications/initialized` with `2xx` (`202` is usual).
- MUST answer `tools/list` and `tools/call` in that session with `2xx` and the JSON-RPC result the Model Context Protocol defines: a `tools` list whose entries each have a `name` and an `inputSchema`, and a `content` list for a call.
- MUST NOT answer with a redirect. STACK follows none.
- MAY answer any request as a JSON body or as an event stream (`text/event-stream`). STACK reads the last `data:` event of a stream as the answer.
- SHOULD end a session on `DELETE` with `2xx`, or answer `405` when it does not let a client end one.

An endpoint that keeps no sessions conforms as long as it takes these requests in this order.

## 5. Limits

| Limit | Value |
|---|---|
| Time to answer each request | 30 seconds |
| Size of an answer | 10 MB |
| Scheme | `https` only |
| Addresses | Public addresses only; the endpoint's host must be one of the connection's allowed hosts |
| Redirects | Never followed |

## 6. What this version does not define

- Server-to-client requests (sampling, elicitation, roots) and notifications in an event stream. STACK reads only the answer to its request.
- MCP methods other than `tools/list` and `tools/call`.
- OAuth sign-in to the service from STACK. The credential is the one the owner put on the connection.

## 7. Security considerations

- The credential is sent only to the connection's allowed hosts, over `https`, to public addresses, and the address is checked again right before each request.
- What the service returns (its tool list, tool results, anything a person wrote) is passed to the agent marked `untrusted`: third-party text, never instructions. It is scanned like any other text the proxy returns.
- STACK never returns the credential to the agent, and never sends a credential the agent offered.

## 8. Conformance

Run the `service-mcp` suite of the conformance kit against your endpoint with a credential STACK would send:

```
npx @getstackrun/conformance service-mcp --url https://your.host/mcp --header "X-API-Key: <test key>" [--tool <name> --tool-arguments '{}']
```

It sends exactly the requests of section 3 and checks the answers against section 4. Give `--tool` only for a tool that is safe to call with the arguments you give.
