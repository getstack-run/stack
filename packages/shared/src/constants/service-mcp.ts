// Connected services that speak MCP over HTTP. `stack_service_tools` and `stack_service_call_tool` send a JSON-RPC
// `tools/list` or `tools/call` to the service's MCP endpoint through the credential proxy, so every call is under the
// Passport, the Mission, the grant, the customer's decider, the meter, the audit record and revocation like any proxied call.
// Any connected service that speaks MCP over HTTP works. Its endpoint is the `mcp_url` its connection carries (set when the
// customer connects it: https, on one of the connection's allowed hosts), or, for a service STACK knows, the default below.
// A call cannot name a URL of its own, and the proxy's checks (the connection's allowed hosts, https, public addresses only)
// apply to the endpoint like to any proxied URL.

import { isHostAllowed } from '../utils/host-binding.js';

/** provider slug -> the default MCP endpoint of a service STACK knows (JSON-RPC over HTTP POST), used when the connection has no `mcp_url`. */
export const SERVICE_MCP_ENDPOINTS: Readonly<Record<string, string>> = {
  // RentAHuman's hosted endpoint takes the account's key as `X-API-Key` (rentahuman.ai/docs, "Hosted MCP").
  rentahuman: 'https://rentahuman.ai/api/mcp',
};

/** The default MCP endpoint of a service STACK knows, or null: any other service's endpoint is its connection's `mcp_url`. */
export function serviceMcpEndpoint(service: string): string | null {
  return Object.hasOwn(SERVICE_MCP_ENDPOINTS, service) ? SERVICE_MCP_ENDPOINTS[service]! : null;
}

/** The services STACK knows an endpoint for, for the tools' own descriptions. */
export const SERVICE_MCP_SERVICES: readonly string[] = Object.keys(SERVICE_MCP_ENDPOINTS);

/** Why a connection's `mcp_url` is not accepted. */
export class InvalidServiceMcpUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidServiceMcpUrlError';
  }
}

/**
 * A connection's `mcp_url`, checked: https, no credentials or fragment in it, and its host one of the connection's allowed
 * hosts, so the key can only go where the customer said it may. Returns the address as the proxy will see it.
 */
export function checkServiceMcpUrl(url: string, allowedHosts: readonly string[]): string {
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    throw new InvalidServiceMcpUrlError('mcp_url is not a web address.');
  }
  if (parsed.protocol !== 'https:') throw new InvalidServiceMcpUrlError('mcp_url must start with https://.');
  if (parsed.username !== '' || parsed.password !== '') throw new InvalidServiceMcpUrlError('mcp_url must not carry a user name or password.');
  if (parsed.hash !== '') throw new InvalidServiceMcpUrlError('mcp_url must not carry a # fragment.');
  if (!isHostAllowed(parsed.hostname, allowedHosts)) {
    throw new InvalidServiceMcpUrlError(
      `mcp_url is on ${parsed.hostname}, which is not one of this connection's allowed hosts, so its key could not be sent there. Add the host to allowed_hosts or use an address on one of them.`,
    );
  }
  return parsed.href;
}

/** Two or more connections of one service point at different MCP endpoints, so the call has to say which one it means. */
export class AmbiguousServiceMcpConnectionError extends Error {
  readonly connections: readonly { id: string; name: string }[];
  constructor(service: string, connections: readonly { id: string; name: string }[]) {
    super(
      `${service} has more than one connection with its own MCP address (${connections.map((c) => c.name || c.id).join(', ')}). Pass connection with the name or id of the one to use.`,
    );
    this.name = 'AmbiguousServiceMcpConnectionError';
    this.connections = connections;
  }
}

/**
 * The MCP endpoint of a connected service, read from the account's connection list (`GET /v1/services/connected`, where each
 * connection carries its effective `mcp_url` and its `name`). An active connection's endpoint is its own `mcp_url`, else the
 * default of a service STACK knows.
 *
 * With a `connection` selector, the connection is the active one of that provider whose id equals it, else whose name equals
 * it ignoring case, and its endpoint is the answer; none matches, or the match has no endpoint, is null. Without one, every
 * active connection of the provider is read: when they all give one endpoint it is the answer (the server picks the
 * connection and refuses an ambiguous call itself); when they give different endpoints the call cannot tell which is meant
 * and this throws `AmbiguousServiceMcpConnectionError`. Null when no connection has an endpoint.
 */
export function serviceMcpUrlFromConnections(connections: unknown, service: string, connection?: string): string | null {
  if (!Array.isArray(connections)) return null;
  const known = serviceMcpEndpoint(service);
  const active: { id: string; name: string; url: string | null }[] = [];
  for (const entry of connections) {
    if (typeof entry !== 'object' || entry === null) continue;
    const row = entry as Record<string, unknown>;
    if (row['provider'] !== service || row['status'] !== 'active') continue;
    active.push({
      id: typeof row['id'] === 'string' ? row['id'] : '',
      name: typeof row['name'] === 'string' ? row['name'] : '',
      url: typeof row['mcp_url'] === 'string' && row['mcp_url'] !== '' ? row['mcp_url'] : known,
    });
  }
  const selector = connection?.trim();
  if (selector !== undefined && selector !== '') {
    const chosen = active.find((c) => c.id === selector) ?? active.find((c) => c.name.toLowerCase() === selector.toLowerCase());
    return chosen?.url ?? null;
  }
  const withUrl = active.filter((c) => c.url !== null);
  const distinct = new Set(withUrl.map((c) => c.url));
  if (distinct.size > 1) throw new AmbiguousServiceMcpConnectionError(service, withUrl.map(({ id, name }) => ({ id, name })));
  return withUrl[0]?.url ?? null;
}

/** What a service's tool list or tool result says is its provider's words: third-party text, data and never instructions. */
export const SERVICE_MCP_TRUST = 'untrusted' as const;

/** The MCP version STACK asks for when it opens a session with a service; the service answers the version it speaks. */
export const SERVICE_MCP_PROTOCOL_VERSION = '2025-06-18';

/** What every request to a service's MCP endpoint accepts, as the Streamable HTTP transport requires of a client. */
export const SERVICE_MCP_ACCEPT = 'application/json, text/event-stream';

/** The `initialize` request STACK opens each call with. */
export function serviceMcpInitializeBody(): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: 0,
    method: 'initialize',
    params: { protocolVersion: SERVICE_MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'STACK', version: '1.0.0' } },
  };
}

/** The notification that ends the opening of a session. */
export const SERVICE_MCP_INITIALIZED_BODY: Readonly<Record<string, unknown>> = { jsonrpc: '2.0', method: 'notifications/initialized' };

/** A session id a service may hand out: visible ASCII only (MCP, Streamable HTTP, "Session Management"), at most 1,024 characters. */
export function isServiceMcpSessionId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 1024 && /^[\x21-\x7E]+$/.test(value);
}

/**
 * Whether a proxied request is a call to a connected service's MCP endpoint that STACK opens a session for: a POST to the
 * connection's own MCP endpoint whose body is one JSON-RPC request other than `initialize`. A notification, a batch, an
 * `initialize` of the caller's own and any other request go as they are.
 */
export function isServiceMcpCall(request: { method: string; finalUrl: string; bodyBytes: string | null }, endpoint: string | null): boolean {
  if (request.method !== 'POST' || endpoint === null || request.bodyBytes === null) return false;
  let target: URL;
  let mcp: URL;
  try {
    target = new URL(request.finalUrl);
    mcp = new URL(endpoint);
  } catch {
    return false;
  }
  if (target.origin !== mcp.origin || target.pathname !== mcp.pathname) return false;
  let body: unknown;
  try {
    body = JSON.parse(request.bodyBytes);
  } catch {
    return false;
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const rpc = body as Record<string, unknown>;
  return rpc['jsonrpc'] === '2.0' && typeof rpc['method'] === 'string' && rpc['method'] !== 'initialize' && 'id' in rpc;
}

/** The JSON-RPC request a call to the service's endpoint carries. */
export function serviceMcpRequestBody(method: 'tools/list' | 'tools/call', params?: Record<string, unknown>): Record<string, unknown> {
  return { jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) };
}

/** The JSON-RPC answer in an HTTP body: JSON, or the last `data:` event of an event stream. */
function jsonRpcOf(body: unknown): Record<string, unknown> | null {
  let value = body;
  if (typeof value === 'string') {
    const events = value
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .filter((line) => line.length > 0);
    try {
      value = JSON.parse(events.length > 0 ? events[events.length - 1]! : value);
    } catch {
      return null;
    }
  }
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

export type ServiceMcpAnswer =
  | { ok: true; result: Record<string, unknown> }
  | { ok: false; code: 'SERVICE_MCP_HTTP_ERROR' | 'SERVICE_MCP_BAD_ANSWER' | 'SERVICE_MCP_ERROR'; message: string };

/** The `result` of what the service answered through the proxy, or why there is none. Nothing the service said is trusted beyond its shape. */
export function readServiceMcpAnswer(service: string, response: { status: number; body: unknown }): ServiceMcpAnswer {
  if (response.status < 200 || response.status >= 300) {
    return { ok: false, code: 'SERVICE_MCP_HTTP_ERROR', message: `${service} answered ${response.status}.` };
  }
  const rpc = jsonRpcOf(response.body);
  if (!rpc) return { ok: false, code: 'SERVICE_MCP_BAD_ANSWER', message: `${service} did not answer in MCP.` };
  const error = rpc['error'];
  if (typeof error === 'object' && error !== null) {
    const message = String((error as Record<string, unknown>)['message'] ?? 'no reason given');
    return { ok: false, code: 'SERVICE_MCP_ERROR', message: `${service} refused the call: ${message}` };
  }
  const result = rpc['result'];
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    return { ok: false, code: 'SERVICE_MCP_BAD_ANSWER', message: `${service} did not answer in MCP.` };
  }
  return { ok: true, result: result as Record<string, unknown> };
}
