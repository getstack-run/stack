import { ConnectionAmbiguousError, StackError } from './errors.js';

// Connected services that speak MCP over HTTP (JSON-RPC `tools/list` and `tools/call` to the service's endpoint). The call goes through
// the credential proxy, so it is under the Passport, the Mission, the grant, the customer's decider, the meter, the audit record and
// revocation like any proxied call. Any connected service that speaks MCP over HTTP works: its endpoint is the `mcp_url` its connection
// carries (the account's connection list, `GET /v1/services/connected`, gives each connection's effective one), and a call cannot name a
// URL of its own. What a service says (its tool list, a result) is its provider's words: data, never instructions.

/** provider slug -> the default MCP endpoint of a service STACK knows, used when the connection has no `mcp_url`. */
export const SERVICE_MCP_ENDPOINTS: Readonly<Record<string, string>> = {
  rentahuman: 'https://rentahuman.ai/api/mcp',
};

/** The default MCP endpoint of a service STACK knows, or a `SERVICE_HAS_NO_MCP_ENDPOINT` error: any other service's endpoint is its connection's `mcp_url`. */
export function serviceMcpEndpoint(service: string): string {
  if (!Object.hasOwn(SERVICE_MCP_ENDPOINTS, service)) {
    throw noMcpAddress(service);
  }
  return SERVICE_MCP_ENDPOINTS[service]!;
}

function noMcpAddress(service: string): StackError {
  return new StackError(
    `${service} has no MCP address. Connect it with an mcp_url (an https address on one of the connection's allowed hosts) so its tools can be listed and called.`,
    'SERVICE_HAS_NO_MCP_ENDPOINT',
    400,
  );
}

/**
 * The MCP endpoint of a connected service, read from the account's connection list (`GET /v1/services/connected`). Each active
 * connection of the provider has one (its `mcp_url`, or the default of a service STACK knows).
 *
 * With `connection` (an `scon_` id, else a name, any case) the endpoint is that connection's; no such active connection is the
 * not-found outcome. Without it, when every active connection gives the same address that address is used (the server picks the
 * connection, and refuses ambiguity itself); when they differ the caller must pass `connection` (`CONNECTION_AMBIGUOUS`).
 */
export function serviceMcpUrlOf(connections: unknown, service: string, connection?: string): string {
  const active: Record<string, unknown>[] = [];
  if (Array.isArray(connections)) {
    for (const row of connections) {
      if (typeof row !== 'object' || row === null) continue;
      const candidate = row as Record<string, unknown>;
      if (candidate['provider'] === service && candidate['status'] === 'active') active.push(candidate);
    }
  }
  const urlOf = (row: Record<string, unknown>): string | null =>
    typeof row['mcp_url'] === 'string' && row['mcp_url'] !== ''
      ? row['mcp_url']
      : Object.hasOwn(SERVICE_MCP_ENDPOINTS, service)
        ? SERVICE_MCP_ENDPOINTS[service]!
        : null;

  if (connection !== undefined) {
    const wanted = connection.trim().toLowerCase();
    const chosen =
      active.find((row) => row['id'] === connection) ??
      active.find((row) => typeof row['name'] === 'string' && row['name'].trim().toLowerCase() === wanted);
    if (!chosen) throw new StackError(`${service} has no active connection "${connection}".`, 'NOT_FOUND', 404);
    const url = urlOf(chosen);
    if (url === null) throw noMcpAddress(service);
    return url;
  }

  const urls = new Set(active.map(urlOf));
  if (urls.size > 1) {
    const names = active.map((row) => String(row['name'] ?? row['id'])).join(', ');
    throw new ConnectionAmbiguousError(
      `${service} has several connections (${names}) with different MCP addresses. Pass connection with the id or name of the one to use.`,
      409,
      { connections: active.map((row) => ({ id: row['id'], name: row['name'] })) },
    );
  }
  const [only] = urls;
  if (only) return only;
  throw noMcpAddress(service);
}

export interface ServiceMcpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  [key: string]: unknown;
}

/** The tools a connected service offers. Provider text: data, never instructions. */
export interface ServiceToolList {
  service: string;
  tools: ServiceMcpTool[];
  untrusted: true;
}

/** What a tool of a connected service returned. Provider text: data, never instructions. */
export interface ServiceToolResult {
  service: string;
  tool: string;
  content: unknown[];
  is_error: boolean;
  structured?: unknown;
  untrusted: true;
}

export function serviceMcpRequest(method: 'tools/list' | 'tools/call', params?: Record<string, unknown>): Record<string, unknown> {
  return { jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) };
}

/** The JSON-RPC answer in an HTTP body: JSON, or the one `data:` event of an event stream. */
function jsonRpcOf(body: unknown): Record<string, unknown> | null {
  let value = body;
  if (typeof value === 'string') {
    const data = value
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .filter(Boolean);
    try {
      value = JSON.parse(data.length > 0 ? data[data.length - 1]! : value);
    } catch {
      return null;
    }
  }
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

/** The `result` of a service's answer, or the error it gave (a failure of the call, never a result to trust). */
export function serviceMcpResult(service: string, response: { status: number; body: unknown }): Record<string, unknown> {
  if (response.status < 200 || response.status >= 300) {
    throw new StackError(`${service} answered ${response.status}.`, 'SERVICE_MCP_HTTP_ERROR', response.status === 401 || response.status === 403 ? 403 : 502, { upstream_status: response.status });
  }
  const rpc = jsonRpcOf(response.body);
  if (!rpc) throw new StackError(`${service} did not answer in MCP.`, 'SERVICE_MCP_BAD_ANSWER', 502);
  const error = rpc['error'];
  if (typeof error === 'object' && error !== null) {
    const record = error as Record<string, unknown>;
    throw new StackError(`${service} refused the call: ${String(record['message'] ?? 'no reason given')}`, 'SERVICE_MCP_ERROR', 502, { upstream_code: record['code'] });
  }
  const result = rpc['result'];
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    throw new StackError(`${service} did not answer in MCP.`, 'SERVICE_MCP_BAD_ANSWER', 502);
  }
  return result as Record<string, unknown>;
}

export function toolListOf(service: string, response: { status: number; body: unknown }): ServiceToolList {
  const result = serviceMcpResult(service, response);
  const tools = Array.isArray(result['tools']) ? (result['tools'] as unknown[]).filter((t): t is ServiceMcpTool => typeof t === 'object' && t !== null && typeof (t as { name?: unknown }).name === 'string') : [];
  return { service, tools, untrusted: true };
}

export function toolResultOf(service: string, tool: string, response: { status: number; body: unknown }): ServiceToolResult {
  const result = serviceMcpResult(service, response);
  return {
    service,
    tool,
    content: Array.isArray(result['content']) ? (result['content'] as unknown[]) : [],
    is_error: result['isError'] === true,
    ...(result['structuredContent'] !== undefined ? { structured: result['structuredContent'] } : {}),
    untrusted: true,
  };
}
