// A service's MCP endpoint, built on the MCP TypeScript SDK as a service would build it, served
// through a fetch function so no socket is opened. Used by the service-mcp suite's reference test
// and by the test of STACK's own proxy against it.

import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';

export const ENDPOINT_URL = 'https://mcp.service.example/mcp';
export const ENDPOINT_HOST = 'mcp.service.example';
export const ENDPOINT_KEY = 'svc_key_conformance';

function makeServer() {
  const server = new McpServer({ name: 'reference-service', version: '0.0.0' });
  server.registerTool('echo', { description: 'Says hello', inputSchema: {} }, async () => ({ content: [{ type: 'text', text: 'hello' }] }));
  return server;
}

/**
 * The endpoint as a fetch function. `sessions` true keeps a session per client (the SDK's stateful
 * mode, which refuses any request before initialize and any without its session id); false is the
 * SDK's stateless mode. `defect` breaks one rule on purpose. Every request is recorded, and the
 * endpoint checks the key itself (`X-API-Key`).
 *
 * @param {{ sessions: boolean, defect?: 'refuses_initialize' | 'bad_session_id' | 'redirects' }} options
 */
export function serviceEndpoint({ sessions, defect }) {
  const requests = [];
  const live = new Map();
  async function fetchFn(url, init) {
    const request = new Request(url, init);
    const body = init.body ? JSON.parse(String(init.body)) : null;
    requests.push({ method: request.method, headers: Object.fromEntries(request.headers), body });
    if (request.headers.get('x-api-key') !== ENDPOINT_KEY) return new Response('{"error":"unauthorized"}', { status: 401 });
    if (defect === 'refuses_initialize' && body?.method === 'initialize') {
      return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32600, message: 'closed' } });
    }
    if (defect === 'bad_session_id' && body?.method === 'initialize') {
      return Response.json(
        { jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'x', version: '0' } } },
        { headers: { 'mcp-session-id': 'has space' } },
      );
    }
    if (defect === 'redirects' && body?.method === 'tools/list') return new Response(null, { status: 307, headers: { location: 'https://elsewhere.example/mcp' } });
    if (!sessions) {
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await makeServer().connect(transport);
      return transport.handleRequest(request);
    }
    const id = request.headers.get('mcp-session-id');
    if (id) {
      const transport = live.get(id);
      if (!transport) return Response.json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Session not found' } }, { status: 404 });
      const answer = await transport.handleRequest(request);
      if (request.method === 'DELETE') live.delete(id);
      return answer;
    }
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => live.set(sid, transport),
    });
    await makeServer().connect(transport);
    return transport.handleRequest(request);
  }
  return { fetch: fetchFn, requests, live };
}
