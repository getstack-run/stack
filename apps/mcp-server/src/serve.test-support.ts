import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createStackMcpHttpServer, type StackMcpHttpServer } from './serve.js';
import type { McpServeExtension } from './extension.js';

const activeServers: StackMcpHttpServer[] = [];


export function initializeBody() {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'stack-mcp-transport-test', version: '1.0.0' },
    },
  };
}

/** The engine's own server unless an extension is given: STACK's hosted tests pass their own. */
export async function startServerWith(extension: McpServeExtension | null, options: Parameters<typeof createStackMcpHttpServer>[0]) {
  const server = createStackMcpHttpServer(options, extension);
  activeServers.push(server);
  await server.listen(0, '127.0.0.1');
  const address = server.httpServer.address() as AddressInfo;
  return { server, baseUrl: `http://127.0.0.1:${address.port}` };
}

export const startServer = (options: Parameters<typeof createStackMcpHttpServer>[0]) => startServerWith(null, options);

export async function closeServers(): Promise<void> {
  await Promise.all(activeServers.splice(0).map((server) => server.close()));
}

export async function initialize(baseUrl: string, bearer: string) {
  return fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify(initializeBody()),
  });
}

export async function requestExistingSession(
  baseUrl: string,
  bearer: string,
  sessionId: string,
  body: Record<string, unknown>,
) {
  return fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Mcp-Session-Id': sessionId,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify(body),
  });
}

export async function initializeSession(baseUrl: string, bearer: string): Promise<string> {
  const response = await initialize(baseUrl, bearer);
  assert.equal(response.status, 200);
  const sessionId = response.headers.get('mcp-session-id');
  assert.ok(sessionId);
  await response.text();
  return sessionId;
}

export function openChunkedPost(
  baseUrl: string,
  headers: Record<string, string>,
): {
  request: ReturnType<typeof httpRequest>;
  response: Promise<{ status: number; body: string }>;
} {
  let request!: ReturnType<typeof httpRequest>;
  const response = new Promise<{ status: number; body: string }>((resolve, reject) => {
    request = httpRequest(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        ...headers,
      },
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on('data', (chunk: Buffer) => chunks.push(chunk));
      incoming.once('end', () => resolve({
        status: incoming.statusCode ?? 0,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.once('error', reject);
  });
  return { request, response };
}

export async function listToolNames(
  baseUrl: string,
  bearer: string,
  sessionId: string,
  id: number,
): Promise<string[]> {
  const response = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Mcp-Session-Id': sessionId,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params: {} }),
  });
  assert.equal(response.status, 200);
  const body = await response.text();
  const payloads = response.headers.get('content-type')?.includes('text/event-stream')
    ? body.split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => JSON.parse(line.slice(5).trim()) as Record<string, unknown>)
    : [JSON.parse(body) as Record<string, unknown>];
  const payload = payloads.find((candidate) => candidate['id'] === id) as {
    result?: { tools?: Array<{ name?: unknown }> };
  } | undefined;
  assert.ok(payload?.result?.tools);
  return payload.result.tools
    .map((tool) => tool.name)
    .filter((name): name is string => typeof name === 'string');
}

export function authContextResponse(
  principal: { type: 'operator' | 'member' | 'agent'; id: string } = { type: 'operator', id: 'op_test' },
  isPlatformStaff = false,
) {
  return new Response(JSON.stringify({
    principal,
    is_platform_staff: isPlatformStaff,
  }), { status: 200 });
}

export const DIRECTORY_RESOURCE = 'https://mcp.test/directory';
export const DIRECTORY_METADATA = 'https://mcp.test/.well-known/oauth-protected-resource/directory';

export function boundAuthContextResponse(oauthResource?: string) {
  return new Response(JSON.stringify({
    principal: { type: 'operator', id: 'op_test' },
    is_platform_staff: false,
    ...(oauthResource ? { oauth_resource: oauthResource } : {}),
  }), { status: 200 });
}

/** One bearer per resource: the fake API reports the resource each token was granted for. */
export function resourceAwareFetch(): typeof fetch {
  return async (_input, init) => {
    const authorization = new Headers(init?.headers).get('authorization');
    if (authorization === 'Bearer directory-token') return boundAuthContextResponse(DIRECTORY_RESOURCE);
    if (authorization === 'Bearer mcp-token') return boundAuthContextResponse('https://mcp.test/mcp');
    return boundAuthContextResponse();
  };
}
