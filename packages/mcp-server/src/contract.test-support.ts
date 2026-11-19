import { vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

/** The engine's server, or STACK's hosted one: the factory the tool under test is served by. */
export type ServerFactory = typeof createStackMcpServer;

// Capture the body of the FIRST non-idempotent api() POST/PATCH the tool
// makes. Returns the parsed JSON body (top-level object).
export async function captureOutboundBody(tool: string, input: Record<string, unknown>, create: ServerFactory = createStackMcpServer): Promise<Record<string, unknown>> {
  return (await captureOutboundRequest(tool, input, create)).body;
}

export async function captureOutboundRequest(
  tool: string,
  input: Record<string, unknown>,
  create: ServerFactory = createStackMcpServer,
): Promise<{ body: Record<string, unknown>; headers: Record<string, string> }> {
  let captured: Record<string, unknown> | null = null;
  let capturedHeaders: Record<string, string> = {};
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      if (captured === null && init.body && (init.method === 'POST' || init.method === 'PATCH')) {
        captured = JSON.parse(init.body) as Record<string, unknown>;
        capturedHeaders = init.headers ?? {};
      }
      // Return a benign success so the tool handler completes.
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );

  const server = create('http://localhost:0', 'sk_test_unused');
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'contract-test', version: '0.0.0' });
  await Promise.all([server.connect(st), client.connect(ct)]);
  await client.callTool({ name: tool, arguments: input });
  await client.close();

  if (captured === null) throw new Error(`${tool} made no POST/PATCH api() call`);
  return { body: captured, headers: capturedHeaders };
}
