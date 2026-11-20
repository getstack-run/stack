import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, it } from 'node:test';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { initializeBody } from '../serve.test-support.js';
import { releaseAnsweredJsonStreams } from './transport-cleanup.js';

// The SDK transport keeps, for every request it answers in JSON mode, the stream entry that holds the whole answer, until
// the session closes. A client that lists the tools gets about a megabyte kept per call. The server releases the entry
// once the answer has gone out.

const open: Server[] = [];
afterEach(async () => {
  await Promise.all(open.splice(0).map((server) => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); })));
});

type Internals = { _webStandardTransport: { _streamMapping: Map<string, unknown>; _requestToStreamMapping: Map<unknown, string> } };
const mappings = (transport: StreamableHTTPServerTransport) => (transport as unknown as Internals)._webStandardTransport;

async function startSession(release: boolean) {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => 'session-1', enableJsonResponse: true });
  const mcp = new McpServer({ name: 'cleanup-test', version: '1.0.0' });
  mcp.registerTool('echo', {}, async () => ({ content: [{ type: 'text', text: 'echo' }] }));
  await mcp.connect(transport);
  const http = createServer((req, res) => {
    void (async () => {
      const body = await new Promise<unknown>((resolve) => {
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
      });
      try {
        await transport.handleRequest(req, res, body);
      } finally {
        if (release) releaseAnsweredJsonStreams(transport);
      }
    })();
  });
  open.push(http);
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  const post = async (body: unknown) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Mcp-Session-Id': 'session-1', 'Mcp-Protocol-Version': '2025-06-18' },
      body: JSON.stringify(body),
    });
    return (await response.json()) as { result?: { tools?: unknown[] } };
  };
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify(initializeBody()) }).then((r) => r.text());
  return { transport, post };
}

describe('the answered requests of a JSON-mode transport', () => {
  it('leave nothing held once each answer has gone out', async () => {
    const { transport, post } = await startSession(true);
    for (let id = 2; id < 12; id += 1) {
      const listed = await post({ jsonrpc: '2.0', id, method: 'tools/list', params: {} });
      assert.equal(listed.result?.tools?.length, 1);
    }
    assert.equal(mappings(transport)._streamMapping.size, 0);
    assert.equal(mappings(transport)._requestToStreamMapping.size, 0);
  });

  it('keep the entry of a request that is still waiting for its answer', async () => {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => 'session-2', enableJsonResponse: true });
    const internals = mappings(transport);
    internals._streamMapping.set('answered', { resolveJson: () => undefined });
    internals._streamMapping.set('waiting', { resolveJson: () => undefined });
    internals._streamMapping.set('standalone', { controller: {} });
    internals._requestToStreamMapping.set(7, 'waiting');
    releaseAnsweredJsonStreams(transport);
    assert.deepEqual([...internals._streamMapping.keys()].sort(), ['standalone', 'waiting']);
  });

  it('are left alone when the transport has no such tables', () => {
    assert.doesNotThrow(() => releaseAnsweredJsonStreams({} as StreamableHTTPServerTransport));
  });
});
