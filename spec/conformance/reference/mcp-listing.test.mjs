// The reference MCP server and the engine's own MCP server must pass the mcp-listing suite, and
// the suite must fail servers that each have one deliberate defect.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { createStackMcpServer, ToolSetController } from '@stack/mcp-server';
import { describe, expect, it } from 'vitest';
import { formatReport, runMcpListingSuite } from '../src/index.mjs';
import { referenceOpen } from './mcp-listing-reference.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CATALOG = JSON.parse(readFileSync(join(HERE, '..', '..', 'mcp-tools', 'tools.json'), 'utf8')).tools;

const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

/** The `open` function of the engine's own server: the SDK client over an in-memory pair. */
function engineOpen() {
  return async function open({ audience, pieces, profile }) {
    const toolSet = profile === 'standard' ? new ToolSetController(audience, pieces) : undefined;
    const server = createStackMcpServer('http://api.test', 'sk_test_unused', { profile, ...(toolSet ? { toolSet } : {}) });
    const client = new Client({ name: 'listing-suite', version: '0.0.0' });
    const handlers = [];
    client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      for (const handler of handlers) handler();
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    return {
      async listTools() {
        return (await client.listTools()).tools;
      },
      callTool: (name, args) => client.callTool({ name, arguments: args }),
      onToolListChanged: (handler) => handlers.push(handler),
      ...(toolSet ? { setPieces: async (next) => void toolSet.update(next) } : {}),
      close: () => client.close(),
    };
  };
}

describe('the reference MCP server', () => {
  it('passes the suite over the whole catalog, with nothing skipped and no warning', async () => {
    const report = await runMcpListingSuite({ open: referenceOpen(CATALOG), catalog: CATALOG });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(report.results.length);
  });

  it('skips the change checks when the session cannot change its pieces', async () => {
    const open = referenceOpen(CATALOG);
    const report = await runMcpListingSuite({
      open: async (options) => {
        const { setPieces: _unused, ...session } = await open(options);
        return session;
      },
      catalog: CATALOG,
    });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id)).toEqual(['ML11', 'ML12', 'ML13']);
  });
});

describe('the engine\'s own MCP server', () => {
  it('passes the suite over the tools it serves', async () => {
    // The engine serves a part of the catalog: the tools its modules register.
    const probe = createStackMcpServer('http://api.test', 'sk_test_unused');
    const client = new Client({ name: 'probe', version: '0.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([probe.connect(serverTransport), client.connect(clientTransport)]);
    const served = new Set((await client.listTools()).tools.map((t) => t.name));
    await client.close();
    const catalog = CATALOG.filter((t) => served.has(t.name));
    expect(catalog.length).toBeGreaterThan(100);
    const report = await runMcpListingSuite({ open: engineOpen(), catalog });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });
});

describe('the suite fails a server with one defect', () => {
  const run = (defects) => runMcpListingSuite({ open: referenceOpen(CATALOG, defects), catalog: CATALOG });

  it('one that lists every tool to every session', async () => {
    const ids = mustFailed(await run({ listEverything: true }));
    expect(ids).toEqual(expect.arrayContaining(['ML01', 'ML02', 'ML05', 'ML06']));
  });

  it('one that never sends the list-changed notice', async () => {
    expect(mustFailed(await run({ neverNotify: true }))).toEqual(['ML11', 'ML12']);
  });

  it('one that marks tools alwaysLoad true', async () => {
    expect(mustFailed(await run({ alwaysLoadTrue: true }))).toEqual(expect.arrayContaining(['ML08']));
  });

  it('one whose unlisted tools can still be called', async () => {
    expect(mustFailed(await run({ callUnlisted: true }))).toEqual(['ML06']);
  });
});
