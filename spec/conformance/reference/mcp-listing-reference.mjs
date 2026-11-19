// A reference MCP server of the listing rules (spec/mcp-tools/SPEC.md section 11), over the MCP
// TypeScript SDK and nothing of STACK's. It registers every tool of a catalog as a no-op, lists
// the ones a session is for, carries the load-on-demand hint, and sends
// `notifications/tools/list_changed` when a change of pieces changes the list. It is what an
// implementation of section 11 needs to be, in about a page.

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

const ALWAYS_LOAD = 'anthropic/alwaysLoad';

function listed(tool, session) {
  if (tool.audience === 'owner') return session.audience === 'owner';
  if (tool.audience === 'agent' && session.audience !== 'agent') return false;
  if (tool.pieces.length === 0) return true;
  return tool.pieces.some((piece) => session.pieces.has(piece));
}

/**
 * Build the `open` function the mcp-listing suite takes, over a catalog (the `tools` of tools.json).
 * `defects` turns one deliberate defect on, for the kit's own negative controls.
 * @param {object[]} catalog
 * @param {{ listEverything?: boolean, neverNotify?: boolean, alwaysLoadTrue?: boolean, narrowDirectory?: boolean, callUnlisted?: boolean }} [defects]
 */
export function referenceOpen(catalog, defects = {}) {
  return async function open({ audience, pieces, profile }) {
    const state = { audience, pieces: new Set(pieces) };
    const server = new McpServer({ name: 'reference', version: '0.0.0' });
    const registered = new Map();
    const inProfile = (tool) => tool.profiles.includes(profile);
    for (const tool of catalog.filter(inProfile)) {
      const hint = profile === 'standard' && tool.on_demand ? { [ALWAYS_LOAD]: false } : defects.alwaysLoadTrue && profile === 'standard' ? { [ALWAYS_LOAD]: true } : undefined;
      const entry = server.registerTool(
        tool.name,
        {
          title: tool.title ?? tool.name,
          description: tool.description ?? tool.name,
          inputSchema: {},
          annotations: tool.annotations ?? {},
          ...(hint ? { _meta: hint } : {}),
        },
        async () => ({ content: [{ type: 'text', text: '{}' }] }),
      );
      registered.set(tool.name, { entry, tool });
    }
    const apply = () => {
      let changed = false;
      for (const { entry, tool } of registered.values()) {
        // The directory profile is never narrowed.
        const on = profile === 'directory' || defects.listEverything ? true : listed(tool, state);
        if (entry.enabled !== on) {
          changed = true;
          // A plain assignment sends nothing: exactly one notice is sent below.
          entry.enabled = on;
        }
      }
      return changed;
    };
    apply();

    const client = new Client({ name: 'listing-suite', version: '0.0.0' });
    const handlers = [];
    client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      for (const handler of handlers) handler();
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    return {
      async listTools() {
        const out = [];
        let cursor;
        do {
          const page = await client.listTools(cursor ? { cursor } : undefined);
          out.push(...page.tools);
          cursor = page.nextCursor;
        } while (cursor);
        return out;
      },
      async callTool(name, args) {
        if (defects.callUnlisted) return { content: [], isError: false };
        return client.callTool({ name, arguments: args });
      },
      onToolListChanged(handler) {
        handlers.push(handler);
      },
      async setPieces(next) {
        state.pieces = new Set(next);
        if (apply() && !defects.neverNotify) server.sendToolListChanged();
      },
      async close() {
        await client.close();
      },
    };
  };
}
