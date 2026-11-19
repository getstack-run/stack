import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { MAX_ANY_OF_PER_SCOPE } from '@stack/shared';
import { createStackMcpServer } from './index.js';

// The description of a grant says how many choices of rules it takes: the number the schema enforces, not another.

describe('the grant tool\'s description of choices of rules', () => {
  it('names the limit the schema enforces', async () => {
    const server = createStackMcpServer('http://api.test', 'oauth_access_token', { profile: 'standard' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'grant-test', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const tools = (await client.listTools()).tools;
    const described = tools
      .map((tool) => JSON.stringify(tool.inputSchema))
      .filter((schema) => schema.includes('such choices to a grant'));
    expect(described.length).toBeGreaterThan(0);
    for (const schema of described) {
      expect(schema).toContain(`At most ${MAX_ANY_OF_PER_SCOPE} such choices to a grant.`);
      expect(schema).not.toMatch(/At most two/i);
    }
    expect(MAX_ANY_OF_PER_SCOPE).toBe(8);
  });
});
