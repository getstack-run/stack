import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

describe('Identity settings MCP boundary', () => {
  it('exposes the read tool and the settings writer under its one name', async () => {
    const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'identity-settings-boundary', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const names = (await client.listTools()).tools.map((tool) => tool.name);

    expect(names).toContain('stack_get_identity_settings');
    expect(names).toContain('stack_set_identity_settings');
    expect(names).not.toContain('stack_update_identity_settings');

    await client.close();
  });
});
