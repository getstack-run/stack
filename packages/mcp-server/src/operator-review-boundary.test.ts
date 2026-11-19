import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

describe('Operator review MCP boundary', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('keeps read-only mission evidence tools and exposes no human review writer', async () => {
    const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'operator-review-boundary', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const names = (await client.listTools()).tools.map((tool) => tool.name);

    expect(names).toContain('stack_view_mission_activity');
    expect(names).toContain('stack_list_mission_operator_reviews');
    expect(names).toContain('stack_export_signed_record');
    expect(names).toContain('stack_list_signed_records');
    expect(names).toContain('stack_get_signed_record');
    expect(names).not.toContain('stack_create_mission_dossier');
    expect(names).not.toContain('stack_create_operator_review');
    expect(names).not.toContain('stack_replay_mission');
    expect(names).not.toContain('stack_list_mission_dossiers');

    await client.close();
  });
});
