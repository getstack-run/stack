import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

describe('Provisioning MCP secret boundary', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('stack_partner_create_account sends controls only when it is given, and still returns no key', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({
      account_id: 'op_fixture', external_ref: 'cust_fixture', billing: 'partner', status: 'active', created: true, created_at: 'now', api_key: 'synthetic-key-never-return',
    }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const server = createStackMcpServer('http://localhost:0', 'synthetic-unused');
    const client = new Client({ name: 'partner-controls', version: '1' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      await client.callTool({ name: 'stack_partner_create_account', arguments: { external_ref: 'cust_1' } });
      const withControls = await client.callTool({ name: 'stack_partner_create_account', arguments: { external_ref: 'cust_2', controls: true } });
      const bodies = fetchMock.mock.calls.map((call) => JSON.parse(String((call[1] as { body: string }).body)) as Record<string, unknown>);
      expect(bodies).toEqual([{ external_ref: 'cust_1' }, { external_ref: 'cust_2', controls: true }]);
      expect(JSON.stringify(withControls)).not.toContain('synthetic-key-never-return');
    } finally { await client.close(); }
  });
  it.each([
    ['stack_create_inbound_webhook', { provider: 'generic', agent_id: 'agt_fixture' }, 'id'],
    ['stack_partner_create_account_webhook', { account_id: 'op_fixture', provider: 'generic', agent_id: 'agt_fixture' }, 'id'],
    ['stack_partner_create_account', { external_ref: 'cust_fixture' }, 'account_id'],
  ] as const)('%s returns only safe provisioning metadata', async (name, args, identifier) => {
    const canary = 'synthetic-secret-canary-never-return';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 'iwh_fixture', operator_id: 'op_fixture', account_id: 'op_fixture', provider: 'generic', agent_id: 'agt_fixture',
      webhook_url: 'https://api.example.invalid/v1/inbound/generic/fixture', signing_configured: true,
      webhook_secret: canary, provider_signing_secret: canary, api_key: canary,
      unexpected_future_field: { secret: canary }, created_at: '2026-09-07T00:00:00.000Z',
    }), { status: 201 })));
    const server = createStackMcpServer('http://localhost:0', 'synthetic-unused');
    const client = new Client({ name: 'provisioning-boundary', version: '1' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError).not.toBe(true);
      expect(JSON.stringify(result)).not.toContain(canary);
      const text = (result.content as Array<{ text: string }>)[0]!.text;
      expect(JSON.parse(text)[identifier]).toBe(identifier === 'id' ? 'iwh_fixture' : 'op_fixture');
      expect(text).not.toContain('unexpected_future_field');
    } finally { await client.close(); }
  });
});
