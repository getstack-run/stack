import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer, type McpProfile } from './index.js';

const SECRET = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0beef';

async function connectedClient(profile: McpProfile): Promise<Client> {
  const server = createStackMcpServer('http://localhost:0', 'sk_test_unused', { profile });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'notification-secret-boundary', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

function restResponse(body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status: 201, headers: { 'content-type': 'application/json' } });
}

describe('stack_add_delivery_method secret boundary', () => {
  afterEach(() => vi.unstubAllGlobals());

  for (const profile of ['standard', 'directory'] as const) {
    it(`never returns the webhook signing secret on the ${profile} profile`, async () => {
      const fetchMock = vi.fn().mockResolvedValue(restResponse({
        id: 'ndst_webhook123',
        channel_type: 'webhook',
        destination: 'https://hooks.example/stack',
        verified: false,
        webhook_secret: SECRET,
        webhook_secret_encrypted: 'kms:ciphertext',
      }));
      vi.stubGlobal('fetch', fetchMock);
      const client = await connectedClient(profile);
      const result = await client.callTool({
        name: 'stack_add_delivery_method',
        arguments: {
          channel_type: 'webhook',
          destination: 'https://hooks.example/stack',
          governance_approval_id: 'gvr_approved',
        },
      });
      await client.close();

      const text = (result.content as Array<{ text: string }>)[0]!.text;
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain(SECRET.slice(0, 16));
      expect(text).not.toContain('kms:ciphertext');
      const body = JSON.parse(text) as Record<string, unknown>;
      expect(body).toMatchObject({
        id: 'ndst_webhook123',
        channel_type: 'webhook',
        verified: false,
        webhook_secret_returned: false,
        webhook_secret_hint: '…beef',
      });
      expect(body).not.toHaveProperty('webhook_secret');
      expect(body).not.toHaveProperty('webhook_secret_encrypted');
      expect(String(body['webhook_secret_access'])).toContain('/rotate-secret');

      const [url, init] = fetchMock.mock.calls[0]!;
      expect(url).toBe('http://localhost:0/v1/notifications/destinations');
      expect(new Headers(init.headers).get('X-Governance-Approval')).toBe('gvr_approved');
    });
  }

  it('adds no secret fields for an email destination', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(restResponse({
      id: 'ndst_email', channel_type: 'email', destination: 'ops@example.com', verified: true,
    })));
    const client = await connectedClient('standard');
    const result = await client.callTool({
      name: 'stack_add_delivery_method',
      arguments: { channel_type: 'email', destination: 'ops@example.com' },
    });
    await client.close();
    const body = JSON.parse((result.content as Array<{ text: string }>)[0]!.text) as Record<string, unknown>;
    expect(body).toEqual({ id: 'ndst_email', channel_type: 'email', destination: 'ops@example.com', verified: true });
  });
});
