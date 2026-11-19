import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

const EXCLUDED_PUBLIC_TOOLS = [
  'stack_connect_custom_service',
  'stack_get_credential',
  'stack_import_authority_proof',
  'stack_add_authority_receiver_key',
  'stack_decide_authority_approval',
  'stack_activate_authority_binding',
  'stack_erase_authority_proof',
] as const;

async function connectedClient(): Promise<Client> {
  const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'public-boundary', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe('public MCP safety boundary', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('does not advertise secret handling or authority management', async () => {
    const client = await connectedClient();
    const names = (await client.listTools()).tools.map((tool) => tool.name);

    for (const name of EXCLUDED_PUBLIC_TOOLS) expect(names).not.toContain(name);
    // Resolving an event is the owner's, with no secret in it, so it is listed.
    expect(names).toContain('stack_resolve_security_event');
    expect(names).toContain('stack_request_authority');
    expect(names).toContain('stack_get_authority_request');

    await client.close();
  });

  it('creates only a pending Authority request and returns its human approval URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      request_id: 'aor_0123456789abcdef0123456789abcdef',
      status: 'pending',
      approval_url: 'https://getstack.run/app/approve/authority/aor_0123456789abcdef0123456789abcdef',
      created_at: '2026-08-26T10:00:00.000Z',
      expires_at: '2026-08-26T10:15:00.000Z',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'stack_request_authority',
      arguments: {
        organisation_name: 'Example AB',
        role_name: 'CFO',
        role_claim_path: 'roles',
        role_claim_value: 'cfo',
        agent_id: 'agt_support',
        service_connection_id: 'scon_stripe',
        provider: 'stripe',
        purpose: 'Refund a customer charge',
        http_method: 'POST',
        resource_path: '/v1/refunds',
        expires_at: '2026-08-26T10:10:00.000Z',
        idempotency_key: 'support-ticket-4815',
      },
    });
    expect(result.isError).not.toBe(true);
    expect(result.content).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'text', text: expect.stringContaining('"status": "pending"') }),
    ]));
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:0/v1/authority/enterprise-oidc/requests',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'Idempotency-Key': 'support-ticket-4815' }),
      }),
    );
    await client.close();
  });

  it('rejects direct invocation of every excluded tool', async () => {
    const client = await connectedClient();

    for (const name of EXCLUDED_PUBLIC_TOOLS) {
      const result = await client.callTool({ name, arguments: {} });
      expect(result.isError).toBe(true);
      expect(result.content).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'text', text: expect.stringMatching(/not found/i) }),
        ]),
      );
    }

    await client.close();
  });
});
