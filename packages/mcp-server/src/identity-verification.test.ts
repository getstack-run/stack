import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

async function connectedClient(): Promise<Client> {
  const server = createStackMcpServer('http://localhost:0', 'sk_test_unused');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'identity-verification-test', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe('stack_start_identity_verification', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('is advertised and starts the existing provider flow', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      session_id: 'ses_stack_123',
      session_ref: 'vs_provider_456',
      verification_url: 'https://provider.example/verify/vs_provider_456',
      expires_at: '2026-08-28T12:00:00.000Z',
      raw_response: { document: 'must never leave the API' },
      access_token: 'must-never-leave-the-api',
    }), { status: 201, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connectedClient();

    const names = (await client.listTools()).tools.map((tool) => tool.name);
    expect(names).toContain('stack_start_identity_verification');
    const result = await client.callTool({
      name: 'stack_start_identity_verification',
      arguments: {
        provider_key: 'stripe_identity',
        requested_claims: ['verified_identity'],
        return_url: 'https://getstack.run/app/identity',
      },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:0/v1/identity/verify/initiate',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          provider_key: 'stripe_identity',
          requested_claims: ['verified_identity'],
          return_url: 'https://getstack.run/app/identity',
        }),
      }),
    );
    const text = (result.content as Array<{ type: string; text: string }>)[0]!.text;
    expect(JSON.parse(text)).toEqual({
      session_id: 'ses_stack_123',
      session_ref: 'vs_provider_456',
      verification_url: 'https://provider.example/verify/vs_provider_456',
      expires_at: '2026-08-28T12:00:00.000Z',
    });
    expect(text).not.toContain('raw_response');
    expect(text).not.toContain('access_token');
    await client.close();
  });

  it('rejects an invalid return URL before calling the API', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'stack_start_identity_verification',
      arguments: {
        provider_key: 'stripe_identity',
        requested_claims: ['verified_identity'],
        return_url: 'not-a-url',
      },
    });
    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
    await client.close();
  });
});

describe('stack_get_identity_verification', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reads one session by its id, encoded in the path, and returns where it stands', async () => {
    const session = {
      session_id: 'ses_stack/123',
      provider_key: 'stripe_identity',
      session_ref: 'vs_provider_456',
      status: 'expired',
      requested_claims: ['verified_identity'],
      created_at: '2026-08-28T11:00:00.000Z',
      expires_at: '2026-08-28T12:00:00.000Z',
      completed_at: null,
    };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connectedClient();
    const result = await client.callTool({ name: 'stack_get_identity_verification', arguments: { session_id: 'ses_stack/123' } });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:0/v1/identity/verify/sessions/ses_stack%2F123',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(JSON.parse((result.content as Array<{ type: string; text: string }>)[0]!.text)).toEqual(session);
    await client.close();
  });
});
