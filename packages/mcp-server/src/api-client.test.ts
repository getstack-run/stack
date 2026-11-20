import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createApiClient } from './api-client.js';
import { createStackMcpServer } from './index.js';

const BASE = 'http://api.test';

function respond(body: string | null, init: ResponseInit) {
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response(body, init)));
}

async function connectedClient(): Promise<Client> {
  const server = createStackMcpServer(BASE, 'sk_test_unused');
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'api-client', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

afterEach(() => vi.unstubAllGlobals());

describe('api() response handling', () => {
  it('sends the Bearer token, JSON content type and body, and returns the parsed JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"id":"agt_1"}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const { api } = createApiClient(BASE, 'sk_test_key');

    await expect(api('POST', '/v1/agents', { name: 'a' }, { 'X-Extra': '1' })).resolves.toEqual({ id: 'agt_1' });
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/agents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer sk_test_key', 'X-Extra': '1' },
      body: '{"name":"a"}',
    });
  });

  it('treats a 204 with no body as a success, not a parse error', async () => {
    respond(null, { status: 204 });
    const { api } = createApiClient(BASE, 'sk_test_key');
    await expect(api('DELETE', '/v1/agents/agt_1')).resolves.toEqual({ ok: true, status: 204 });
  });

  it('treats a 200 with an empty body as a success', async () => {
    respond('', { status: 200 });
    const { api } = createApiClient(BASE, 'sk_test_key');
    await expect(api('POST', '/v1/agents/agt_1/revoke')).resolves.toEqual({ ok: true, status: 200 });
  });

  it('turns a 2xx body that is not JSON into a structured error, never a SyntaxError', async () => {
    respond('<html>gateway</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const { api } = createApiClient(BASE, 'sk_test_key');
    const error = await api('GET', '/v1/agents').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(SyntaxError);
    expect(JSON.parse((error as Error).message)).toEqual({
      code: 'API_RESPONSE_NOT_JSON',
      message: 'The STACK API answered HTTP 200 with a body that is not JSON (text/html).',
      status: 200,
    });
  });

  it('reports the status when an error response is not JSON', async () => {
    respond('<html>bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } });
    const { api } = createApiClient(BASE, 'sk_test_key');
    await expect(api('GET', '/v1/agents')).rejects.toThrow('API error: 502');
  });

  it('reports the status when an error response has no body', async () => {
    respond(null, { status: 502 });
    const { api } = createApiClient(BASE, 'sk_test_key');
    await expect(api('GET', '/v1/agents')).rejects.toThrow('API error: 502');
  });

  it('reports the status when an error body is JSON without an error object', async () => {
    for (const body of ['null', '[]', '"oops"', '{}']) {
      respond(body, { status: 500 });
      const { api } = createApiClient(BASE, 'sk_test_key');
      await expect(api('GET', '/v1/agents'), body).rejects.toThrow('API error: 500');
    }
  });

  it('keeps the API error message when the error body carries one', async () => {
    respond('{"error":{"message":"agent not found","code":"NOT_FOUND"}}', { status: 404 });
    const { api } = createApiClient(BASE, 'sk_test_key');
    await expect(api('GET', '/v1/agents/agt_x')).rejects.toThrow('agent not found');
  });

  it('rethrows a governance step-up with the approval id and url', async () => {
    respond(
      '{"error":{"code":"GOVERNANCE_APPROVAL_REQUIRED","message":"needs approval","details":{"approval_id":"gvr_1","approval_url":"https://getstack.run/approve/gvr_1"}}}',
      { status: 403 },
    );
    const { api } = createApiClient(BASE, 'sk_test_key');
    const error = await api('POST', '/v1/agents/register', {}).catch((e: unknown) => e);
    expect(JSON.parse((error as Error).message)).toEqual({
      code: 'GOVERNANCE_APPROVAL_REQUIRED',
      message: 'needs approval',
      approval_id: 'gvr_1',
      approval_url: 'https://getstack.run/approve/gvr_1',
    });
  });

  it.each(['PENDING', 'REJECTED', 'EXPIRED'])('rethrows a retry whose approval is %s with its typed code', async (state) => {
    respond(
      `{"error":{"code":"GOVERNANCE_APPROVAL_${state}","message":"cannot use it","details":{"approval_id":"gvr_1","status":"${state.toLowerCase()}"}}}`,
      { status: 403 },
    );
    const { api } = createApiClient(BASE, 'sk_test_key');
    const error = await api('POST', '/v1/agents/register', {}).catch((e: unknown) => e);
    expect(JSON.parse((error as Error).message)).toEqual({
      code: `GOVERNANCE_APPROVAL_${state}`,
      message: 'cannot use it',
      approval_id: 'gvr_1',
    });
  });
});

describe('the forwarded-client header', () => {
  const sentHeaders = (fetchMock: ReturnType<typeof vi.fn>, call: number) =>
    (fetchMock.mock.calls[call]![1] as { headers: Record<string, string> }).headers;

  it('is asked for on every call, so each one is signed anew, and the bearer is not touched', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    let issued = 0;
    const { api } = createApiClient(BASE, 'sk_test_key', { forwardedClient: () => `value-${++issued}` });
    await api('GET', '/v1/a');
    await api('GET', '/v1/b');
    expect(sentHeaders(fetchMock, 0)['x-stack-forwarded-client']).toBe('value-1');
    expect(sentHeaders(fetchMock, 1)['x-stack-forwarded-client']).toBe('value-2');
    expect(sentHeaders(fetchMock, 0)['Authorization']).toBe('Bearer sk_test_key');
  });

  it('is left out when the hook has no value, and when there is no hook', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await createApiClient(BASE, 'sk_test_key', { forwardedClient: () => undefined }).api('GET', '/v1/a');
    await createApiClient(BASE, 'sk_test_key').api('GET', '/v1/b');
    expect(sentHeaders(fetchMock, 0)).not.toHaveProperty('x-stack-forwarded-client');
    expect(sentHeaders(fetchMock, 1)).not.toHaveProperty('x-stack-forwarded-client');
  });

  it('leaves a call-made-as-an-agent bearer override as it is', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const { api } = createApiClient(BASE, 'sk_test_key', { forwardedClient: () => 'value' });
    await api('GET', '/v1/a', undefined, { Authorization: 'Bearer agent-passport' });
    expect(sentHeaders(fetchMock, 0)['Authorization']).toBe('Bearer agent-passport');
    expect(sentHeaders(fetchMock, 0)['x-stack-forwarded-client']).toBe('value');
  });
});

describe('tools over an empty or non-JSON API response', () => {
  it('returns the success result for a tool whose call answers 204', async () => {
    respond(null, { status: 204 });
    const client = await connectedClient();
    const result = await client.callTool({ name: 'stack_revoke_passport', arguments: { jti: 'jti_1' } });
    expect(result.isError).not.toBe(true);
    expect(result.content).toEqual([{ type: 'text', text: JSON.stringify({ ok: true, status: 204 }, null, 2) }]);
    await client.close();
  });

  it('returns a tool error, not a crash, when the API answers HTML', async () => {
    respond('<html>maintenance</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    const client = await connectedClient();
    const result = await client.callTool({ name: 'stack_list_agents', arguments: {} });
    expect(result.isError).toBe(true);
    expect(result.content).toEqual([
      expect.objectContaining({ type: 'text', text: expect.stringContaining('API_RESPONSE_NOT_JSON') }),
    ]);
    await client.close();
  });

});
