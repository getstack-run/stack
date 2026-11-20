import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { Stack } from '../index.js';
import { walletPaymentAuthorizationPayload, type AgentWalletKey } from '../wallet-key.js';
import { SERVICE_MCP_ENDPOINTS } from '../service-mcp.js';
import { signRentAHumanPayment } from './rentahuman.js';

interface Sent {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(answer: (sent: Sent) => unknown = () => ({})): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const sent: Sent = { method: init.method ?? 'GET', path: new URL(url).pathname, body: init.body ? JSON.parse(init.body) : undefined, headers: init.headers ?? {} };
      calls.push(sent);
      return new Response(JSON.stringify(answer(sent)), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_rah_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
});

const start = {
  join_id: 'rahj_1', amount_cents: 1000, pay_to: '0x3333333333333333333333333333333333333333',
  typed_data: { domain: {}, message: { value: '10000000' } }, wallet: { privy_app_id: 'app_1', wallet_id: 'w_1' }, expires_at: '2026-11-05T12:00:00.000Z',
};

describe('RentAHuman: opening an account and topping up', () => {
  it('sends the two steps to their routes, the agent under its Passport', async () => {
    const calls = stubFetch((sent) => (sent.path.endsWith('/join') ? start : { join_id: 'rahj_1', status: 'completed', connection_id: 'scon_1', agent_id: 'agt_1', wake_registered: true }));
    const { rentahuman } = stack();
    const began = await rentahuman.join('acct_1', { country: 'US', accept_terms: true }, { passportToken: 'ppt' });
    expect(began.join_id).toBe('rahj_1');
    await rentahuman.completeJoin('acct_1', { join_id: 'rahj_1', signed: 'c2ln' }, { passportToken: 'ppt' });
    await rentahuman.fund('acct_1', 2500, { passportToken: 'ppt' });
    await rentahuman.completeFund('acct_1', { fund_id: 'rahj_2', signed: 'c2ln' }, { passportToken: 'ppt' });
    await rentahuman.get('acct_1');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /v1/accounts/acct_1/rentahuman/join',
      'POST /v1/accounts/acct_1/rentahuman/join/complete',
      'POST /v1/accounts/acct_1/rentahuman/fund',
      'POST /v1/accounts/acct_1/rentahuman/fund/complete',
      'GET /v1/accounts/acct_1/rentahuman',
    ]);
    expect(calls[0]!.body).toEqual({ country: 'US', accept_terms: true });
    expect(calls[1]!.body).toEqual({ join_id: 'rahj_1', signed: 'c2ln' });
    expect(calls[2]!.body).toEqual({ amount_cents: 2500 });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('ppt');
    expect(calls[4]!.headers['X-Passport-Token']).toBeUndefined();
    // The two calls that pay from the wallet are made as the agent: the Passport is their bearer credential.
    expect(calls.map((c) => c.headers['Authorization'])).toEqual([
      'Bearer sk_live_rah_test', 'Bearer ppt', 'Bearer sk_live_rah_test', 'Bearer ppt', 'Bearer sk_live_rah_test',
    ]);
  });

  it('signs what the wallet asked to be signed with the agent\'s own key, and sends only the signature', async () => {
    const key: AgentWalletKey = { publicKey: 'pk', sign: vi.fn((payload: string) => `signed:${payload.length}`), exportPrivateKey: () => 'wallet-auth:x' };
    const calls = stubFetch((sent) => (sent.path.endsWith('/join') ? start : { join_id: 'rahj_1', status: 'completed', connection_id: 'scon_1', agent_id: 'agt_1', wake_registered: true }));
    const result = await stack().rentahuman.joinWithKey('acct_1', key, { country: 'US', accept_terms: true }, { passportToken: 'ppt' });
    expect(result.status).toBe('completed');
    const payload = walletPaymentAuthorizationPayload({ appId: 'app_1', walletId: 'w_1', typedData: start.typed_data });
    expect(key.sign).toHaveBeenCalledWith(payload);
    expect(signRentAHumanPayment(key, start)).toBe(`signed:${payload.length}`);
    expect(calls[1]!.body).toEqual({ join_id: 'rahj_1', signed: `signed:${payload.length}` });
    expect(JSON.stringify(calls)).not.toContain('wallet-auth:');
  });
});

describe('connected services that speak MCP: serviceTools and serviceCallTool', () => {
  // The account's connection list (each connection's effective mcp_url) answers the read; the proxy answers the call.
  const CONNECTIONS = [
    { id: 'scon_1', provider: 'rentahuman', status: 'active', mcp_url: 'https://rentahuman.ai/api/mcp' },
    { id: 'scon_2', provider: 'custom_acme_tools', status: 'active', mcp_url: 'https://mcp.acme.example/rpc' },
    { id: 'scon_3', provider: 'slack', status: 'active', mcp_url: null },
  ];
  const proxied = (rpc: unknown) => (sent: { path: string }) =>
    sent.path === '/v1/services/connected' ? CONNECTIONS : { operation_id: 'op', status: 200, headers: {}, body: rpc };
  const proxyCalls = (calls: Array<{ path: string }>) => calls.filter((c) => c.path === '/v1/proxy') as typeof calls;

  it('sends tools/list and tools/call to the service\'s endpoint through the proxy, and marks what comes back untrusted', async () => {
    const calls = stubFetch(proxied({ jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'search_humans', description: 'Search' }, { description: 'nameless' }] } }));
    const list = await stack().proxy.serviceTools('rentahuman', { passportToken: 'ppt' });
    expect(list).toEqual({ service: 'rentahuman', tools: [{ name: 'search_humans', description: 'Search' }], untrusted: true });
    expect(calls.map((c) => c.path)).toEqual(['/v1/services/connected', '/v1/proxy']);
    expect(calls[1]!.body).toMatchObject({
      service: 'rentahuman', url: 'https://rentahuman.ai/api/mcp', method: 'POST', body: { jsonrpc: '2.0', method: 'tools/list' },
    });
    expect(calls[1]!.headers['X-Passport-Token']).toBe('ppt');
    expect(typeof calls[1]!.headers['X-STACK-Authority-Request-Id']).toBe('string');
  });

  it('works for any connected service that carries an mcp_url: the call goes to that address', async () => {
    const calls = stubFetch(proxied({ jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'lookup' }], content: [], isError: false } }));
    expect((await stack().proxy.serviceTools('custom_acme_tools', { passportToken: 'ppt' })).tools).toEqual([{ name: 'lookup' }]);
    await stack().proxy.serviceCallTool('custom_acme_tools', 'lookup', { q: 'x' }, { passportToken: 'ppt' });
    const sent = proxyCalls(calls);
    expect(sent).toHaveLength(2);
    expect(sent[0]!.body).toMatchObject({ service: 'custom_acme_tools', url: 'https://mcp.acme.example/rpc', method: 'POST' });
    expect(sent[1]!.body).toMatchObject({ service: 'custom_acme_tools', url: 'https://mcp.acme.example/rpc', body: { method: 'tools/call', params: { name: 'lookup', arguments: { q: 'x' } } } });
  });

  it('calls a tool with its arguments, reuses the operation id for an exact retry, and reads an event-stream answer', async () => {
    const calls = stubFetch(proxied('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"dryRun\\":true}"}],"isError":false}}\n\n'));
    const result = await stack().proxy.serviceCallTool('rentahuman', 'create_bounty', { title: 'Shopfront', dryRun: true }, { passportToken: 'ppt', authorityRequestId: 'a'.repeat(32) });
    expect(result).toEqual({ service: 'rentahuman', tool: 'create_bounty', content: [{ type: 'text', text: '{"dryRun":true}' }], is_error: false, untrusted: true });
    expect(calls[1]!.body).toMatchObject({ body: { method: 'tools/call', params: { name: 'create_bounty', arguments: { title: 'Shopfront', dryRun: true } } } });
    expect(calls[1]!.headers['X-STACK-Authority-Request-Id']).toBe('a'.repeat(32));
  });

  it('throws a service\'s own error and a service that is not one STACK reaches by MCP; a tool\'s error result comes back flagged', async () => {
    stubFetch(proxied({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } }));
    await expect(stack().proxy.serviceCallTool('rentahuman', 'nope', {}, { passportToken: 'ppt' })).rejects.toMatchObject({ code: 'SERVICE_MCP_ERROR' });
    await expect(stack().proxy.serviceTools('slack', { passportToken: 'ppt' })).rejects.toMatchObject({ code: 'SERVICE_HAS_NO_MCP_ENDPOINT' });
    stubFetch(proxied({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'no such conversation' }], isError: true } }));
    expect(await stack().proxy.serviceCallTool('rentahuman', 'get_conversation', { conversationId: 'x' }, { passportToken: 'ppt' })).toMatchObject({ is_error: true });
    stubFetch((sent) => (sent.path === '/v1/services/connected' ? CONNECTIONS : { operation_id: 'op', status: 502, headers: {}, body: 'bad gateway' }));
    await expect(stack().proxy.serviceTools('rentahuman', { passportToken: 'ppt' })).rejects.toMatchObject({ code: 'SERVICE_MCP_HTTP_ERROR' });
  });

  it('passes the own refusal of a service on whole, however long', async () => {
    const words = 'why '.repeat(1000);
    stubFetch(proxied({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: words } }));
    await expect(stack().proxy.serviceCallTool('rentahuman', 'nope', {}, { passportToken: 'ppt' })).rejects.toMatchObject({ code: 'SERVICE_MCP_ERROR', message: `rentahuman refused the call: ${words}` });
  });

  it('keeps its endpoints equal to STACK\'s own table', () => {
    // The SDK is published without @stack/shared: the table is read from STACK's source by path.
    const source = readFileSync(new URL('../../../shared/src/constants/service-mcp.ts', import.meta.url), 'utf8');
    const table = [...source.matchAll(/^\s+(\w+): '(https:\/\/[^']+)',$/gm)].map((m) => [m[1], m[2]]);
    expect(Object.fromEntries(table)).toEqual(SERVICE_MCP_ENDPOINTS);
  });
});
