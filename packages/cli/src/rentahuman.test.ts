import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api.js';
import { printJson } from './format.js';
import { cmdRentAHuman, cmdServiceMcp } from './rentahuman.js';

vi.mock('./api.js', async (importOriginal) => ({ ...(await importOriginal<object>()), api: vi.fn(async () => ({})) }));
vi.mock('./format.js', async (importOriginal) => ({ ...(await importOriginal<object>()), printJson: vi.fn() }));
vi.mock('./secret-input.js', () => ({ readSecretFromStdin: vi.fn(async () => 'passport-from-stdin') }));

const ACCOUNT = 'acct_abcdefgh1234';
const BASE = `/v1/accounts/${ACCOUNT}/rentahuman`;
const SIGNED = 'A'.repeat(96);
const PASSPORT = { 'X-Passport-Token': 'passport-from-stdin' };

beforeEach(() => vi.clearAllMocks());

describe('rentahuman CLI wire contract', () => {
  it('asks for the signup payment only once the terms are accepted, and sends what it was given', async () => {
    await expect(cmdRentAHuman(['join', ACCOUNT, '--country', 'US'])).rejects.toThrow(/--accept-terms/);
    expect(api).not.toHaveBeenCalled();
    await cmdRentAHuman(['join', ACCOUNT, '--country', 'US', '--city', 'Austin', '--agent-name', 'Scout', '--accept-terms']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/join`, { body: { country: 'US', accept_terms: true, city: 'Austin', agent_name: 'Scout' }, headers: {} });
  });

  it('sends the agent\'s signature as the agent, never without its Passport, and never reads a Passport from argv', async () => {
    await expect(cmdRentAHuman(['join-complete', ACCOUNT, 'rahj_1', '--signed', SIGNED])).rejects.toThrow(/--passport-stdin/);
    await expect(cmdRentAHuman(['join-complete', ACCOUNT, 'rahj_1', '--passport', 'secret'])).rejects.toThrow(/must not be placed in argv/);
    expect(api).not.toHaveBeenCalled();
    await cmdRentAHuman(['join-complete', ACCOUNT, 'rahj_1', '--signed', SIGNED, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/join/complete`, { body: { join_id: 'rahj_1', signed: SIGNED }, headers: PASSPORT });
    await cmdRentAHuman(['fund-complete', ACCOUNT, 'rahj_2', '--signed', SIGNED, '--passport-stdin']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/fund/complete`, { body: { fund_id: 'rahj_2', signed: SIGNED }, headers: PASSPORT });
  });

  it('asks for a top-up in whole cents and reads the connection', async () => {
    await cmdRentAHuman(['fund', ACCOUNT, '2500']);
    expect(api).toHaveBeenLastCalledWith('POST', `${BASE}/fund`, { body: { amount_cents: 2500 }, headers: {} });
    await expect(cmdRentAHuman(['fund', ACCOUNT, '12.50'])).rejects.toThrow(/whole number of cents/);
    await cmdRentAHuman(['get', ACCOUNT]);
    expect(api).toHaveBeenLastCalledWith('GET', BASE, { headers: {} });
    await expect(cmdRentAHuman(['wat'])).rejects.toThrow(/rentahuman takes/);
  });
});

describe('service tools and service call', () => {
  const listAnswer = { status: 200, headers: {}, body: { jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'send_message' }] } } };
  // The account's connection list gives each connection's effective mcp_url: where the call goes.
  const CONNECTIONS = [
    { id: 'scon_1', provider: 'rentahuman', status: 'active', mcp_url: 'https://rentahuman.ai/api/mcp' },
    { id: 'scon_2', provider: 'custom_acme_tools', status: 'active', mcp_url: 'https://mcp.acme.example/rpc' },
    { id: 'scon_3', provider: 'slack', status: 'active', mcp_url: null },
  ];

  it("send a tools/list to the service's own endpoint through the proxy as the agent, with an operation id, and print it as untrusted", async () => {
    vi.mocked(api).mockResolvedValueOnce(CONNECTIONS).mockResolvedValueOnce(listAnswer);
    await cmdServiceMcp(['tools', 'rentahuman', '--passport-stdin']);
    expect(vi.mocked(api).mock.calls[0]).toEqual(['GET', '/v1/services/connected']);
    const [method, path, options] = vi.mocked(api).mock.calls[1]!;
    expect([method, path]).toEqual(['POST', '/v1/proxy']);
    expect(options?.body).toMatchObject({ service: 'rentahuman', url: 'https://rentahuman.ai/api/mcp', method: 'POST', body: { method: 'tools/list' } });
    expect(options?.headers?.['X-Passport-Token']).toBe('passport-from-stdin');
    expect(options?.headers?.['X-STACK-Authority-Request-Id']).toMatch(/^[A-Za-z0-9_-]{22,256}$/);
    expect(printJson).toHaveBeenCalledWith({ service: 'rentahuman', tools: [{ name: 'send_message' }], untrusted: true });
  });

  it('work for any connected service that carries an mcp_url: the call goes to that address', async () => {
    vi.mocked(api).mockResolvedValueOnce(CONNECTIONS).mockResolvedValueOnce(listAnswer);
    await cmdServiceMcp(['tools', 'custom_acme_tools', '--passport-stdin']);
    expect(vi.mocked(api).mock.calls[1]![2]?.body).toMatchObject({ service: 'custom_acme_tools', url: 'https://mcp.acme.example/rpc', method: 'POST', body: { method: 'tools/list' } });
  });

  it('call a tool with its JSON arguments and a given operation id, so an exact repeat is one operation', async () => {
    vi.mocked(api).mockResolvedValueOnce(CONNECTIONS).mockResolvedValueOnce({ status: 200, headers: {}, body: { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'sent' }] } } });
    const id = 'r'.repeat(32);
    await cmdServiceMcp(['call', 'rentahuman', 'send_message', '--args', '{"conversationId":"cnv_1","content":"Thursday."}', '--request-id', id, '--passport-stdin']);
    const options = vi.mocked(api).mock.calls[1]![2];
    expect(options?.body).toMatchObject({ body: { method: 'tools/call', params: { name: 'send_message', arguments: { conversationId: 'cnv_1', content: 'Thursday.' } } } });
    expect(options?.headers?.['X-STACK-Authority-Request-Id']).toBe(id);
    expect(printJson).toHaveBeenCalledWith(expect.objectContaining({ tool: 'send_message', is_error: false, untrusted: true }));
  });

  it('refuse a service with no MCP address, bad arguments and a call with no Passport, before anything is sent through the proxy', async () => {
    vi.mocked(api).mockResolvedValueOnce(CONNECTIONS);
    await expect(cmdServiceMcp(['tools', 'slack', '--passport-stdin'])).rejects.toThrow(/no MCP address/);
    await expect(cmdServiceMcp(['call', 'rentahuman', 'send_message', '--args', '[1]', '--passport-stdin'])).rejects.toThrow(/one JSON object/);
    await expect(cmdServiceMcp(['tools', 'rentahuman'])).rejects.toThrow(/--passport-stdin/);
    await expect(cmdServiceMcp(['wat'])).rejects.toThrow(/service takes/);
    expect(vi.mocked(api).mock.calls.map((c) => c[1])).toEqual(['/v1/services/connected']);
  });

  it('with --connection picks the endpoint of that connection and sends the selector to the proxy; several addresses and no selector refuse', async () => {
    const TWO = [
      { id: 'scon_a', name: 'Work', provider: 'acme', status: 'active', mcp_url: 'https://a.example/mcp' },
      { id: 'scon_b', name: 'Personal', provider: 'acme', status: 'active', mcp_url: 'https://b.example/mcp' },
    ];
    vi.mocked(api).mockResolvedValueOnce(TWO).mockResolvedValueOnce(listAnswer);
    await cmdServiceMcp(['tools', 'acme', '--connection', 'personal', '--passport-stdin']);
    expect(vi.mocked(api).mock.calls[1]![2]?.body).toMatchObject({ service: 'acme', url: 'https://b.example/mcp', connection: 'personal' });
    vi.mocked(api).mockClear();
    vi.mocked(api).mockResolvedValueOnce(TWO);
    await expect(cmdServiceMcp(['tools', 'acme', '--passport-stdin'])).rejects.toThrow(/Work, Personal/);
    expect(vi.mocked(api)).toHaveBeenCalledTimes(1);
  });
});
