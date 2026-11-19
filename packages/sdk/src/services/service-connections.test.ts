import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack, ConnectionAmbiguousError, StackError, serviceMcpUrlOf } from '../index.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
}

function stubFetch(answer: (sent: Sent) => { status?: number; body: unknown }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string }) => {
      const parsed = new URL(url);
      const sent: Sent = { method: init.method ?? 'GET', path: parsed.pathname, search: parsed.search, body: init.body ? JSON.parse(init.body) : undefined };
      calls.push(sent);
      const reply = answer(sent);
      return new Response(JSON.stringify(reply.body), { status: reply.status ?? 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
});

const row = (id: string, name: string, mcp_url: string | null, extra: Record<string, unknown> = {}) => ({ id, provider: 'acme', status: 'active', name, mcp_url, ...extra });

describe('serviceMcpUrlOf with several connections', () => {
  const same = [row('scon_a', 'Work', 'https://a.example/mcp'), row('scon_b', 'Personal', 'https://a.example/mcp')];
  const different = [row('scon_a', 'Work', 'https://a.example/mcp'), row('scon_b', 'Personal', 'https://b.example/mcp')];

  it('uses the one address every connection shares, without a selector', () => {
    expect(serviceMcpUrlOf(same, 'acme')).toBe('https://a.example/mcp');
  });

  it('refuses addresses that differ, naming the connections', () => {
    let error: unknown;
    try {
      serviceMcpUrlOf(different, 'acme');
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ConnectionAmbiguousError);
    expect((error as ConnectionAmbiguousError).connections).toEqual([{ id: 'scon_a', name: 'Work' }, { id: 'scon_b', name: 'Personal' }]);
    expect((error as Error).message).toContain('connection');
  });

  it('picks by id first, then by name in any case', () => {
    expect(serviceMcpUrlOf(different, 'acme', 'scon_b')).toBe('https://b.example/mcp');
    expect(serviceMcpUrlOf(different, 'acme', 'work')).toBe('https://a.example/mcp');
    expect(serviceMcpUrlOf(different, 'acme', 'PERSONAL')).toBe('https://b.example/mcp');
  });

  it('does not find an unknown, inactive or other-provider connection', () => {
    const list = [...different, row('scon_c', 'Old', 'https://c.example/mcp', { status: 'revoked' })];
    expect(() => serviceMcpUrlOf(list, 'acme', 'Old')).toThrow(StackError);
    expect(() => serviceMcpUrlOf(list, 'acme', 'scon_zzz')).toThrow(/no active connection/);
    expect(() => serviceMcpUrlOf(list, 'slack', 'Work')).toThrow(/no active connection/);
  });

  it('keeps the old outcomes with one connection or none', () => {
    expect(serviceMcpUrlOf([row('scon_a', 'default', 'https://a.example/mcp')], 'acme')).toBe('https://a.example/mcp');
    expect(() => serviceMcpUrlOf([], 'acme')).toThrow(expect.objectContaining({ code: 'SERVICE_HAS_NO_MCP_ENDPOINT' }));
    expect(() => serviceMcpUrlOf([row('scon_a', 'default', null)], 'acme')).toThrow(expect.objectContaining({ code: 'SERVICE_HAS_NO_MCP_ENDPOINT' }));
  });
});

describe('connections on the wire', () => {
  it('sends connection on a proxy request only when given', async () => {
    const calls = stubFetch(() => ({ body: { status: 200, headers: {}, body: {} } }));
    await stack().proxy.request({ service: 'acme', method: 'GET', url: 'https://a.example/x' }, { passportToken: 'ppt' });
    await stack().proxy.request({ service: 'acme', method: 'GET', url: 'https://a.example/x', connection: 'Work' }, { passportToken: 'ppt' });
    expect(calls[0]!.body).not.toHaveProperty('connection');
    expect(calls[1]!.body).toMatchObject({ service: 'acme', connection: 'Work' });
  });

  it('selects the connection for serviceTools and serviceCallTool, and sends it to the proxy', async () => {
    const list = [row('scon_a', 'Work', 'https://a.example/mcp'), row('scon_b', 'Personal', 'https://b.example/mcp')];
    const calls = stubFetch((sent) => (sent.path === '/v1/services/connected' ? { body: list } : { body: { status: 200, headers: {}, body: { jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'x' }], content: [] } } } }));
    await stack().proxy.serviceTools('acme', { passportToken: 'ppt', connection: 'personal' });
    await stack().proxy.serviceCallTool('acme', 'x', {}, { passportToken: 'ppt', connection: 'scon_a' });
    const proxied = calls.filter((c) => c.path === '/v1/proxy');
    expect(proxied[0]!.body).toMatchObject({ url: 'https://b.example/mcp', connection: 'personal' });
    expect(proxied[1]!.body).toMatchObject({ url: 'https://a.example/mcp', connection: 'scon_a' });
    await expect(stack().proxy.serviceTools('acme', { passportToken: 'ppt' })).rejects.toBeInstanceOf(ConnectionAmbiguousError);
  });

  it('sends connection_name only when given, on connect, custom and connect links', async () => {
    const calls = stubFetch(() => ({ body: {} }));
    await stack().services.connect({ service_id: 'svc_1', scopes: ['read'], credential: 'k' });
    await stack().services.connect({ service_id: 'svc_1', scopes: ['read'], credential: 'k', connection_name: 'Work' });
    await stack().services.connectCustom({ name: 'Acme', credential: 'k', connection_name: 'Work' });
    await stack().services.createConnectLink({ service_id: 'github' });
    await stack().services.createConnectLink({ service_id: 'github', connection_name: 'Work' });
    await stack().services.createConnectLink({ custom: { name: 'Acme', allowed_hosts: ['a.example'], connection_name: 'Work' } });
    await stack().services.createConnectLink({ connect: { kind: 'post_address' } });
    expect(calls[0]!.body).not.toHaveProperty('connection_name');
    expect(calls[1]!.body).toMatchObject({ connection_name: 'Work' });
    expect(calls[2]!.body).toMatchObject({ connection_name: 'Work' });
    expect(calls[3]!.body).not.toHaveProperty('connection_name');
    expect(calls[4]!.body).toEqual({ service_id: 'github', connection_name: 'Work' });
    // A custom link carries the name inside `custom`; a key link carries none. The API refuses both at the top level.
    expect(calls[5]!.body).toEqual({ custom: { name: 'Acme', allowed_hosts: ['a.example'], connection_name: 'Work' } });
    expect(calls[6]!.body).toEqual({ connect: { kind: 'post_address' } });
  });

  it('renames a connection with a PATCH, the id encoded', async () => {
    const calls = stubFetch(() => ({ body: { id: 'scon_a', name: 'Work' } }));
    await stack().services.rename('scon_a/b', 'Work');
    expect(calls[0]).toMatchObject({ method: 'PATCH', path: '/v1/services/scon_a%2Fb', body: { connection_name: 'Work' } });
  });

  it('reads a credential by provider with an optional connection selector', async () => {
    const calls = stubFetch(() => ({ body: {} }));
    await stack().credentials.get('acme');
    await stack().credentials.get('acme', 'Work');
    expect(calls[0]!.search).toBe('');
    expect(calls[1]!.search).toBe('?connection=Work');
  });

  it('turns a 409 CONNECTION_AMBIGUOUS into a typed error that lists the connections', async () => {
    stubFetch(() => ({ status: 409, body: { error: { code: 'CONNECTION_AMBIGUOUS', message: 'Pass connection.', details: { connections: [{ id: 'scon_a', name: 'Work' }] } } } }));
    const refused = await stack().credentials.get('acme').catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(ConnectionAmbiguousError);
    expect((refused as ConnectionAmbiguousError).connections).toEqual([{ id: 'scon_a', name: 'Work' }]);
    expect((refused as ConnectionAmbiguousError).status).toBe(409);
  });
});
