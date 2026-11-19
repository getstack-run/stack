import { afterEach, describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

// A connect link exists so a credential never passes through the chat. The
// tools take no credential, return none, and the link status read does not
// return the link itself.

const BASE = 'http://api.test';
const TOKEN = 'T'.repeat(43);
const LINK = {
  link_id: 'cnl_abc123',
  provider: 'github',
  service_id: 'svc_github',
  method: 'key',
  status: 'pending',
  connection_id: null,
  expires_at: '2026-10-20T12:10:00.000Z',
  created_at: '2026-10-20T12:00:00.000Z',
  completed_at: null,
};

async function connect(profile: 'standard' | 'directory' = 'standard') {
  const server = createStackMcpServer(BASE, 'oauth_access_token', { profile });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'link-test', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

afterEach(() => vi.unstubAllGlobals());

describe('connect link tools', () => {
  it('create a link from a service id and scopes only, and return the page URL once', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ...LINK, url: `https://getstack.run/app/connect/link/${TOKEN}` }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const result = await client.callTool({ name: 'stack_create_connect_link', arguments: { service_id: 'github' } });
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/services/connect-links`, expect.objectContaining({
      method: 'POST', body: JSON.stringify({ service_id: 'github' }),
    }));
    expect(JSON.stringify(result.content)).toContain('/app/connect/link/');
  });

  it('accept no credential, secret or token as input in either profile', async () => {
    for (const profile of ['standard', 'directory'] as const) {
      const client = await connect(profile);
      const tools = (await client.listTools()).tools.filter((tool) => /connect_link/.test(tool.name));
      expect(tools.map((tool) => tool.name).sort()).toEqual(['stack_create_connect_link', 'stack_get_connect_link']);
      for (const tool of tools) {
        const properties = Object.keys((tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {});
        expect(properties.filter((name) => /credential|secret|key|token|password/i.test(name)), tool.name).toEqual([]);
      }
    }
  });

  it('create a link for the account\'s own API from its name and hosts only', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ...LINK, provider: 'custom_acme', url: `https://getstack.run/app/connect/link/${TOKEN}` }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const custom = { name: 'Acme', description: 'Our billing API', allowed_hosts: ['api.acme.example'] };
    const result = await client.callTool({ name: 'stack_create_connect_link', arguments: { custom } });
    expect(result.isError).not.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/services/connect-links`, expect.objectContaining({
      method: 'POST', body: JSON.stringify({ custom }),
    }));
  });

  it('refuse a credential inside custom, and a call that names both or neither, before the API is called', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const SECRET = ['never', 'echo', 'this', 'synthetic', 'value'].join('-');
    for (const field of ['credential', 'api_key', 'token', 'client_secret']) {
      const result = await client.callTool({
        name: 'stack_create_connect_link',
        arguments: { custom: { name: 'Acme', allowed_hosts: ['api.acme.example'], [field]: SECRET } },
      });
      expect(result.isError, field).toBe(true);
      expect(JSON.stringify(result), field).not.toContain(SECRET);
    }
    for (const args of [
      { service_id: 'github', custom: { name: 'Acme', allowed_hosts: ['api.acme.example'] } },
      {},
      { custom: { name: 'Acme', allowed_hosts: [] } },
    ]) {
      const result = await client.callTool({ name: 'stack_create_connect_link', arguments: args });
      expect(result.isError, JSON.stringify(args)).toBe(true);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('ignore scopes given with custom, which applies to a catalog service, and send the custom description alone', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ...LINK, url: `https://getstack.run/app/connect/link/${TOKEN}` }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const custom = { name: 'Acme', allowed_hosts: ['api.acme.example'] };
    const result = await client.callTool({ name: 'stack_create_connect_link', arguments: { custom, scopes: ['x'] } });
    expect(result.isError).toBeFalsy();
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/services/connect-links`, expect.objectContaining({
      method: 'POST', body: JSON.stringify({ custom }),
    }));
  });

  it('read a link by id and return its status without the URL or a credential', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(LINK), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const result = await client.callTool({ name: 'stack_get_connect_link', arguments: { link_id: 'cnl_abc123' } });
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/services/connect-links/cnl_abc123`, expect.objectContaining({ method: 'GET' }));
    const text = JSON.stringify(result.content);
    expect(text).not.toContain('/app/connect/link/');
    expect(text).not.toMatch(/credential|api_key|client_secret/i);
  });

  it('encode the link id as one path segment', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(LINK), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    await client.callTool({ name: 'stack_get_connect_link', arguments: { link_id: '../x?y=1' } });
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/services/connect-links/..%2Fx%3Fy%3D1`, expect.anything());
  });
});

describe('stack_connect_service', () => {
  // Built from parts so the literal is not secret-shaped in the source.
  const SECRET = ['never', 'echo', 'this', 'synthetic', 'value', '0123456789'].join('-');

  it('starts the connect-link flow with the service id and scopes and returns the link', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ...LINK, url: `https://getstack.run/app/connect/link/${TOKEN}` }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const result = await client.callTool({ name: 'stack_connect_service', arguments: { service_id: 'github', scopes: ['repo'] } });
    expect(result.isError).not.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/services/connect-links`, expect.objectContaining({
      method: 'POST', body: JSON.stringify({ service_id: 'github', scopes: ['repo'] }),
    }));
    expect(JSON.stringify(result.content)).toContain('/app/connect/link/');
  });

  it('takes the catalog arguments of stack_create_connect_link and no credential field', async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    const alias = tools.find((tool) => tool.name === 'stack_connect_service')!;
    const canonical = tools.find((tool) => tool.name === 'stack_create_connect_link')!;
    const directory = (await (await connect('directory')).listTools()).tools.find((tool) => tool.name === 'stack_create_connect_link')!;
    // The directory profile keeps the shape it was reviewed with; the standard profile's old name adds only the connection's name.
    const names = (tool: { inputSchema: unknown }) => Object.keys((tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {}).sort();
    expect(names(directory)).toEqual(['scopes', 'service_id']);
    expect(names(alias)).toEqual(['connection_name', 'scopes', 'service_id']);
    // The standard profile's create tool adds the account's own API and the keys of its own supplier accounts; the old name stays catalog-only.
    expect(Object.keys((canonical.inputSchema as { properties?: Record<string, unknown> }).properties ?? {}).sort()).toEqual(['connect', 'connection_name', 'custom', 'scopes', 'service_id']);
    expect(alias.description).toMatch(/stack_create_connect_link/);
  });

  it('refuses a credential argument, tells the caller to use the link and never echoes or logs the value', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const logged: unknown[][] = [];
    for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => { logged.push(args); });
    }
    const client = await connect();
    for (const field of ['credential', 'oauth_token', 'api_key', 'token', 'client_secret']) {
      const result = await client.callTool({ name: 'stack_connect_service', arguments: { service_id: 'slack', scopes: ['chat:write'], [field]: SECRET } });
      expect(result.isError, field).toBe(true);
      const text = JSON.stringify(result);
      expect(text, field).toMatch(/connect link/i);
      expect(text, field).toMatch(/stack_create_connect_link/);
      expect(text, field).not.toContain(SECRET);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    expect(JSON.stringify(logged)).not.toContain(SECRET);
    vi.restoreAllMocks();
  });

  it('keeps every secret out of the transcript of a successful call', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ...LINK, url: `https://getstack.run/app/connect/link/${TOKEN}` }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const result = await client.callTool({ name: 'stack_connect_service', arguments: { service_id: 'slack' } });
    const text = JSON.stringify(result.content);
    expect(text).not.toMatch(/credential"|api_key|client_secret|oauth_token/i);
  });
});

describe('stack_list_approvals', () => {
  const row = (id: string, status: string, extra: Record<string, unknown> = {}) => ({
    id, action: 'agent_unblock', resource_id: 'agt_1', summary: `Unblock agent ${id}`, status, requested_via: 'oauth',
    expires_at: '2026-10-21T12:00:00.000Z', created_at: '2026-10-20T12:00:00.000Z', decided_at: null,
    policy_preview: { secret: 'x' }, ...extra,
  });
  const listed = async (args: Record<string, unknown>, approvals: unknown[]) => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ approvals }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect('directory');
    const result = await client.callTool({ name: 'stack_list_approvals', arguments: args });
    const text = (result.content as Array<{ text: string }>)[0]!.text;
    const body = (result.isError ? { approvals: [] } : JSON.parse(text)) as { approvals: Array<Record<string, unknown>> };
    return { fetchMock, result, body };
  };

  it('reads the account\'s approvals with one GET and returns only the fields a person needs to tell them apart', async () => {
    const { fetchMock, body } = await listed({}, [row('gvr_a', 'pending'), row('gvr_b', 'approved', { decided_at: '2026-10-20T12:05:00.000Z' })]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/governance/approvals`, expect.objectContaining({ method: 'GET' }));
    expect(body.approvals.map((a) => a['id'])).toEqual(['gvr_a', 'gvr_b']);
    expect(body.approvals[0]).toMatchObject({ id: 'gvr_a', action: 'agent_unblock', status: 'pending', expires_at: '2026-10-21T12:00:00.000Z' });
    expect(body.approvals[0]).not.toHaveProperty('policy_preview');
    expect(JSON.stringify(body)).not.toMatch(/payload_hash|approval_url/);
  });

  it('lists one status and caps the count, newest first as the API sends them', async () => {
    const rows = [row('gvr_1', 'pending'), row('gvr_2', 'expired'), row('gvr_3', 'pending'), row('gvr_4', 'pending')];
    expect((await listed({ status: 'pending' }, rows)).body.approvals.map((a) => a['id'])).toEqual(['gvr_1', 'gvr_3', 'gvr_4']);
    expect((await listed({ status: 'pending', limit: 2 }, rows)).body.approvals.map((a) => a['id'])).toEqual(['gvr_1', 'gvr_3']);
    expect((await listed({}, Array.from({ length: 30 }, (_, i) => row(`gvr_${i}`, 'pending')))).body.approvals).toHaveLength(20);
  });

  it('keeps the partner\'s tenant label and refuses an unknown status or an out-of-range limit before calling the API', async () => {
    const { body } = await listed({}, [row('gvr_t', 'pending', { tenant: { operator_id: 'op_t', name: 'Acme' } })]);
    expect(body.approvals[0]).toMatchObject({ tenant: { operator_id: 'op_t', name: 'Acme' } });
    for (const args of [{ status: 'decided' }, { limit: 0 }, { limit: 101 }]) {
      const { fetchMock, result } = await listed(args, []);
      expect(result.isError, JSON.stringify(args)).toBe(true);
      expect(fetchMock, JSON.stringify(args)).not.toHaveBeenCalled();
    }
  });
});

describe('stack_get_approval', () => {
  it('returns the approval and its link, not the payload hash', async () => {
    const detail = {
      approval: {
        id: 'gvr_one', action: 'agent_unblock', resource_id: 'agt_1', summary: 'Unblock agent agt_1', status: 'pending',
        requested_via: 'oauth', expires_at: '2026-10-21T12:00:00.000Z', created_at: '2026-10-20T12:00:00.000Z', decided_at: null,
        policy_preview: { secret: 'x' },
      },
      payload_hash: 'a'.repeat(64),
      approval_url: 'https://getstack.run/app/approve/gvr_one',
    };
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(detail), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect('directory');
    const result = await client.callTool({ name: 'stack_get_approval', arguments: { approval_id: 'gvr_one' } });
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/v1/governance/approvals/gvr_one`, expect.objectContaining({ method: 'GET' }));
    const body = JSON.parse((result.content as Array<{ text: string }>)[0]!.text) as { approval: Record<string, unknown>; approval_url: string };
    expect(body.approval).toMatchObject({ id: 'gvr_one', action: 'agent_unblock', status: 'pending', expires_at: '2026-10-21T12:00:00.000Z' });
    expect(body.approval_url).toBe('https://getstack.run/app/approve/gvr_one');
    expect(JSON.stringify(body)).not.toContain('a'.repeat(64));
    expect(body.approval).not.toHaveProperty('policy_preview');
  });

  it('refuses an id that is not an approval id before calling the API', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = await connect();
    const result = await client.callTool({ name: 'stack_get_approval', arguments: { approval_id: '../../x' } });
    expect(result.isError).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
