import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { StackError } from '../errors.js';

interface Sent {
  method: string;
  path: string;
  body: unknown;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string }) => {
      calls.push({
        method: init.method ?? 'GET',
        path: new URL(url).pathname,
        body: init.body ? JSON.parse(init.body) : undefined,
      });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const services = () => new Stack({ apiKey: 'sk_live_connect_link_test', baseUrl: 'http://api.fixture' }).services;

const LINK = {
  link_id: 'cnl_abc',
  provider: 'github',
  service_id: 'svc_github',
  method: 'key',
  status: 'pending',
  connection_id: null,
  expires_at: '2026-10-20T12:10:00.000Z',
  created_at: '2026-10-20T12:00:00.000Z',
  completed_at: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('services.createConnectLink', () => {
  it('posts the description of the account\'s own API under custom, and nothing else', async () => {
    const calls = stubFetch({ status: 201, body: { ...LINK, provider: 'custom_acme', url: 'https://getstack.run/app/connect/link/t' } });
    const custom = { name: 'Acme', description: 'Billing', allowed_hosts: ['api.acme.example'], template: 'bearer' };
    await services().createConnectLink({ custom });
    expect(calls).toEqual([{ method: 'POST', path: '/v1/services/connect-links', body: { custom } }]);
  });

  it('posts the address of the MCP endpoint of the API with the description, when it speaks MCP over HTTP', async () => {
    const calls = stubFetch({ status: 201, body: { ...LINK, provider: 'custom_acme', url: 'https://getstack.run/app/connect/link/t' } });
    const custom = { name: 'Acme', allowed_hosts: ['api.acme.example'], mcp_url: 'https://api.acme.example/mcp' };
    await services().createConnectLink({ custom });
    expect(calls).toEqual([{ method: 'POST', path: '/v1/services/connect-links', body: { custom } }]);
  });

  it('posts the service and returns the link with its one URL', async () => {
    const calls = stubFetch({ status: 201, body: { ...LINK, url: 'https://getstack.run/app/connect/link/token' } });
    const link = await services().createConnectLink({ service_id: 'github' });
    expect(calls).toEqual([{ method: 'POST', path: '/v1/services/connect-links', body: { service_id: 'github' } }]);
    expect(link).toMatchObject({ link_id: 'cnl_abc', status: 'pending', url: 'https://getstack.run/app/connect/link/token' });
  });

  it('sends the scopes only when given, and nothing else', async () => {
    const calls = stubFetch({ status: 201, body: { ...LINK, method: 'oauth', url: 'https://getstack.run/x' } });
    await services().createConnectLink({ service_id: 'github', scopes: ['repo'] });
    await services().createConnectLink({ service_id: 'github', scopes: undefined });
    expect(calls.map((call) => call.body)).toEqual([{ service_id: 'github', scopes: ['repo'] }, { service_id: 'github' }]);
  });

  it('surfaces the open-link limit as a StackError', async () => {
    stubFetch({ status: 429, body: { error: { code: 'RATE_LIMITED', message: 'Too many requests.' } } });
    await expect(services().createConnectLink({ service_id: 'github' })).rejects.toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    await expect(services().createConnectLink({ service_id: 'github' })).rejects.toBeInstanceOf(StackError);
  });
});

describe('services.listConnectLinks', () => {
  it('reads the links still waiting and returns the list, never a URL', async () => {
    const calls = stubFetch({ status: 200, body: { links: [LINK] } });
    const links = await services().listConnectLinks();
    expect(calls).toEqual([{ method: 'GET', path: '/v1/services/connect-links', body: undefined }]);
    expect(links).toEqual([LINK]);
    expect(JSON.stringify(links)).not.toContain('url');
  });
});

describe('services.getConnectLink', () => {
  it('reads the link by id, escaping the id, and never sees a URL', async () => {
    const calls = stubFetch({ status: 200, body: { ...LINK, status: 'connected', connection_id: 'conn_1', completed_at: '2026-10-20T12:03:00.000Z' } });
    const link = await services().getConnectLink('cnl_a/b');
    expect(calls).toEqual([{ method: 'GET', path: '/v1/services/connect-links/cnl_a%2Fb', body: undefined }]);
    expect(link).toMatchObject({ status: 'connected', connection_id: 'conn_1' });
    expect(link).not.toHaveProperty('url');
  });

  it('answers a link of another account as not found', async () => {
    stubFetch({ status: 404, body: { error: { code: 'NOT_FOUND', message: 'Connect link not found: cnl_x' } } });
    await expect(services().getConnectLink('cnl_x')).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 });
  });
});
