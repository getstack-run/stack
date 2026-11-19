import { describe, expect, it } from 'vitest';
import { PROVIDER_API_HOSTS } from './provider-api-hosts.js';
import {
  InvalidServiceMcpUrlError,
  SERVICE_MCP_ACCEPT,
  SERVICE_MCP_INITIALIZED_BODY,
  SERVICE_MCP_PROTOCOL_VERSION,
  SERVICE_MCP_ENDPOINTS,
  SERVICE_MCP_SERVICES,
  checkServiceMcpUrl,
  isServiceMcpCall,
  isServiceMcpSessionId,
  readServiceMcpAnswer,
  serviceMcpEndpoint,
  serviceMcpInitializeBody,
  serviceMcpRequestBody,
  serviceMcpUrlFromConnections,
  AmbiguousServiceMcpConnectionError,
} from './service-mcp.js';

describe('connected services that speak MCP over HTTP', () => {
  it('names an endpoint only for the services in the table, and never for a name that is only an object property', () => {
    expect(serviceMcpEndpoint('rentahuman')).toBe('https://rentahuman.ai/api/mcp');
    expect(serviceMcpEndpoint('slack')).toBeNull();
    expect(serviceMcpEndpoint('constructor')).toBeNull();
    expect(serviceMcpEndpoint('__proto__')).toBeNull();
    expect(SERVICE_MCP_SERVICES).toEqual(Object.keys(SERVICE_MCP_ENDPOINTS));
  });

  it("keeps every endpoint on a host the service's credential is allowed to reach, over https", () => {
    for (const [service, endpoint] of Object.entries(SERVICE_MCP_ENDPOINTS)) {
      const url = new URL(endpoint);
      expect(url.protocol, service).toBe('https:');
      expect(PROVIDER_API_HOSTS[service], service).toContain(url.hostname);
    }
  });

  it('builds a JSON-RPC request, with params only when there are some', () => {
    expect(serviceMcpRequestBody('tools/list')).toEqual({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(serviceMcpRequestBody('tools/call', { name: 'send_message', arguments: { content: 'Hi' } })).toEqual({
      jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'send_message', arguments: { content: 'Hi' } },
    });
  });
});

describe("a connection's mcp_url", () => {
  const hosts = ['mcp.acme.example', '.tools.example.org'];

  it('is accepted when it is https and on one of the allowed hosts of the connection, exact or under a dot-led domain', () => {
    expect(checkServiceMcpUrl('https://mcp.acme.example/rpc', hosts)).toBe('https://mcp.acme.example/rpc');
    expect(checkServiceMcpUrl('  https://MCP.acme.example:8443/rpc?v=2  ', hosts)).toBe('https://mcp.acme.example:8443/rpc?v=2');
    expect(checkServiceMcpUrl('https://eu.tools.example.org/mcp', hosts)).toBe('https://eu.tools.example.org/mcp');
  });

  it('is refused when it is not https, carries a user name or a fragment, or is not a web address', () => {
    for (const bad of ['http://mcp.acme.example/rpc', 'ftp://mcp.acme.example/rpc', 'mcp.acme.example/rpc', 'https://user:pw@mcp.acme.example/rpc', 'https://mcp.acme.example/rpc#x', '']) {
      expect(() => checkServiceMcpUrl(bad, hosts), bad).toThrow(InvalidServiceMcpUrlError);
    }
  });

  it('is refused when its host is not one the key may be sent to, so an address cannot send the key elsewhere', () => {
    for (const bad of ['https://evil.example/rpc', 'https://mcp.acme.example.evil.example/rpc', 'https://acme.example/rpc', 'https://example.org/mcp']) {
      expect(() => checkServiceMcpUrl(bad, hosts), bad).toThrow(/not one of this connection's allowed hosts/);
    }
    expect(() => checkServiceMcpUrl('https://mcp.acme.example/rpc', [])).toThrow(InvalidServiceMcpUrlError);
  });

  it('is read from the connection list: the first active connection of that provider that has one', () => {
    const list = [
      { provider: 'slack', status: 'active', mcp_url: null },
      { provider: 'custom_acme', status: 'revoked', mcp_url: 'https://old.acme.example/rpc' },
      { provider: 'custom_acme', status: 'active', mcp_url: 'https://mcp.acme.example/rpc' },
    ];
    expect(serviceMcpUrlFromConnections(list, 'custom_acme')).toBe('https://mcp.acme.example/rpc');
    expect(serviceMcpUrlFromConnections(list, 'slack')).toBeNull();
    expect(serviceMcpUrlFromConnections(list, 'nobody')).toBeNull();
    expect(serviceMcpUrlFromConnections({ not: 'a list' }, 'custom_acme')).toBeNull();
  });
});

describe('choosing among several connections of one service', () => {
  const list = [
    { id: 'scon_a', name: 'work', provider: 'custom_acme', status: 'active', mcp_url: 'https://mcp.acme.example/rpc' },
    { id: 'scon_b', name: 'Home', provider: 'custom_acme', status: 'active', mcp_url: 'https://mcp.acme.example/other' },
    { id: 'scon_c', name: 'old', provider: 'custom_acme', status: 'revoked', mcp_url: 'https://mcp.acme.example/old' },
  ];

  it('takes the connection whose id equals the selector, else whose name equals it ignoring case', () => {
    expect(serviceMcpUrlFromConnections(list, 'custom_acme', 'scon_b')).toBe('https://mcp.acme.example/other');
    expect(serviceMcpUrlFromConnections(list, 'custom_acme', 'HOME')).toBe('https://mcp.acme.example/other');
    expect(serviceMcpUrlFromConnections(list, 'custom_acme', 'Work')).toBe('https://mcp.acme.example/rpc');
  });

  it('is null for a selector that matches no active connection of that provider', () => {
    expect(serviceMcpUrlFromConnections(list, 'custom_acme', 'old')).toBeNull();
    expect(serviceMcpUrlFromConnections(list, 'custom_acme', 'scon_zzz')).toBeNull();
    expect(serviceMcpUrlFromConnections(list, 'slack', 'work')).toBeNull();
  });

  it('uses the one address when every connection gives it, and says which are meant when they differ', () => {
    const same = [list[0]!, { ...list[1]!, mcp_url: 'https://mcp.acme.example/rpc' }];
    expect(serviceMcpUrlFromConnections(same, 'custom_acme')).toBe('https://mcp.acme.example/rpc');
    expect(() => serviceMcpUrlFromConnections(list, 'custom_acme')).toThrow(AmbiguousServiceMcpConnectionError);
    try {
      serviceMcpUrlFromConnections(list, 'custom_acme');
    } catch (error) {
      expect((error as AmbiguousServiceMcpConnectionError).connections).toEqual([
        { id: 'scon_a', name: 'work' },
        { id: 'scon_b', name: 'Home' },
      ]);
    }
  });

  it('falls back to the default endpoint of a service STACK knows', () => {
    const rah = [{ id: 'scon_r', name: 'default', provider: 'rentahuman', status: 'active', mcp_url: null }];
    expect(serviceMcpUrlFromConnections(rah, 'rentahuman')).toBe('https://rentahuman.ai/api/mcp');
    expect(serviceMcpUrlFromConnections(rah, 'rentahuman', 'default')).toBe('https://rentahuman.ai/api/mcp');
  });
});

describe('reading what a service answered', () => {
  const ok = (body: unknown, status = 200) => readServiceMcpAnswer('rentahuman', { status, body });

  it('reads a JSON answer and the last event of an event stream', () => {
    expect(ok({ jsonrpc: '2.0', id: 1, result: { tools: [] } })).toEqual({ ok: true, result: { tools: [] } });
    const stream = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n\n';
    expect(ok(stream)).toEqual({ ok: true, result: { content: [] } });
    const two = 'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\ndata: {"jsonrpc":"2.0","id":1,"result":{"done":true}}\n\n';
    expect(ok(two)).toEqual({ ok: true, result: { done: true } });
  });

  it("answers the service's own refusal with its words whole, however long", () => {
    const words = 'x'.repeat(5000);
    const refused = ok({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: words } });
    expect(refused).toEqual({ ok: false, code: 'SERVICE_MCP_ERROR', message: `rentahuman refused the call: ${words}` });
  });

  it('answers a failed HTTP status, and an answer that is not MCP, without trusting what it says', () => {
    expect(ok('bad gateway', 502)).toMatchObject({ ok: false, code: 'SERVICE_MCP_HTTP_ERROR' });
    expect(ok('<html>sign in</html>')).toMatchObject({ ok: false, code: 'SERVICE_MCP_BAD_ANSWER' });
    expect(ok(['not', 'an', 'object'])).toMatchObject({ ok: false, code: 'SERVICE_MCP_BAD_ANSWER' });
    expect(ok({ jsonrpc: '2.0', id: 1 })).toMatchObject({ ok: false, code: 'SERVICE_MCP_BAD_ANSWER' });
    expect(ok({ jsonrpc: '2.0', id: 1, result: [1, 2] })).toMatchObject({ ok: false, code: 'SERVICE_MCP_BAD_ANSWER' });
  });
});

describe('the MCP session STACK opens around a call to a service', () => {
  const endpoint = 'https://mcp.example.com/mcp';
  const call = (body: unknown, overrides: Partial<{ method: string; finalUrl: string }> = {}) => ({
    method: 'POST',
    finalUrl: endpoint,
    bodyBytes: typeof body === 'string' ? body : JSON.stringify(body),
    ...overrides,
  });

  it('is a POST of one JSON-RPC request to the connection\'s own endpoint, never anything else', () => {
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/list')), endpoint)).toBe(true);
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/call', { name: 'a', arguments: {} })), endpoint)).toBe(true);
    expect(isServiceMcpCall(call({ jsonrpc: '2.0', id: 'x', method: 'resources/list' }), endpoint)).toBe(true);
    // The caller's own initialize, a notification, a batch and a body that is not JSON-RPC go as they are.
    expect(isServiceMcpCall(call(serviceMcpInitializeBody()), endpoint)).toBe(false);
    expect(isServiceMcpCall(call(SERVICE_MCP_INITIALIZED_BODY), endpoint)).toBe(false);
    expect(isServiceMcpCall(call([serviceMcpRequestBody('tools/list')]), endpoint)).toBe(false);
    expect(isServiceMcpCall(call({ id: 1, method: 'tools/list' }), endpoint)).toBe(false);
    expect(isServiceMcpCall(call('not json'), endpoint)).toBe(false);
    // Another path or host of the same service, another method, or a connection with no MCP endpoint is an ordinary call.
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/list'), { finalUrl: 'https://mcp.example.com/api' }), endpoint)).toBe(false);
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/list'), { finalUrl: 'https://other.example.com/mcp' }), endpoint)).toBe(false);
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/list'), { method: 'PUT' }), endpoint)).toBe(false);
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/list')), null)).toBe(false);
    expect(isServiceMcpCall({ method: 'POST', finalUrl: endpoint, bodyBytes: null }, endpoint)).toBe(false);
    // A query string on the call does not make it another endpoint.
    expect(isServiceMcpCall(call(serviceMcpRequestBody('tools/list'), { finalUrl: `${endpoint}?x=1` }), endpoint)).toBe(true);
  });

  it('opens with initialize at the version STACK speaks and accepts both answer forms', () => {
    expect(serviceMcpInitializeBody()).toMatchObject({ jsonrpc: '2.0', method: 'initialize', params: { protocolVersion: SERVICE_MCP_PROTOCOL_VERSION } });
    expect(SERVICE_MCP_ACCEPT).toBe('application/json, text/event-stream');
  });

  it('keeps only a session id of visible ASCII', () => {
    expect(isServiceMcpSessionId('a1b2-C3_d4')).toBe(true);
    expect(isServiceMcpSessionId('')).toBe(false);
    expect(isServiceMcpSessionId('has space')).toBe(false);
    expect(isServiceMcpSessionId('line\nbreak')).toBe(false);
    expect(isServiceMcpSessionId('x'.repeat(1025))).toBe(false);
    expect(isServiceMcpSessionId(undefined)).toBe(false);
  });
});
