import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Agent as HttpAgent, createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { RequestOptions } from 'node:https';
import { gzipSync } from 'node:zlib';

// Connection reuse is the sensitive part of publicFetch: a pooled
// socket must only ever be handed to a call whose destination re-passed the
// SSRF check AND resolved to exactly the address set the socket was opened
// for, and a socket that hit any failure must never go back to the pool.
//
// Test seam: the production code builds an `https.Agent` and calls
// `https.request`. Here `node:https` is replaced by an http.Agent subclass and
// a request function that sends the SAME options (agent included) to a
// loopback HTTP server, so real sockets are pooled, reused and destroyed by
// the real agent logic. TLS itself is not exercised by this file.
const fixtures = vi.hoisted(() => ({
  lookup: vi.fn(),
  request: vi.fn(),
  agents: [] as unknown[],
}));
vi.mock('node:dns/promises', () => ({ lookup: fixtures.lookup }));
vi.mock('node:https', async () => {
  const http = await vi.importActual<typeof import('node:http')>('node:http');
  class TestHttpsAgent extends http.Agent {
    constructor(options: ConstructorParameters<typeof http.Agent>[0]) {
      super(options);
      fixtures.agents.push(this);
    }
  }
  return { Agent: TestHttpsAgent, request: fixtures.request };
});
import { closePublicFetchPools, publicFetch } from './public-fetch.js';

describe('publicFetch keep-alive pool', () => {
  let server: Server;
  let port: number;
  let connections = 0;
  let handler: (request: IncomingMessage, response: ServerResponse) => void;
  const usedAgents: unknown[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => handler(request, response));
    server.on('connection', () => { connections += 1; });
    server.keepAliveTimeout = 30_000;
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as { port: number }).port;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  beforeEach(() => {
    connections = 0;
    usedAgents.length = 0;
    fixtures.agents.length = 0;
    fixtures.lookup.mockReset().mockResolvedValue([{ address: '1.1.1.1', family: 4 }]);
    fixtures.request.mockReset().mockImplementation((url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => {
      usedAgents.push(options.agent);
      return httpRequest(`http://127.0.0.1:${port}${url.pathname}`, {
        ...options, lookup: undefined, servername: undefined,
      } as RequestOptions, callback);
    });
    handler = (_request, response) => { response.end('{"ok":true}'); };
  });
  afterEach(() => {
    closePublicFetchPools();
    server.closeAllConnections();
  });

  const get = (options: Parameters<typeof publicFetch>[2] = {}, init: RequestInit = {}) =>
    publicFetch('https://provider.example/', init, { keepAlive: true, ...options });

  it('reuses one connection for repeated calls to the same checked destination', async () => {
    expect((await (await get()).json())).toEqual({ ok: true });
    expect((await (await get()).json())).toEqual({ ok: true });
    expect(connections).toBe(1);
    expect(usedAgents[0]).toBe(usedAgents[1]);
    expect(usedAgents[0]).toBeInstanceOf(HttpAgent);
    expect(fixtures.lookup).toHaveBeenCalledTimes(2);
  });

  it('never pools without the opt-in', async () => {
    await (await publicFetch('https://provider.example/')).text();
    await (await publicFetch('https://provider.example/')).text();
    expect(usedAgents).toEqual([false, false]);
  });

  it('refuses a blocked address before any socket, pooled or new', async () => {
    await (await get()).text();
    fixtures.lookup.mockResolvedValue([{ address: '10.0.0.1', family: 4 }]);
    await expect(get()).rejects.toThrow('non-public');
    await expect(get({ resolvedAddresses: ['169.254.169.254'] })).rejects.toThrow('non-public');
    expect(fixtures.request).toHaveBeenCalledTimes(1);
  });

  it('cannot hand an existing socket to a host that rebinds to a different address', async () => {
    await (await get()).text();
    expect(connections).toBe(1);
    // Rebind to a private address: refused outright.
    fixtures.lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    await expect(get()).rejects.toThrow('non-public');
    // Rebind to another public address: a different pool, a new connection.
    fixtures.lookup.mockResolvedValue([{ address: '2.2.2.2', family: 4 }]);
    await (await get()).text();
    expect(connections).toBe(2);
    expect(usedAgents[1]).not.toBe(usedAgents[0]);
    // A mixed answer that adds a blocked address is refused, not matched to a pool.
    fixtures.lookup.mockResolvedValue([{ address: '1.1.1.1', family: 4 }, { address: '10.1.2.3', family: 4 }]);
    await expect(get()).rejects.toThrow('non-public');
    expect(fixtures.request).toHaveBeenCalledTimes(2);
  });

  it('keys reuse on the exact address set, not on any overlap', async () => {
    fixtures.lookup.mockResolvedValue([{ address: '1.1.1.1', family: 4 }, { address: '2.2.2.2', family: 4 }]);
    await (await get()).text();
    fixtures.lookup.mockResolvedValue([{ address: '2.2.2.2', family: 4 }, { address: '1.1.1.1', family: 4 }]);
    await (await get()).text();
    expect(usedAgents[1]).toBe(usedAgents[0]);
    fixtures.lookup.mockResolvedValue([{ address: '1.1.1.1', family: 4 }]);
    await (await get()).text();
    expect(usedAgents[2]).not.toBe(usedAgents[0]);
  });

  it('does not reuse a socket after a response size cap error', async () => {
    handler = (_request, response) => { response.end('x'.repeat(500)); };
    await expect(get({ maxResponseBytes: 100 })).rejects.toThrow('size limit');
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('does not reuse a socket whose decoded body failed the cap after the wire response completed', async () => {
    // Small on the wire, large decoded: the agent takes the socket back when
    // the wire response ends, before the decoded-size check fails.
    handler = (_request, response) => { response.setHeader('content-encoding', 'gzip'); response.end(gzipSync('x'.repeat(50_000))); };
    await expect(get({ maxResponseBytes: 1_000 })).rejects.toThrow('size limit');
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('does not reuse a socket after a streamed cap error', async () => {
    handler = (_request, response) => { response.write('x'.repeat(80)); response.end('x'.repeat(80)); };
    await expect(get({ maxResponseBytes: 100 })).rejects.toThrow('size limit');
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('does not reuse a socket after the deadline fires', async () => {
    handler = (_request, response) => { response.writeHead(200); response.write('a'); };
    await expect(get({ timeoutMs: 50 })).rejects.toMatchObject({ name: 'AbortError' });
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('does not reuse a socket after a caller abort', async () => {
    const controller = new AbortController();
    handler = (_request, response) => { response.writeHead(200); response.write('a'); setTimeout(() => controller.abort(), 10); };
    await expect(get({}, { signal: controller.signal })).rejects.toBeDefined();
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('does not reuse a socket after a refused redirect', async () => {
    handler = (_request, response) => { response.writeHead(302, { location: 'http://127.0.0.1/private' }); response.end(); };
    await expect(get()).rejects.toThrow('redirect');
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('does not reuse a socket after a truncated body', async () => {
    handler = (_request, response) => {
      response.writeHead(200, { 'content-length': '50' });
      response.write('short');
      setImmediate(() => response.destroy());
    };
    await expect(get()).rejects.toThrow();
    handler = (_request, response) => { response.end('{"ok":true}'); };
    await (await get()).text();
    expect(connections).toBe(2);
  });

  it('keeps redirect refusal, caps and hop-by-hop stripping identical on a pooled socket', async () => {
    await (await get()).text();
    handler = (_request, response) => { response.writeHead(302, { location: 'https://elsewhere.example/' }); response.end(); };
    await expect(get({}, { headers: { authorization: 'Bearer fixture' } })).rejects.toThrow('redirect');
    handler = (request, response) => {
      expect(request.headers['proxy-authorization']).toBeUndefined();
      response.end('y'.repeat(200));
    };
    await expect(get({ maxResponseBytes: 100 }, { headers: { 'proxy-authorization': 'secret' } })).rejects.toThrow('size limit');
  });
});
