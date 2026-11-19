import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createServer, request as httpRequest, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import type { RequestOptions } from 'node:https';
import { gzipSync } from 'node:zlib';

const fixtures = vi.hoisted(() => ({
  lookup: vi.fn(),
  request: vi.fn(),
}));
vi.mock('node:dns/promises', () => ({ lookup: fixtures.lookup }));
vi.mock('node:https', () => ({ request: fixtures.request }));
import { publicFetch } from './public-fetch.js';

describe('publicFetch connection boundary', () => {
  let server: Server;
  let port: number;
  let handler: (request: IncomingMessage, response: ServerResponse) => void;
  let captured: RequestOptions;
  beforeAll(async () => {
    server = createServer((request, response) => handler(request, response));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as { port: number }).port;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  beforeEach(() => {
    fixtures.lookup.mockReset().mockResolvedValue([{ address: '1.1.1.1', family: 4 }]);
    fixtures.request.mockReset().mockImplementation((url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => {
      captured = options;
      // Test-only transport seam: production's HTTPS options are inspected, but
      // body/deadline behavior runs against an inert loopback HTTP server. This
      // fixture does not claim to test a real TLS handshake.
      return httpRequest(`http://127.0.0.1:${port}${url.pathname}`, {
        ...options, lookup: undefined, servername: undefined,
      } as RequestOptions, callback);
    });
    handler = (_request, response) => { response.end('{"ok":true}'); };
  });

  it('pins the only DNS result to both socket lookup forms and preserves TLS identity', async () => {
    const response = await publicFetch('https://provider.example/');
    expect(await response.json()).toEqual({ ok: true });
    expect(fixtures.lookup).toHaveBeenCalledTimes(1);
    expect(captured.servername).toBe('provider.example');
    expect(captured.agent).toBe(false);
    expect(captured.rejectUnauthorized).not.toBe(false);
    const callback = vi.fn();
    captured.lookup!('provider.example', {}, callback);
    expect(callback).toHaveBeenLastCalledWith(null, '1.1.1.1', 4);
    captured.lookup!('provider.example', { all: true }, callback);
    expect(callback).toHaveBeenLastCalledWith(null, [{ address: '1.1.1.1', family: 4 }]);
    expect(fixtures.lookup).toHaveBeenCalledTimes(1);
  });

  it.each(['https://[::ffff:7f00:1]/', 'https://127.1/', 'https://localhost./', 'https://user:secret@provider.example/'])('rejects unsafe destination before opening a socket: %s', async (url) => {
    await expect(publicFetch(url)).rejects.toThrow();
    expect(fixtures.request).not.toHaveBeenCalled();
  });

  it('rejects DNS answers containing any private destination', async () => {
    fixtures.lookup.mockResolvedValue([{ address: '1.1.1.1', family: 4 }, { address: '::ffff:a00:1', family: 6 }]);
    await expect(publicFetch('https://provider.example/')).rejects.toThrow('non-public');
    expect(fixtures.request).not.toHaveBeenCalled();
  });

  it('refuses redirects without following or forwarding credentials', async () => {
    handler = (_request, response) => { response.writeHead(302, { location: 'http://127.0.0.1/private' }); response.end(); };
    await expect(publicFetch('https://provider.example/', { headers: { authorization: 'Bearer fixture' } })).rejects.toThrow('redirect');
    expect(fixtures.request).toHaveBeenCalledTimes(1);
    expect((await publicFetch('https://provider.example/', { redirect: 'manual' })).status).toBe(302);
    expect(fixtures.request).toHaveBeenCalledTimes(2);
  });

  it('bounds chunked UTF-8 by bytes while receiving', async () => {
    handler = (_request, response) => { response.write('é'.repeat(40)); response.end('é'.repeat(40)); };
    await expect(publicFetch('https://provider.example/', {}, { maxResponseBytes: 100 })).rejects.toThrow('size limit');
  });

  it('bounds compressed responses after decompression', async () => {
    handler = (_request, response) => { response.setHeader('content-encoding', 'gzip'); response.end(gzipSync('x'.repeat(10_000))); };
    await expect(publicFetch('https://provider.example/', {}, { maxResponseBytes: 100 })).rejects.toThrow('size limit');
  });

  it('decodes a bounded compressed public response', async () => {
    handler = (_request, response) => { response.setHeader('content-encoding', 'gzip'); response.end(gzipSync('{"ok":true}')); };
    const response = await publicFetch('https://provider.example/');
    expect(await response.json()).toEqual({ ok: true });
    expect(response.headers.has('content-encoding')).toBe(false);
  });

  it.each([{ method: 'HEAD', status: 200 }, { method: 'GET', status: 304 }])(
    'accepts bodyless $method/$status responses with representation metadata', async ({ method, status }) => {
      handler = (_request, response) => {
        response.writeHead(status, { 'content-length': '10000', 'content-encoding': 'gzip' });
        response.end();
      };
      const response = await publicFetch('https://provider.example/', { method, redirect: 'manual' }, { maxResponseBytes: 100 });
      expect(response.status).toBe(status);
      expect(await response.text()).toBe('');
    },
  );

  it('identifies request byte limits distinctly from response byte limits', async () => {
    await expect(publicFetch('https://provider.example/', { method: 'POST', body: 'x'.repeat(31) }, { maxRequestBytes: 30 }))
      .rejects.toMatchObject({ direction: 'request', limitBytes: 30 });
    expect(fixtures.request).not.toHaveBeenCalled();
    handler = (_request, response) => { response.end('x'.repeat(31)); };
    await expect(publicFetch('https://provider.example/', {}, { maxResponseBytes: 30 }))
      .rejects.toMatchObject({ direction: 'response', limitBytes: 30 });
  });

  it('keeps the total deadline active after headers arrive', async () => {
    handler = (_request, response) => { response.writeHead(200); response.write('a'); };
    await expect(publicFetch('https://provider.example/', {}, { timeoutMs: 50 })).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('bounds DNS time and never opens a late socket', async () => {
    fixtures.lookup.mockImplementation(() => new Promise((resolve) => setTimeout(() => resolve([{ address: '1.1.1.1', family: 4 }]), 70)));
    await expect(publicFetch('https://provider.example/', {}, { timeoutMs: 20 })).rejects.toMatchObject({ name: 'AbortError' });
    await new Promise((resolve) => setTimeout(resolve, 90));
    expect(fixtures.request).not.toHaveBeenCalled();
  });

  it('rejects truncated bodies without waiting for the full deadline', async () => {
    handler = (_request, response) => {
      response.writeHead(200, { 'content-length': '50' });
      response.write('short');
      setImmediate(() => response.destroy());
    };
    await expect(publicFetch('https://provider.example/')).rejects.toThrow();
  });

  it('limits the request body before opening a socket', async () => {
    await expect(publicFetch('https://provider.example/', { method: 'POST', body: 'é'.repeat(20) }, { maxRequestBytes: 30 })).rejects.toThrow('Request body exceeds');
    expect(fixtures.request).not.toHaveBeenCalled();
  });

  it('rejects an already aborted request before DNS or connection', async () => {
    await expect(publicFetch('https://provider.example/', { signal: AbortSignal.abort() })).rejects.toMatchObject({ name: 'AbortError' });
    expect(fixtures.lookup).not.toHaveBeenCalled();
    expect(fixtures.request).not.toHaveBeenCalled();
  });

  it('revalidates internal pinned addresses without another DNS query', async () => {
    await expect(publicFetch('https://provider.example/', {}, { resolvedAddresses: ['127.0.0.1'] })).rejects.toThrow('non-public');
    expect(fixtures.lookup).not.toHaveBeenCalled();
    expect(fixtures.request).not.toHaveBeenCalled();
    expect((await publicFetch('https://provider.example/', {}, { resolvedAddresses: ['1.1.1.1'] })).status).toBe(200);
    expect(fixtures.lookup).not.toHaveBeenCalled();
  });

  it('sends a default User-Agent and keeps a caller-supplied one', async () => {
    const seen: (string | undefined)[] = [];
    handler = (request, response) => { seen.push(request.headers['user-agent']); response.end('ok'); };
    await publicFetch('https://provider.example/');
    await publicFetch('https://provider.example/', { headers: { 'User-Agent': 'agent-own/1.0' } });
    expect(seen).toEqual(['STACK (+https://getstack.run)', 'agent-own/1.0']);
  });

  it('removes hop headers, nominated headers, and untrusted host and length', async () => {
    handler = (request, response) => {
      expect(request.headers.host).toBe(`127.0.0.1:${port}`);
      expect(request.headers['x-hop']).toBeUndefined();
      expect(request.headers['proxy-authorization']).toBeUndefined();
      expect(request.headers['content-length']).toBe('2');
      response.writeHead(200, { connection: 'x-secret', 'x-secret': 'hidden', 'x-public': 'kept' });
      response.end('ok');
    };
    const response = await publicFetch('https://provider.example/', {
      method: 'POST', body: 'ok', headers: { host: 'metadata', 'content-length': '999', connection: 'x-hop', 'x-hop': 'bad', 'proxy-authorization': 'secret' },
    });
    expect(response.headers.get('x-public')).toBe('kept');
    expect(response.headers.has('x-secret')).toBe(false);
    expect(response.headers.has('connection')).toBe(false);
  });
});
