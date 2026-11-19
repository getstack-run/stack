import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApiClient } from './api-client.js';
import { FETCH_WAIT_CEILING_MS, longRequest } from './long-request.js';
import { runWithCallScope } from './tool-deadlines.js';

const servers: Server[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); })));
});

async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe('longRequest', () => {
  it('sends the method, headers and body, and answers as a Response', async () => {
    let seen: { method?: string; auth?: string; length?: string; body: string } = { body: '' };
    const base = await listen((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        seen = { method: req.method, auth: req.headers['authorization'], length: req.headers['content-length'], body: Buffer.concat(chunks).toString('utf8') };
        res.writeHead(201, { 'Content-Type': 'application/json', 'Retry-After': '7' });
        res.end('{"ok":true}');
      });
    });
    const response = await longRequest(`${base}/x`, { method: 'POST', headers: { Authorization: 'Bearer k', 'Content-Type': 'application/json' }, body: '{"a":"é"}' });
    expect(response.status).toBe(201);
    expect(response.headers.get('retry-after')).toBe('7');
    expect(await response.json()).toEqual({ ok: true });
    expect(seen).toEqual({ method: 'POST', auth: 'Bearer k', length: String(Buffer.byteLength('{"a":"é"}')), body: '{"a":"é"}' });
  });

  it('answers a status with no body, and stops when its signal fires', async () => {
    const base = await listen((req, res) => {
      if (req.url === '/none') {
        res.writeHead(204);
        res.end();
      }
      // /hang never answers.
    });
    const none = await longRequest(`${base}/none`, { method: 'GET', headers: {} });
    expect(none.status).toBe(204);
    expect(await none.text()).toBe('');
    const controller = new AbortController();
    const hanging = longRequest(`${base}/hang`, { method: 'GET', headers: {}, signal: controller.signal });
    controller.abort();
    await expect(hanging).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('the API client in a tool call', () => {
  it('sends a short call by fetch with the call\'s signal, and a long one by a request with no wait of its own', async () => {
    const fetchMock = vi.fn(async () => new Response('{"via":"fetch"}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const base = await listen((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"via":"longRequest"}');
    });
    const { api } = createApiClient(base, 'k');
    const controller = new AbortController();
    expect(await runWithCallScope({ signal: controller.signal, deadlineMs: FETCH_WAIT_CEILING_MS }, () => api('GET', '/x'))).toEqual({ via: 'fetch' });
    expect(fetchMock).toHaveBeenCalledWith(`${base}/x`, expect.objectContaining({ signal: controller.signal }));
    // A replaced fetch is always the one used, whatever the deadline.
    expect(await runWithCallScope({ signal: controller.signal, deadlineMs: FETCH_WAIT_CEILING_MS + 1 }, () => api('GET', '/x'))).toEqual({ via: 'fetch' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    // Outside a tool call nothing changes: fetch, with no signal.
    expect(await api('GET', '/x')).toEqual({ via: 'fetch' });
    expect(fetchMock).toHaveBeenLastCalledWith(`${base}/x`, expect.not.objectContaining({ signal: expect.anything() }));
    // With the real fetch, a call whose deadline passes what fetch waits goes by the request with no wait of its own.
    vi.unstubAllGlobals();
    expect(await runWithCallScope({ signal: controller.signal, deadlineMs: FETCH_WAIT_CEILING_MS + 1 }, () => api('GET', '/x'))).toEqual({ via: 'longRequest' });
  });
});
