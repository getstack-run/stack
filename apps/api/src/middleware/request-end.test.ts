import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { listen, pause } from '../test/http-hangup.js';
import { holdRequestEnd, onRequestEnd, releaseRequestEnd } from './request-end.js';

// A request is over when its answer finished, when the action ended after its
// client left, or (for a handler that hijacked its reply) when the handler
// says so. Every one of those has to run the end hooks exactly once, with a
// status the request really had, over a real socket: `app.inject` has no
// client to hang up. The POST cases are the ones that matter: every model call
// is a POST, and Fastify's own abort signal does not fire for one.

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function serve() {
  const app = Fastify();
  apps.push(app);
  const ends: Array<{ url: string; status: number }> = [];
  onRequestEnd(app, (request, status) => { ends.push({ url: request.url, status }); });
  let open!: () => void;
  let gate = new Promise<void>((resolve) => { open = resolve; });
  const reopen = () => { gate = new Promise<void>((resolve) => { open = resolve; }); };

  app.post('/ok', async () => ({ ok: true }));
  app.post('/slow', async () => { await gate; return { ok: true }; });
  app.post('/slow-bad', async (_request, reply) => {
    await gate;
    return reply.status(400).send({ error: 'bad' });
  });
  app.get('/slow-get', async () => { await gate; return { ok: true }; });

  // A handler that hijacks: it writes, keeps working after the last byte, and ends the request itself.
  app.post('/hijack-stream', async (request, reply) => {
    holdRequestEnd(request);
    reply.raw.statusCode = 200;
    reply.raw.setHeader('content-type', 'text/event-stream');
    reply.hijack();
    reply.raw.write('data: first\n\n');
    await gate;
    reply.raw.write('data: rest\n\n');
    reply.raw.end();
    await pause(30);
    await releaseRequestEnd(request, reply.raw.statusCode);
  });
  app.post('/hijack-throw', async (request, reply) => {
    holdRequestEnd(request);
    reply.raw.statusCode = 200;
    reply.hijack();
    reply.raw.write('data: first\n\n');
    try {
      await gate;
      throw new Error('upstream failed');
    } finally {
      if (reply.raw.writableEnded === false) reply.raw.end();
      await releaseRequestEnd(request, reply.raw.statusCode);
    }
  });
  const client = await listen(app);
  return { ...client, ends, open: () => open(), reopen };
}

const POST = { method: 'POST', body: { model: 'm', messages: [] } } as const;

describe('onRequestEnd, over a real socket', () => {
  it('runs once at the end of a request that finishes', async () => {
    const t = await serve();
    expect(await t.call('/ok', POST)).toBe(200);
    await pause(50);
    expect(t.ends).toEqual([{ url: '/ok', status: 200 }]);
  });

  it('runs for a POST whose client hung up, once the action ends, with the status the action really had', async () => {
    const t = await serve();
    await t.hangUp('/slow-bad', 100, POST);
    // The action is still running: nothing is settled with a guess.
    expect(t.ends).toEqual([]);
    t.open();
    await pause(100);
    expect(t.ends).toEqual([{ url: '/slow-bad', status: 400 }]);
  });

  it('runs for a GET whose client hung up, as before', async () => {
    const t = await serve();
    await t.hangUp('/slow-get');
    expect(t.ends).toEqual([]);
    t.open();
    await pause(100);
    expect(t.ends).toEqual([{ url: '/slow-get', status: 200 }]);
  });
});

describe('a hijacked reply', () => {
  it('is not over when the client has the last byte, only when the handler says so', async () => {
    const t = await serve();
    const done = t.call('/hijack-stream', POST);
    await pause(50);
    expect(t.ends).toEqual([]);
    t.open();
    expect(await done).toBe(200);
    await pause(100);
    expect(t.ends).toEqual([{ url: '/hijack-stream', status: 200 }]);
  });

  it('is not over when the client hangs up mid-stream: the handler goes on, and its end runs once when it is done', async () => {
    const t = await serve();
    await t.hangUp('/hijack-stream', 100, POST);
    // The client is gone, the handler is still working: the request is still open.
    expect(t.ends).toEqual([]);
    t.open();
    await pause(150);
    expect(t.ends).toEqual([{ url: '/hijack-stream', status: 200 }]);
  });

  it('ends a request whose handler threw after the hijack, and the connection with it', async () => {
    const t = await serve();
    const status = vi.fn();
    const done = t.call('/hijack-throw', POST).then(status);
    await pause(50);
    expect(status).not.toHaveBeenCalled();
    t.open();
    await done;
    await pause(100);
    expect(status).toHaveBeenCalledWith(200);
    expect(t.ends).toEqual([{ url: '/hijack-throw', status: 200 }]);
  });

  it('ends nothing twice, and a release on a request that was never held is harmless', async () => {
    const app = Fastify();
    apps.push(app);
    const end = vi.fn();
    onRequestEnd(app, end);
    app.get('/x', async (request) => {
      await releaseRequestEnd(request, 200);
      await releaseRequestEnd(request, 200);
      return 'x';
    });
    const client = await listen(app);
    expect(await client.call('/x')).toBe(200);
    await pause(50);
    expect(end).toHaveBeenCalledTimes(1);
  });
});
