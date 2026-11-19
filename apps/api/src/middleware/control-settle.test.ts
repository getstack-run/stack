import Fastify from 'fastify';
import http from 'node:http';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerControlSettle } from './control-settle.js';

type Outcome = { ok: boolean; handedBack: boolean };

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** A server whose routes leave one settle hook open, as an allowed control decision does. */
async function serve() {
  const app = Fastify();
  apps.push(app);
  registerControlSettle(app);
  const hook = vi.fn<(outcome: Outcome) => Promise<void>>(async () => undefined);
  let release!: () => void;
  let gate = new Promise<void>((resolve) => { release = resolve; });
  const reopen = () => { gate = new Promise<void>((resolve) => { release = resolve; }); };

  app.get('/ok', async (request) => {
    request.controlSettle = [hook];
    return 'done';
  });
  app.get('/fail', async (request) => {
    request.controlSettle = [hook];
    throw Object.assign(new Error('upstream failed'), { statusCode: 502 });
  });
  app.get('/refused', async (request, reply) => {
    request.controlSettle = [hook];
    request.refundAction = true;
    return reply.status(403).send({ error: 'refused' });
  });
  // The action takes a while; a client may hang up before it ends.
  app.get('/slow', async (request) => {
    request.controlSettle = [hook];
    await gate;
    return 'done';
  });
  app.get('/slow-fail', async (request) => {
    request.controlSettle = [hook];
    await gate;
    throw Object.assign(new Error('upstream failed'), { statusCode: 502 });
  });
  // A streamed answer: headers and a first chunk go out, then the client leaves.
  app.get('/stream', async (request, reply) => {
    request.controlSettle = [hook];
    const stream = new Readable({ read() {} });
    stream.push('first chunk');
    void gate.then(() => { stream.push('rest'); stream.push(null); });
    return reply.send(stream);
  });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const port = (app.server.address() as { port: number }).port;

  const call = (path: string) => new Promise<number>((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    }).on('error', reject);
  });
  /** Open a request and hang up after `afterMs`, as a client that disconnects mid-flight. */
  const hangUp = async (path: string, afterMs = 100) => {
    const request = http.get({ host: '127.0.0.1', port, path });
    request.on('error', () => undefined);
    request.on('response', (res) => { res.on('data', () => undefined); res.on('error', () => undefined); });
    await pause(afterMs);
    request.destroy();
    await pause(100);
  };
  return { hook, call, hangUp, release: () => release(), reopen };
}

describe('telling an allowed action how it ended', () => {
  it('tells a finished action once, with whether it succeeded and whether it was handed back', async () => {
    const t = await serve();
    expect(await t.call('/ok')).toBe(200);
    await pause(50);
    expect(t.hook.mock.calls).toEqual([[{ ok: true, handedBack: false }]]);

    t.hook.mockClear();
    expect(await t.call('/fail')).toBe(502);
    await pause(50);
    expect(t.hook.mock.calls).toEqual([[{ ok: false, handedBack: false }]]);

    t.hook.mockClear();
    expect(await t.call('/refused')).toBe(403);
    await pause(50);
    expect(t.hook.mock.calls).toEqual([[{ ok: false, handedBack: true }]]);
  });

  it('tells an action whose client hung up, once the action ends, so a lease or a reserved approval is never left behind', async () => {
    const t = await serve();
    await t.hangUp('/slow');
    // The action is still running: nothing is told yet.
    expect(t.hook).not.toHaveBeenCalled();
    t.release();
    await pause(150);
    expect(t.hook.mock.calls).toEqual([[{ ok: true, handedBack: false }]]);
  });

  it('tells an action that failed after its client hung up, with the failure', async () => {
    const t = await serve();
    await t.hangUp('/slow-fail');
    expect(t.hook).not.toHaveBeenCalled();
    t.release();
    await pause(150);
    expect(t.hook.mock.calls).toEqual([[{ ok: false, handedBack: false }]]);
  });

  it('tells a streamed action the moment its client leaves mid-stream, and only once when the stream then ends', async () => {
    const t = await serve();
    await t.hangUp('/stream');
    // The answer had started (200) and was cut: it ran, so it is not handed back.
    expect(t.hook.mock.calls).toEqual([[{ ok: true, handedBack: false }]]);
    t.release();
    await pause(150);
    expect(t.hook).toHaveBeenCalledTimes(1);
  });

  it('never tells twice, however the request ends', async () => {
    const t = await serve();
    await t.call('/ok');
    await t.hangUp('/slow');
    t.release();
    await pause(150);
    t.reopen();
    await t.hangUp('/stream');
    await pause(100);
    t.release();
    await pause(100);
    // One call for each of the three requests, no more.
    expect(t.hook).toHaveBeenCalledTimes(3);
  });
});
