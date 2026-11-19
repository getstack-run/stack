import Fastify from 'fastify';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { listen, pause } from '../test/http-hangup.js';
import { registerApprovalRelease, registerScanAbort } from './request-cleanup.js';

// What an admitted request left open (a reserved approval, an in-flight
// classifier call) is given back when the request ends: at the response, and,
// because Fastify's onResponse does not run for a client that hung up, also
// when the client leaves.

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function serve() {
  const app = Fastify();
  apps.push(app);
  registerApprovalRelease(app);
  registerScanAbort(app);
  const release = vi.fn(async () => undefined);
  const abortScan = vi.fn();
  let open!: () => void;
  let gate = new Promise<void>((resolve) => { open = resolve; });

  // Admitted, finished, and the route cleared the reservation after consuming it.
  app.get('/consumed', async (request) => {
    request.approvalToRelease = release;
    request.approvalToRelease = undefined as never;
    return 'done';
  });
  // Admitted, then refused or failed later: the reservation is still held.
  app.get('/failed', async (request) => {
    request.approvalToRelease = release;
    request.pendingInputScanAbort = abortScan;
    throw Object.assign(new Error('upstream failed'), { statusCode: 502 });
  });
  app.get('/slow-failed', async (request) => {
    request.approvalToRelease = release;
    request.pendingInputScanAbort = abortScan;
    await gate;
    throw Object.assign(new Error('upstream failed'), { statusCode: 502 });
  });
  app.get('/slow-consumed', async (request) => {
    request.approvalToRelease = release;
    request.pendingInputScanAbort = abortScan;
    await gate;
    request.approvalToRelease = undefined as never;
    request.pendingInputScanAbort = undefined as never;
    return 'done';
  });
  app.get('/stream', async (request, reply) => {
    request.approvalToRelease = release;
    request.pendingInputScanAbort = abortScan;
    const stream = new Readable({ read() {} });
    stream.push('first chunk');
    void gate.then(() => { stream.push('rest'); stream.push(null); });
    return reply.send(stream);
  });
  const client = await listen(app);
  return { ...client, release, abortScan, open: () => open(), reopen: () => { gate = new Promise<void>((resolve) => { open = resolve; }); } };
}

describe('what an admitted request leaves open, when the client stays', () => {
  it('gives back a reservation the request still held, and not one the route consumed', async () => {
    const t = await serve();
    expect(await t.call('/failed')).toBe(502);
    await pause(50);
    expect(t.release).toHaveBeenCalledTimes(1);
    expect(t.abortScan).toHaveBeenCalledTimes(1);

    t.release.mockClear();
    t.abortScan.mockClear();
    expect(await t.call('/consumed')).toBe(200);
    await pause(50);
    expect(t.release).not.toHaveBeenCalled();
    expect(t.abortScan).not.toHaveBeenCalled();
  });
});

describe('what an admitted request leaves open, when the client hangs up', () => {
  it('gives back a reservation once the action ends without consuming it, and cancels the scan', async () => {
    const t = await serve();
    await t.hangUp('/slow-failed');
    expect(t.release).not.toHaveBeenCalled();
    t.open();
    await pause(150);
    expect(t.release).toHaveBeenCalledTimes(1);
    expect(t.abortScan).toHaveBeenCalledTimes(1);
  });

  it('keeps a reservation the action consumed before the client left', async () => {
    const t = await serve();
    await t.hangUp('/slow-consumed');
    t.open();
    await pause(150);
    expect(t.release).not.toHaveBeenCalled();
    expect(t.abortScan).not.toHaveBeenCalled();
  });

  it('gives back a reservation a cut stream still held, once, when the client leaves mid-stream', async () => {
    const t = await serve();
    await t.hangUp('/stream');
    expect(t.release).toHaveBeenCalledTimes(1);
    t.open();
    await pause(150);
    expect(t.release).toHaveBeenCalledTimes(1);
  });

  it('never runs twice, however the request ends', async () => {
    const t = await serve();
    await t.call('/failed');
    await t.hangUp('/slow-failed');
    t.open();
    await pause(150);
    t.reopen();
    await t.hangUp('/stream');
    t.open();
    await pause(150);
    expect(t.release).toHaveBeenCalledTimes(3);
    expect(t.abortScan).toHaveBeenCalledTimes(3);
  });
});
