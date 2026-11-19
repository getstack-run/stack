// The passthrough holds an answer back for the data trail only up to a bound of its own and one for the whole machine: an
// answer that would take the machine past it streams from that point on, as one past its own bound does.

import http from 'node:http';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { createStreamDelivery, type FinalizeInput, type OutputDelivery } from './delivery.js';
import type { UpstreamAnswer } from './upstream.js';
import type { OpenRouterCall } from './request.js';

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

function answerOf(chunks: Uint8Array[], gate: Promise<void> | null = null): UpstreamAnswer {
  return {
    status: 200,
    headers: { 'content-type': 'application/json' },
    contentType: 'application/json',
    generationIdHeader: null,
    body: {
      async *[Symbol.asyncIterator]() {
        yield chunks[0]!;
        if (gate) await gate;
        for (const chunk of chunks.slice(1)) yield chunk;
      },
    },
    cancel: () => undefined,
  };
}

async function serve(delivery: OutputDelivery, routes: Record<string, () => { answer: UpstreamAnswer; finalized: FinalizeInput[]; read?: () => void }>) {
  const app = Fastify();
  apps.push(app);
  for (const [path, make] of Object.entries(routes)) {
    app.get(path, async (request, reply) => {
      const { answer, finalized, read } = make();
      const state = { hijacked: false };
      await delivery({
        request, reply, answer, state,
        call: { method: 'POST', path: '/chat/completions' } as OpenRouterCall,
        caller: { operatorId: 'op_1', agentId: 'agt_1', missionId: 'msn_1', passportJti: 'pas_1' },
        hold: 'if_small',
        abortOnHangup: true,
        onChunk: () => read?.(),
        finalize: async (input) => {
          finalized.push(input);
          return {};
        },
      });
      if (state.hijacked) {
        // The test stands in for the handler, which releases the end of a hijacked request.
        return reply;
      }
      return reply;
    });
  }
  await app.listen({ port: 0, host: '127.0.0.1' });
  return `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
}

describe('answers held back for the data trail', () => {
  it('streams an answer that would take the machine past its bound, and holds again once the others are done', async () => {
    const delivery = createStreamDelivery({ heldTotalMaxBytes: 100 });
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => { openGate = resolve; });
    let firstRead!: () => void;
    const firstHeld = new Promise<void>((resolve) => { firstRead = resolve; });
    const slow: FinalizeInput[] = [];
    const quick: FinalizeInput[] = [];
    const later: FinalizeInput[] = [];
    let quickRuns = 0;
    const base = await serve(delivery, {
      '/slow': () => ({ answer: answerOf([new Uint8Array(80).fill(1), new Uint8Array(5).fill(2)], gate), finalized: slow, read: () => firstRead() }),
      '/quick': () => ({ answer: answerOf([new Uint8Array(50).fill(3)]), finalized: (quickRuns += 1) === 1 ? quick : later }),
    });

    const pending = fetch(`${base}/slow`).then(async (res) => Buffer.from(await res.arrayBuffer()));
    await firstHeld;
    // 80 bytes are held for the slow answer: 50 more would pass the machine's 100, so this one streams.
    const quickBody = Buffer.from(await (await fetch(`${base}/quick`)).arrayBuffer());
    expect(quickBody.length).toBe(50);
    expect(quick[0]).toMatchObject({ bytesAlreadySent: true, held: null });

    openGate();
    expect((await pending).length).toBe(85);
    expect(slow[0]!.bytesAlreadySent).toBe(false);
    expect(slow[0]!.held?.length).toBe(85);

    // Nothing is held any more: the same answer is held whole again.
    await (await fetch(`${base}/quick`)).arrayBuffer();
    expect(later[0]).toMatchObject({ bytesAlreadySent: false });
    expect(later[0]!.held?.length).toBe(50);
  });
});

describe('a caller that is already gone when the answer starts', () => {
  async function leaveBeforeStart(abortOnHangup: boolean) {
    const delivery = createStreamDelivery();
    const finalized: FinalizeInput[] = [];
    let cancelled = false;
    let chunksRead = 0;
    let delivered!: () => void;
    const done = new Promise<void>((resolve) => { delivered = resolve; });
    const app = Fastify();
    apps.push(app);
    app.get('/gone', async (request, reply) => {
      // The client has gone, and its close has come and gone, before delivery begins and could listen for it.
      await new Promise((resolve) => setTimeout(resolve, 300));
      const answer = { ...answerOf([new Uint8Array(10).fill(1), new Uint8Array(10).fill(2)]), cancel: () => { cancelled = true; } };
      await delivery({
        request, reply, answer, state: { hijacked: false },
        call: { method: 'POST', path: '/chat/completions' } as OpenRouterCall,
        caller: { operatorId: 'op_1', agentId: 'agt_1', missionId: 'msn_1', passportJti: 'pas_1' },
        hold: 'no',
        abortOnHangup,
        onChunk: () => { chunksRead += 1; },
        finalize: async (input) => { finalized.push(input); return {}; },
      });
      delivered();
      return reply;
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    const port = (app.server.address() as { port: number }).port;
    const client = http.request({ host: '127.0.0.1', port, path: '/gone', method: 'GET' });
    client.on('error', () => undefined);
    client.end();
    await new Promise((resolve) => setTimeout(resolve, 100));
    client.destroy();
    await done;
    return { cancelled, finalized, chunksRead };
  }

  it('is noticed at the start of a streamed call: the call to OpenRouter is cancelled and the answer is not read to its end', async () => {
    const { cancelled, finalized, chunksRead } = await leaveBeforeStart(true);
    expect(cancelled).toBe(true);
    expect(chunksRead).toBe(1);
    expect(finalized).toHaveLength(1);
    expect(finalized[0]).toMatchObject({ callerLeft: true, broken: null });
  });

  it('is not noticed by a call that is not streamed: the answer is read to its end and nothing says the caller left', async () => {
    const { cancelled, finalized, chunksRead } = await leaveBeforeStart(false);
    expect(cancelled).toBe(false);
    expect(chunksRead).toBe(2);
    expect(finalized).toHaveLength(1);
    expect(finalized[0]).toMatchObject({ callerLeft: false, broken: null });
  });
});
