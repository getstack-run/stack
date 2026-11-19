import type { FastifyInstance, FastifyRequest } from 'fastify';
import { safeErrorSummary } from '@stack/shared';

type EndRunner = (request: FastifyRequest, statusCode: number, force?: boolean) => void | Promise<void>;

/** The registrations that apply to a request, collected as it arrives, so a handler can end it by hand. */
const runners = new WeakMap<FastifyRequest, EndRunner[]>();
/** Requests whose handler owns their end (a hijacked reply): the response and the socket do not end them. */
const held = new WeakSet<FastifyRequest>();

/**
 * Runs `end` once when a request is over, however it ended.
 *
 * What a request leaves open (a counted action, a reserved approval, a lease,
 * an in-flight classifier call, a fleet admission) has to be settled at the
 * end, and Fastify's onResponse does not run for a client that hung up: the
 * socket is destroyed and neither 'finish' nor 'error' fires. So this listens
 * to three moments and runs `end` at the first one that applies, once per
 * request:
 *   - onResponse: the response finished (the normal end, errors included);
 *   - onSend after an abort: the client left while the action was still
 *     running (Fastify lets the action finish), and its real status is known now;
 *   - the socket closing with the answer unfinished, once the answer had
 *     started: a streamed answer cut by the client, which has no later moment.
 *     The status is the one it was sent with.
 *
 * The abort is read from the response's own 'close' with the answer unfinished,
 * not from Fastify's onRequestAbort: that one fires only for a request whose
 * body had not been fully read when the client left, so a POST (every model
 * call) was never seen. The abort state is private to each registration, so
 * the order registrations are made in does not matter.
 *
 * `statusCode` is therefore always a status the request really ended with,
 * never a guess: an action that is still running when the client leaves is
 * settled only when it ends, and one that never ends is settled by whatever
 * expires its reservation.
 *
 * A handler that hijacks its reply takes the end of the request into its own
 * hands (`holdRequestEnd`, `releaseRequestEnd`): its work goes on after the
 * client has the whole answer, or after the client left, and the response
 * finishing is not the end of it.
 *
 * `end` is fire-and-forget by convention: the client already has its response,
 * or has gone. A failure inside it must be handled inside it; one that is not
 * is logged here and never becomes an unhandled rejection.
 */
export function onRequestEnd(
  app: FastifyInstance,
  end: (request: FastifyRequest, statusCode: number) => void | Promise<void>,
): void {
  const sent = new WeakMap<FastifyRequest, number>();
  const aborted = new WeakSet<FastifyRequest>();
  const ended = new WeakSet<FastifyRequest>();

  const run: EndRunner = (request, statusCode, force = false) => {
    if (ended.has(request)) return;
    if (held.has(request) && !force) return;
    ended.add(request);
    return end(request, statusCode);
  };
  const runDetached = (request: FastifyRequest, statusCode: number) => {
    void Promise.resolve()
      .then(() => run(request, statusCode))
      .catch((err: unknown) => console.error('[request-end] end failed', safeErrorSummary(err)));
  };

  app.addHook('onRequest', (request, reply, done) => {
    const list = runners.get(request);
    if (list) list.push(run);
    else runners.set(request, [run]);
    reply.raw.once('close', () => {
      if (reply.raw.writableFinished) return;
      aborted.add(request);
      const status = sent.get(request) ?? (reply.raw.headersSent ? reply.raw.statusCode : undefined);
      // The answer had started when the client left: nothing else will end this request.
      if (status !== undefined) runDetached(request, status);
    });
    done();
  });

  app.addHook('onResponse', async (request, reply) => {
    await run(request, reply.statusCode);
  });

  app.addHook('onSend', async (request, reply, payload) => {
    sent.set(request, reply.statusCode);
    if (aborted.has(request)) runDetached(request, reply.statusCode);
    return payload;
  });

  app.addHook('onRequestAbort', (request, done) => {
    aborted.add(request);
    const status = sent.get(request);
    if (status !== undefined) runDetached(request, status);
    done();
  });
}

/**
 * A handler that is about to hijack its reply calls this first: the response
 * finishing, or the client leaving, no longer ends the request. The handler
 * ends it itself with `releaseRequestEnd` once its work is done.
 */
export function holdRequestEnd(request: FastifyRequest): void {
  held.add(request);
}

/**
 * Ends a request whose end was held, with the status its answer really had,
 * running every end registered with `onRequestEnd` once. Calling it on a
 * request that was never held, or twice, is safe.
 */
export async function releaseRequestEnd(request: FastifyRequest, statusCode: number): Promise<void> {
  held.delete(request);
  for (const run of runners.get(request) ?? []) {
    try {
      await run(request, statusCode, true);
    } catch (err) {
      console.error('[request-end] end failed', safeErrorSummary(err));
    }
  }
}
