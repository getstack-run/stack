import type { FastifyInstance, FastifyRequest } from 'fastify';
import { runSettle } from '../lib/control-socket/settle.js';
import { actionHandedBack } from '../lib/action-meter.js';
import { onRequestEnd } from './request-end.js';

/**
 * Tells what an allowed action's control decision left open how the action
 * ended: an approval a person gave for it is spent when it ran and given back
 * when it did not, a counted action is handed back when the action never ran
 * (the meter's own rule, `actionHandedBack`), and a lease on concurrency is
 * always returned. Fire-and-forget, like the meter refund: the client already
 * has its response. A lease or reservation a crash strands expires on its own.
 *
 * Fastify's onResponse does not run for a client that hung up, so this runs at
 * the end of the request however it ended (`onRequestEnd`: the response, or
 * the action finishing after the client left, or a streamed answer the client
 * cut), and tells each decision once (taking `request.controlSettle` is the
 * guard).
 */
export function registerControlSettle(app: FastifyInstance): void {
  onRequestEnd(app, settle);
}

async function settle(request: FastifyRequest, statusCode: number): Promise<void> {
  const hooks = request.controlSettle;
  if (!hooks || hooks.length === 0) return;
  request.controlSettle = undefined as never;
  const handedBack = actionHandedBack(statusCode, request.stackSideUnavailable === true, request.refundAction === true);
  await runSettle(hooks, { ok: statusCode < 400, handedBack });
}
