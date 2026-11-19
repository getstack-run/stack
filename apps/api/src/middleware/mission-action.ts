import type { FastifyInstance, FastifyRequest } from 'fastify';
import { safeErrorSummary } from '@stack/shared';
import type { MissionActionReservation } from '@stack/vault';
import { onRequestEnd } from './request-end.js';

/**
 * A call counted against its Mission's action limits is only reserved when the gate admits it (the way the meter's pending
 * count is). The request settles it when it ends: committed when the call was dispatched or ended well, given back when it
 * was refused or failed (a status of 400 or more), so a prompt-injected agent whose calls are all refused cannot use up the
 * Mission's actions. A route that dispatches work with side effects commits first (`commitMissionAction`, right before
 * dispatch), so a failure after that point does not hand the action back.
 */

declare module 'fastify' {
  interface FastifyRequest {
    /** The Mission action this request reserved at the gate, to commit or give back when it ends. */
    missionAction?: MissionActionReservation;
  }
}

/** Hold a reservation on the request until it ends. A second one on the same request is settled at once, as committed. */
export function attachMissionAction(request: FastifyRequest, reservation: MissionActionReservation): void {
  if (request.missionAction) {
    // One request is one action; a second admission on it (a route that admits twice) is not counted twice over.
    void reservation.release().catch((err: unknown) => console.error('[mission] release failed', safeErrorSummary(err)));
    return;
  }
  request.missionAction = reservation;
}

/** Count the request's Mission action for good, immediately before work that cannot be undone is dispatched. */
export async function commitMissionAction(request: FastifyRequest): Promise<void> {
  const reservation = request.missionAction;
  if (!reservation) return;
  request.missionAction = undefined as never;
  await reservation.commit();
}

/** Settle what a request left reserved when it ends, however it ended (including a client that hung up). */
export function registerMissionActionSettle(app: FastifyInstance): void {
  onRequestEnd(app, (request, statusCode) => {
    const reservation = request.missionAction;
    if (!reservation) return;
    request.missionAction = undefined as never;
    const settle = statusCode >= 400 ? reservation.release() : reservation.commit();
    void settle.catch((err: unknown) => {
      console.error('[mission] settling a counted action failed', safeErrorSummary(err));
    });
  });
}
