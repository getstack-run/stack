import type { FastifyReply, FastifyRequest } from 'fastify';
import { ControlsRequiredError, type ControlsRequiredFeature } from '@stack/shared';
import type { Services } from '../config/services.js';

/**
 * The gate of a controls feature: a customer without controls is answered 402 `CONTROLS_REQUIRED` before the handler
 * runs. STACK keeps writing the record for every account (its own abuse handling, the law and revocation need it);
 * reading it is the controls feature, and so is changing the detector settings. Switching controls on shows the whole
 * record, from before too, because nothing was held back from writing.
 *
 * The decision is `entitlements.controlsEnabled`, the one reading of whether a customer has controls: an install answers
 * yes for every account (every controls feature works there with no subscription), the hosted deployment follows the
 * controls subscription, a live grant and an internal account. A status that cannot be read throws (fail closed).
 *
 * Runs after `auth`. The gate is named `requireControlsGate` so the route table lists it as the route's gate.
 */
export function requireControls(
  services: Pick<Services, 'entitlements'>,
  feature: ControlsRequiredFeature = 'record',
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  return async function requireControlsGate(request: FastifyRequest): Promise<void> {
    if (!(await services.entitlements.controlsEnabled(request.operatorId))) throw new ControlsRequiredError(feature);
  };
}
