// Which delivery a call asked for. A caller that cannot take a binary or very large answer (the MCP tool) sends
// `X-Stack-Save-Output: drive`, and the answer is then saved to the agent's drive instead of being passed on. The engine
// has no drive: the places an answer can be saved to are registered by the deployment (`registries.outputDeliveries`). A
// request for `drive` on a deployment without one is refused before anything is sent or held; any other value is ignored,
// and the answer is passed on as it comes.

import type { FastifyRequest } from 'fastify';
import { OPENROUTER_SAVE_OUTPUT_HEADER, StackError } from '@stack/shared';
import type { Services } from '../../../config/services.js';
import type { OutputDelivery } from './delivery.js';

/** The one value of the header that asks for a save. */
const SAVE_TO_DRIVE = 'drive';

/** The delivery the request asked for, or null when it asked for none or for a value that is not one (the answer is passed on untouched). */
export function requestedDelivery(services: Pick<Services, 'registries'>, request: FastifyRequest): OutputDelivery | null {
  const raw = request.headers[OPENROUTER_SAVE_OUTPUT_HEADER.toLowerCase()];
  if (raw === undefined) return null;
  const name = (Array.isArray(raw) ? raw.join(',') : raw).trim().toLowerCase();
  if (name !== SAVE_TO_DRIVE) return null;
  const delivery = services.registries?.outputDeliveries.get(name);
  if (!delivery) {
    throw new StackError(
      `${OPENROUTER_SAVE_OUTPUT_HEADER} names a place this deployment cannot save an answer to. Nothing was sent or charged: call again without the header to receive the answer as it comes.`,
      'SAVE_OUTPUT_UNAVAILABLE',
      400,
    );
  }
  return delivery;
}
