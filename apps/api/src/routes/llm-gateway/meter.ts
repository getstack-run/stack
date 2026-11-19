// Stage 0: meter the call. The gateway used to count nothing, so the
// highest-volume surface in the product consumed no allowance at all. This is
// the operator spending a recorded action, same as any other operation.
//
// Runs after the authority decision and before Mission admission, the
// approval gate and everything that can reach a provider.

import type { FastifyRequest } from 'fastify';
import { meterAction } from '../../middleware/meter.js';
import type { Services } from '../../config/services.js';

export async function meterLlmCall(services: Services, request: FastifyRequest, agentId: string): Promise<void> {
  // The passport's agent: an agent account's model calls count on its owner's account meter.
  await meterAction(services, request, undefined, undefined, agentId);
}
