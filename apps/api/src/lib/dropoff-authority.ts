import type { FastifyRequest } from 'fastify';
import { ForbiddenError } from '@stack/shared';

/** Agent and Passport bearers cannot claim another participant's identity. */
export function assertDropoffAgentBinding(
  request: Pick<FastifyRequest, 'agentId'>,
  claimedAgentId: string,
): void {
  if (request.agentId && request.agentId !== claimedAgentId) {
    throw new ForbiddenError('Authenticated agent cannot act as another drop-off participant');
  }
}
