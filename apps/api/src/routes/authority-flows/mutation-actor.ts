import type { FastifyReply, FastifyRequest } from 'fastify';
import { UnauthorizedError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { requireOperatorAdmin } from '../../middleware/require-platform.js';

/**
 * Who is mutating authority on routes that admit an agent as well as a human.
 * An agent must present a Passport that matches its authenticated context;
 * a human must be the owner or a team admin.
 */
export async function authorityMutationActor(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  if (request.agentId) {
    const passportToken = request.headers['x-passport-token'];
    if (typeof passportToken !== 'string') {
      throw new UnauthorizedError('An agent authority mutation requires X-Passport-Token');
    }
    const claims = await services.passport.verify(passportToken);
    if (
      claims.stk.operator_id !== request.operatorId
      || claims.stk.agent_id !== request.agentId
    ) {
      throw new UnauthorizedError('Agent and Passport authority context do not match');
    }
    return {
      kind: 'agent' as const,
      agent_id: request.agentId,
      passport_jti: claims.jti,
    };
  }

  await requireOperatorAdmin(request, reply);
  if (request.memberId) {
    return {
      kind: 'team_member' as const,
      member_id: request.memberId,
      role_at_signing: 'admin' as const,
    };
  }
  return {
    kind: 'operator_owner' as const,
    operator_id: request.operatorId,
  };
}
