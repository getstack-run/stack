import type { FastifyRequest } from 'fastify';
import type { Services } from '../../config/services.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { AuthorityUseListQuery } from './schemas.js';

export async function listUses(services: Services, request: FastifyRequest) {
  const query = AuthorityUseListQuery.parse(request.query);
  if (query.agent_id) {
    await services.agent.getById(query.agent_id, request.operatorId);
    return safeAuthorityResponse(await services.authority.listAgentAuthorityUses(
      request.operatorId, query.agent_id, query.page, query.limit,
      query.binding_id ? { id: query.binding_id, version: query.binding_version! } : undefined,
    ));
  }
  const uses = await services.authority.listAuthorityUses(request.operatorId);
  return safeAuthorityResponse({ uses });
}

export async function getUse(
  services: Services,
  request: FastifyRequest<{ Params: { useId: string } }>,
) {
  const use = await services.authority.getAuthorityUse(request.operatorId, request.params.useId);
  return safeAuthorityResponse({ use });
}
