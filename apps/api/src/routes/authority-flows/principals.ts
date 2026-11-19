import type { FastifyReply, FastifyRequest } from 'fastify';
import { CreateAuthorityPrincipalInput } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { idempotencyKey, writeAudit } from './request-support.js';
import { accountAuthorityPage, EmptyBody, ReasonBody } from './schemas.js';

type PrincipalRequest = FastifyRequest<{ Params: { principalId: string } }>;

export async function createPrincipal(
  services: Services,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const input = CreateAuthorityPrincipalInput.parse(request.body);
  const principal = await services.authority.createPrincipal(
    request.operatorId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.principal.create');
  return reply.status(201).send(safeAuthorityResponse({ principal }));
}

export async function listPrincipals(services: Services, request: FastifyRequest): Promise<unknown> {
  const query = accountAuthorityPage(request.query, 'principals');
  if (query) return safeAuthorityResponse(await services.authority.listAccountRecords(
    request.operatorId, 'principals', query.page, query.limit,
    query.record_id ? { id: query.record_id, version: query.version } : undefined,
  ));
  const principals = await services.authority.listPrincipals(request.operatorId);
  return safeAuthorityResponse({ principals });
}

export async function getPrincipal(services: Services, request: PrincipalRequest) {
  const principal = await services.authority.getPrincipal(
    request.operatorId,
    request.params.principalId,
  );
  return safeAuthorityResponse({ principal });
}

export async function archivePrincipal(services: Services, request: PrincipalRequest) {
  const input = ReasonBody.parse(request.body);
  const principal = await services.authority.archivePrincipal(
    request.operatorId,
    request.params.principalId,
    input.reason_code,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.principal.archive');
  return safeAuthorityResponse({ principal });
}

export async function erasePrincipal(services: Services, request: PrincipalRequest): Promise<unknown> {
  EmptyBody.parse(request.body ?? {});
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_principal_erase',
    resourceId: request.params.principalId,
    payload: {},
    summary: `Erase authority principal ${request.params.principalId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const tombstone = await services.authority.erasePrincipal(
    request.operatorId,
    request.params.principalId,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.principal.erase');
  return safeAuthorityResponse({ tombstone });
}
