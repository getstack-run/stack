import type { FastifyRequest } from 'fastify';
import type { Services } from '../../config/services.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { idempotencyKey, writeAudit } from './request-support.js';
import { EmptyBody } from './schemas.js';

type PresentationRequest = FastifyRequest<{ Params: { presentationId: string } }>;

export async function listPresentations(services: Services, request: FastifyRequest) {
  const presentations = await services.authority.listAuthorityPresentations(request.operatorId);
  return safeAuthorityResponse({ presentations });
}

export async function getPresentation(services: Services, request: PresentationRequest) {
  const presentation = await services.authority.getAuthorityPresentation(
    request.operatorId,
    request.params.presentationId,
  );
  return safeAuthorityResponse({ presentation });
}

export async function erasePresentation(services: Services, request: PresentationRequest): Promise<unknown> {
  EmptyBody.parse(request.body ?? {});
  const mutationIdempotencyKey = idempotencyKey(request);
  await enforceGovernanceStepUp(services, request, {
    action: 'authority_presentation_erase',
    resourceId: request.params.presentationId,
    payload: {},
    summary: `Erase authority presentation ${request.params.presentationId}`,
    idempotencyKey: mutationIdempotencyKey,
  });
  const tombstone = await services.authority.erasePresentation(
    request.operatorId,
    request.params.presentationId,
    mutationIdempotencyKey,
  );
  await writeAudit(services, request, 'authority.presentation.erase');
  return safeAuthorityResponse({ tombstone });
}
