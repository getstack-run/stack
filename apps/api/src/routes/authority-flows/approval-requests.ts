import type { FastifyReply, FastifyRequest } from 'fastify';
import { CreateAuthorityApprovalRequestsInput } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { idempotencyKey, writeAudit } from './request-support.js';

type BindingRequest = FastifyRequest<{ Params: { bindingId: string } }>;

export async function createApprovalRequests(
  services: Services,
  request: BindingRequest,
  reply: FastifyReply,
) {
  const input = CreateAuthorityApprovalRequestsInput.parse(request.body);
  const approvalRequests = await services.authority.createApprovalRequests(
    request.operatorId,
    request.params.bindingId,
    input,
    idempotencyKey(request),
  );
  await writeAudit(services, request, 'authority.approval_requests.create');
  return reply.status(201).send(safeAuthorityResponse({ approval_requests: approvalRequests }));
}

export async function listApprovalRequests(services: Services, request: BindingRequest) {
  const approvalRequests = await services.authority.listApprovalRequests(
    request.operatorId,
    request.params.bindingId,
  );
  return safeAuthorityResponse({ approval_requests: approvalRequests });
}
