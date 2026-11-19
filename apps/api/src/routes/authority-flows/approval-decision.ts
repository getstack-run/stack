import type { FastifyRequest } from 'fastify';
import { AuthorityApprovalDecisionInput, NotFoundError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { safeAuthorityResponse } from '../../lib/authority-safe-response.js';
import { resolveDashboardAuthorityAuthor } from './dashboard-author.js';
import { idempotencyKey } from './request-support.js';

/**
 * Approval decisions are intentionally outside Bearer auth. The dashboard
 * cookie identifies the human; the authority service maps that server-derived
 * author to an eligible authorizer and validates the exact binding digest and
 * evidence. Neither identity nor eligibility is trusted from the body.
 */
export async function decideApproval(
  services: Services,
  request: FastifyRequest<{ Params: { approvalId: string } }>,
) {
  const { operatorId, author: authenticatedAuthor, browserSession } = await resolveDashboardAuthorityAuthor(services, request);

  const input = AuthorityApprovalDecisionInput.parse(request.body);
  if (input.request_id !== request.params.approvalId) {
    throw new NotFoundError('AuthorityApprovalRequest', request.params.approvalId);
  }
  const decision = await services.authority.decideApproval(
    operatorId,
    request.params.approvalId,
    authenticatedAuthor,
    input,
    idempotencyKey(request),
    browserSession,
  );
  await services.audit.write({
    ctx: {
      trace_id: request.id,
      span_id: request.params.approvalId,
      operator_id: operatorId,
      agent_id: 'system',
      passport_jti: 'none',
    },
    layer: 'vault',
    action: 'authority.approval.decide',
    outcome: 'success',
    duration_ms: 0,
  });
  return safeAuthorityResponse({ decision });
}
