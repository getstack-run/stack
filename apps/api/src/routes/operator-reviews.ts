import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  ForbiddenError,
  OperatorReviewInput,
  canonicalize,
  sha256,
  type HumanOperatorAuthor,
} from '@stack/shared';
import { DISMISSAL_SUPPRESS_SECONDS } from '@stack/vault';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { requireControls } from '../middleware/require-controls.js';

const MissionParams = z.object({ id: z.string().regex(/^ms_[\w-]+$/) });
const AgentParams = z.object({ agentId: z.string().regex(/^agt_[\w-]+$/) });
const ReviewParams = MissionParams.extend({ claim_id: z.string().regex(/^pc_[\w-]+$/) });
const DecisionBody = z.object({
  action: z.enum([
    'checkout_approved',
    'checkout_blocked',
    'security_events_dismissed',
    'agent_suspended',
    'future_warning_block_enabled',
    'future_critical_block_enabled',
  ]),
  source_ids: z.array(z.string().min(1).max(200)).min(1).max(100),
});

function decisionSession(request: FastifyRequest) {
  if (!request.dashboardBrowserSession) throw new ForbiddenError('A verified dashboard session is required');
  return request.dashboardBrowserSession;
}

export function resolveOperatorReviewAuthor(request: Pick<
  FastifyRequest,
  'isDashboardSession' | 'operatorId' | 'memberId' | 'memberRole' | 'agentId'
>): HumanOperatorAuthor {
  if (request.isDashboardSession !== true || request.agentId) {
    throw new ForbiddenError('This action requires a human dashboard session');
  }
  if (request.memberId) {
    if (request.memberRole !== 'standard' && request.memberRole !== 'admin') {
      throw new ForbiddenError('This action requires an active standard or admin member');
    }
    return {
      kind: 'team_member',
      member_id: request.memberId,
      role_at_signing: request.memberRole,
    };
  }
  return { kind: 'operator_owner', operator_id: request.operatorId };
}

export function assertOperatorReviewReader(request: Pick<FastifyRequest, 'agentId'>): void {
  if (request.agentId) {
    throw new ForbiddenError('This evidence route requires a direct operator principal');
  }
}

export function registerOperatorReviewRoutes(app: FastifyInstance, services: Services): void {
  const auth = createAuthMiddleware(services);

  app.post('/v1/operator-decisions', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const body = DecisionBody.parse(request.body);
    const author = resolveOperatorReviewAuthor(request);
    const result = await services.operatorDecision.decide({
      operatorId: request.operatorId,
      authoredBy: author,
      browserSession: decisionSession(request),
      action: body.action,
      sourceIds: body.source_ids,
      auditContext: auditCtx(request),
    });
    return reply.status(201).send(result);
  });

  // Dismiss every open warning of one agent in one step, and keep new ones of the same kinds from coming back
  // for a day. The Console button and the owner's MCP tool both land here. Warnings and info only: a critical
  // is never dismissed or silenced by this, and the notification each event sent when it was first raised was
  // already delivered. Owner or member (never an agent); one audit row names who, how many and which kinds.
  app.post('/v1/agents/:agentId/dismiss-warnings', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const { agentId } = AgentParams.parse(request.params);
    if (request.memberId && request.memberRole !== 'standard' && request.memberRole !== 'admin') {
      throw new ForbiddenError('This action requires an active standard or admin member');
    }
    await services.agent.getById(agentId, request.operatorId);
    const start = Date.now();
    const resolvedBy = request.memberId ? `member:${request.memberId}` : `operator:${request.operatorId}`;
    const resolved = await services.securityEvent.dismissOpenForAgent(request.operatorId, agentId, resolvedBy);
    const bySignal: Record<string, number> = {};
    for (const row of resolved) bySignal[row.signal_type] = (bySignal[row.signal_type] ?? 0) + 1;
    await services.audit.write({
      ctx: auditCtx(request, { agent_id: agentId }),
      layer: 'vault',
      action: 'security_events.dismiss_agent',
      outcome: 'success',
      duration_ms: Date.now() - start,
      payload_hash: sha256(canonicalize({ agent_id: agentId, resolved_by: resolvedBy, dismissed: resolved.length, by_signal: bySignal })),
    });
    return reply.send({
      agent_id: agentId,
      dismissed: resolved.length,
      by_signal_type: bySignal,
      repeats_hidden_for_seconds: DISMISSAL_SUPPRESS_SECONDS,
    });
  });

  app.get('/v1/missions/:id/operator-review-source', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    const params = MissionParams.parse(request.params);
    resolveOperatorReviewAuthor(request);
    return services.operatorReview.source(params.id, request.operatorId);
  });

  app.get('/v1/missions/:id/operator-reviews', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const params = MissionParams.parse(request.params);
    assertOperatorReviewReader(request);
    const items = await services.operatorReview.list(params.id, request.operatorId);
    return reply.send({ items });
  });

  app.post('/v1/missions/:id/operator-reviews', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const params = MissionParams.parse(request.params);
    const author = resolveOperatorReviewAuthor(request);
    const input = OperatorReviewInput.parse(request.body);
    const result = await services.operatorReview.create(
      params.id,
      request.operatorId,
      input,
      author,
      auditCtx(request),
      decisionSession(request),
    );
    return reply.status(201).send(result);
  });

  app.post(
    '/v1/missions/:id/operator-reviews/:claim_id/revisions',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const params = ReviewParams.parse(request.params);
      const author = resolveOperatorReviewAuthor(request);
      const input = OperatorReviewInput.parse(request.body);
      const result = await services.operatorReview.revise(
        params.id,
        params.claim_id,
        request.operatorId,
        input,
        author,
        auditCtx(request),
        decisionSession(request),
      );
      return reply.status(201).send(result);
    },
  );

  app.get(
    '/v1/missions/:id/operator-reviews/:claim_id/download',
    // A signed review's download is part of the record: a controls feature (402 CONTROLS_REQUIRED without controls).
    { preHandler: [auth, denyAgentContexts, requireControls(services)] },
    async (request, reply) => {
      const params = ReviewParams.parse(request.params);
      assertOperatorReviewReader(request);
      const result = await services.operatorReview.download(
        params.id,
        params.claim_id,
        request.operatorId,
      );
      return reply
        .header('Content-Type', 'application/cose')
        .header('Content-Disposition', `attachment; filename="operator-review-${params.id}-${params.claim_id}.cose"`)
        .header('Digest', `sha-256=${result.digest_sha256_base64}`)
        .header('Content-Length', String(result.bytes.length))
        .send(result.bytes);
    },
  );
}
