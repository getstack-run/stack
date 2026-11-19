import type { FastifyInstance } from 'fastify';
import { auditCtx } from '../middleware/audit.js';
import { denyAgentContexts } from '../middleware/require-platform.js';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { NotFoundError, ForbiddenError } from '@stack/shared';

export function registerSecurityEventRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  // List unresolved security events (paginated, filterable).
  //
  // Synthetic agents (sandbox runner + smoke-test pseudo-agents like 'oauth')
  // are filtered out by default — their detector firings are working-as-designed
  // noise, not real-customer signals. Pass `?include_synthetic=true` to see them.
  // The filter does NOT apply when the caller filters by a specific `agent_id`
  // — explicit lookup wins (the agent activity tab in the dashboard relies on
  // this so a sandbox agent's own page can still show its events).
  app.get<{
    Querystring: {
      agent_id?: string;
      page?: string;
      limit?: string;
      include_synthetic?: string;
    };
  }>(
    '/v1/security-events',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      // Only an operator principal; member sessions and member OAuth are denied.
      if (request.memberId) {
        throw new ForbiddenError('Security events require operator access');
      }

      const page = Math.max(1, parseInt(request.query.page ?? '1', 10));
      // Cap 500, raised from 100: the console folds identical events into
      // one card, and a week of the /attack front line alone is a few
      // hundred rows - a 100-row fetch made the queue understate a real
      // fleet (190 unresolved read as "100"). Rows are small (~800B);
      // 500 is a ~400KB worst-case response, still one query.
      const limit = Math.min(500, Math.max(1, parseInt(request.query.limit ?? '50', 10)));
      const includeSynthetic =
        request.query.include_synthetic === 'true' || request.query.include_synthetic === '1';
      const excludeSynthetic = !includeSynthetic;

      const events = await services.securityEvent.getUnresolved(request.operatorId, {
        agentId: request.query.agent_id,
        page,
        limit,
        excludeSynthetic,
      });

      const unresolvedCount = await services.securityEvent.countUnresolved(
        request.operatorId,
        { excludeSynthetic },
      );

      return {
        events,
        unresolved_count: unresolvedCount,
        page,
        limit,
      };
    },
  );

  // Get a specific security event
  app.get<{ Params: { id: string } }>(
    '/v1/security-events/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      if (request.memberId) {
        throw new ForbiddenError('Security events require operator access');
      }

      const event = await services.securityEvent.getById(request.params.id);
      if (!event || event.operator_id !== request.operatorId) {
        throw new NotFoundError('SecurityEvent', request.params.id);
      }
      return event;
    },
  );

  // Resolve (mark as reviewed)
  app.post<{ Params: { id: string } }>(
    '/v1/security-events/:id/resolve',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      const start = Date.now();
      if (request.memberId) {
        throw new ForbiddenError('Security events require operator access');
      }

      const result = await services.securityEvent.resolveEvent(request.params.id, request.operatorId);
      if (!result) {
        throw new NotFoundError('SecurityEvent', request.params.id);
      }

      // Resolving an event is a governance decision by a human, and the
      // Console tells the operator their decision is signed into the chain.
      // That was not true before this write existed: the handler mutated the
      // row and returned, so an Article 12/14 surface was claiming a chain
      // entry that was never made. The claim is now backed.
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'security_event.resolve',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return { resolved: true, id: request.params.id };
    },
  );
}
