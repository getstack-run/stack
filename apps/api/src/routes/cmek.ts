import type { FastifyInstance } from 'fastify';
import { ids } from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { requireOperatorAdmin } from '../middleware/require-platform.js';

/**
 * CMEK (Customer-Managed Encryption Keys) endpoints.
 *
 *  POST   /v1/operator/cmek    — enable CMEK with a customer KMS key ARN
 *  DELETE /v1/operator/cmek    — disable CMEK (re-encrypt back to platform key)
 *  GET    /v1/operator/cmek    — status snapshot for the dashboard
 *
 * Enterprise-tier gate lives in CmekService.enable() — keeping the tier
 * check in the service (not the route) means the worker can also reject
 * mis-tiered operators if a tier downgrade slips through. The route layer
 * only gates on auth + operator-admin role (members with role=admin can
 * touch CMEK; members without cannot).
 *
 * Every endpoint writes audit. The audit chain is what later proves to
 * the customer that they did or didn't touch their key on a given date.
 *
 * deferral 1 of the Signed Primitive epic.
 */
export function registerCmekRoutes(app: FastifyInstance, services: Services) {
  const authenticate = createAuthMiddleware(services);

  app.get(
    '/v1/operator/cmek',
    { preHandler: authenticate },
    async (request, reply) => {
      const snapshot = await services.cmek.getStatus(request.operatorId);
      return reply.send({
        status: snapshot.status,
        key_arn: snapshot.keyArn,
        activated_at: snapshot.activatedAt,
        migrations: snapshot.migrations.map((m) => ({
          id: m.id,
          direction: m.direction,
          table_name: m.table_name,
          rows_total: m.rows_total,
          rows_done: m.rows_done,
          status: m.status,
          error: m.error,
          started_at: m.started_at,
          completed_at: m.completed_at,
        })),
      });
    },
  );

  app.post(
    '/v1/operator/cmek',
    { preHandler: [authenticate, requireOperatorAdmin] },
    async (request, reply) => {
      const start = Date.now();
      const body = (request.body ?? {}) as { key_arn?: unknown };
      if (typeof body.key_arn !== 'string' || body.key_arn.length === 0) {
        return reply.status(400).send({
          error: { code: 'INVALID_REQUEST', message: 'key_arn (string) is required in the body.' },
        });
      }

      const snapshot = await services.cmek.enable(request.operatorId, body.key_arn);

      await services.audit.write({
        ctx: {
          trace_id: request.id,
          span_id: ids.session(),
          operator_id: request.operatorId,
          agent_id: 'system',
          passport_jti: 'none',
        },
        layer: 'vault',
        action: 'cmek.enable',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send({
        status: snapshot.status,
        key_arn: snapshot.keyArn,
        activated_at: snapshot.activatedAt,
        migrations_pending: snapshot.migrations.filter((m) => m.status !== 'completed').length,
      });
    },
  );

  app.delete(
    '/v1/operator/cmek',
    { preHandler: [authenticate, requireOperatorAdmin] },
    async (request, reply) => {
      const start = Date.now();

      const snapshot = await services.cmek.disable(request.operatorId);

      await services.audit.write({
        ctx: {
          trace_id: request.id,
          span_id: ids.session(),
          operator_id: request.operatorId,
          agent_id: 'system',
          passport_jti: 'none',
        },
        layer: 'vault',
        action: 'cmek.disable',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send({
        status: snapshot.status,
        key_arn: snapshot.keyArn,
        activated_at: snapshot.activatedAt,
        migrations_pending: snapshot.migrations.filter((m) => m.status !== 'completed').length,
      });
    },
  );
}
