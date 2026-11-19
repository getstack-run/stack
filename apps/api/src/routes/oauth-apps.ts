import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';

const CreateOauthAppInput = z.object({
  provider: z.string().min(1).max(100),
  client_id: z.string().min(1),
  client_secret: z.string().min(1),
  scopes: z.string().optional(),
  /**
   * The directory a single-tenant Microsoft app is registered in (an id or a
   * verified domain). Kept with the secret, in its KMS envelope; without one,
   * Microsoft sign-in uses the multi-tenant endpoint.
   */
  tenant: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/).optional(),
});

/**
 * (auth refactor): operator-admin-scoped. Mounted through the
 * operator-admin encapsulation block in server.ts — [auth,
 * requireOperatorAdmin] inherited from the scope.
 */
export function registerOauthAppRoutes(app: FastifyInstance, services: Services) {
  app.post('/v1/oauth-apps', async (request, reply) => {
    const input = CreateOauthAppInput.parse(request.body);
    const start = Date.now();

    const result = await services.oauthApp.create(request.operatorId, input);

    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'oauth_app.create',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.status(201).send(result);
  });

  app.get('/v1/oauth-apps', async (request) => {
    return services.oauthApp.list(request.operatorId);
  });

  app.delete<{ Params: { provider: string } }>(
    '/v1/oauth-apps/:provider',
    async (request) => {
      const start = Date.now();

      const result = await services.oauthApp.delete(request.operatorId, request.params.provider);

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'oauth_app.delete',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return result;
    },
  );
}
