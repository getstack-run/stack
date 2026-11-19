import type { FastifyInstance } from 'fastify';
import { createAuthMiddleware } from '../middleware/auth.js';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import type { Services } from '../config/services.js';

/**
 * GET /v1/licence: what this self-managed install's licence grants, and until
 * when. Registered only by a self-managed install; STACK's hosted deployment
 * gates features by plan. The owner or an admin reads it; an agent never does,
 * and the key itself is never returned.
 */
export function registerLicenceRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.get(
    '/v1/licence',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async () => services.features.snapshot(),
  );
}
