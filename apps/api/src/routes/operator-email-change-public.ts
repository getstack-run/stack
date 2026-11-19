import type { FastifyInstance } from 'fastify';
import { ids } from '@stack/shared';
import type { Services } from '../config/services.js';

/**
 * Public half of the email transfer. Mounted OUTSIDE the authenticated scope:
 * the single-use token is the credential, the same posture as a magic link.
 * Cancelling in particular must work with no session at
 * all - the owner of a hijacked account may not have one.
 */
export function registerOperatorEmailChangePublicRoutes(app: FastifyInstance, services: Services) {
  app.post('/v1/operators/email-change/confirm', async (request, reply) => {
    const { token } = (request.body ?? {}) as { token?: string };
    if (!token || typeof token !== 'string') {
      return reply.status(400).send({ error: { message: 'token is required' } });
    }
    const start = Date.now();
    const result = await services.emailChange.confirm(token, {
      traceId: request.id,
      spanId: ids.session(),
      startedAtMs: start,
    });

    return { email: result.email };
  });

  app.post('/v1/operators/email-change/cancel', async (request, reply) => {
    const { token } = (request.body ?? {}) as { token?: string };
    if (!token || typeof token !== 'string') {
      return reply.status(400).send({ error: { message: 'token is required' } });
    }
    const start = Date.now();
    await services.emailChange.cancel(token, {
      traceId: request.id,
      spanId: ids.session(),
      startedAtMs: start,
    });

    return { cancelled: true };
  });
}
