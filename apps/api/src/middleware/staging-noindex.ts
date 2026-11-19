import type { FastifyInstance } from 'fastify';
import { STAGING_ROBOTS_TAG, staging } from '@stack/shared';

/**
 * On a staging deployment (`STACK_STAGING=true`) every answer the API sends,
 * a refusal, a 404 and an error included, carries `X-Robots-Tag: noindex,
 * nofollow`, so nothing a crawler reaches on staging is indexed. Added on the
 * root instance before any plugin or route, so every child context inherits
 * it. Outside staging it adds nothing and answers are unchanged.
 */
export function registerStagingNoindex(app: FastifyInstance, enabled: boolean = staging().enabled): void {
  if (!enabled) return;
  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('X-Robots-Tag', STAGING_ROBOTS_TAG);
    return payload;
  });
}
