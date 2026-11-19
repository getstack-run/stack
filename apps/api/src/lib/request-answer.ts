// What the engine tells a deployment about each answer it finished: the route template, the status, and for a 501 the vault service whose
// credential was missing. The deployment's own seam (`ApiExtension.observeRequestEnd`) counts them; the engine only reports.

import type { FastifyInstance } from 'fastify';
import { safeRouteTemplate } from '@stack/shared';

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * Set by the error handler when the answer was a NotConfiguredError that names the vault service whose credential is missing.
     * Read by the end-of-request observer; never on the wire.
     */
    notConfiguredService?: string;
  }
}

/** The route of a request no registered route matched (or whose template is not a registered one). */
export const UNMATCHED_ROUTE = 'unmatched';

export interface RequestAnswer {
  /** A registered route template, else `unmatched`: never a URL, a path with ids or a query. */
  readonly route: string;
  readonly statusCode: number;
  /** For a 501 answered from a NotConfiguredError: the id of the vault service whose credential is missing. */
  readonly notConfiguredService?: string;
}

/** Calls `observe` with each finished answer. The observer must not throw; a throw is swallowed so no request is ever affected. */
export function registerRequestAnswerObserver(app: FastifyInstance, observe: (answer: RequestAnswer) => void): void {
  app.addHook('onResponse', async (request, reply) => {
    try {
      const route = safeRouteTemplate(request.routeOptions?.url) ?? UNMATCHED_ROUTE;
      observe({
        route,
        statusCode: reply.statusCode,
        ...(request.notConfiguredService ? { notConfiguredService: request.notConfiguredService } : {}),
      });
    } catch {
      // Observing an answer never fails it.
    }
  });
}
