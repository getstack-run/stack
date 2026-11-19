import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Services } from '../../config/services.js';
import type { ClientMetadataResolver } from '../../lib/oauth-cimd.js';

/**
 * Shared types for the stages of the OAuth endpoints. `registerOAuthRoutes`
 * (`routes/oauth.ts`) declares every route and hands each handler the context
 * it used to close over; the stage modules in this directory hold the bodies.
 */

export type OAuthHttpRequest = FastifyRequest;
export type OAuthHttpReply = FastifyReply;

/** What the registrar built once and every handler reads. */
export interface OAuthFlowContext {
  services: Services;
  db: Services['db'];
  clientMetadata: ClientMetadataResolver;
}
