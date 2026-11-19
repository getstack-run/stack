import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ConnectionName, ForbiddenError, StackError, UnauthorizedError, type OperatorTier } from '@stack/shared';
import type { Services } from '../config/services.js';
import { auditCtx } from '../middleware/audit.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { requireRole } from '../middleware/require-role.js';
import type { ConsoleBridge } from '../lib/browser-session.js';

export const PROVIDER_OAUTH_CODE_VERIFIER_HEADER = 'x-stack-oauth-code-verifier';

const AuthorizeBody = z.object({
  provider: z.string().min(1).max(100).regex(/^[a-z0-9_]+$/).optional(),
  /** Started from a connect link: the link fixes provider and scopes. */
  connect_link_token: z.string().min(1).max(128).optional(),
  scopes: z.array(z.string().min(1).max(512)).max(100).optional(),
  return_to: z.enum(['connect', 'services']).default('services'),
  allowed_hosts: z.array(z.string().min(1).max(253)).optional(),
  /** What the new connection is called. A connect link fixes its own name, so it is not taken from here then. */
  connection_name: ConnectionName.optional(),
}).strict().refine((body) => body.provider !== undefined || body.connect_link_token !== undefined, {
  message: 'provider or connect_link_token is required',
});

const CallbackBody = z.object({
  code: z.string().min(1).max(8_192),
  state: z.string().min(1).max(16_384),
  code_verifier: z.string().min(32).max(512).optional(),
}).strict();

export function registerProviderOAuthRoutes(app: FastifyInstance, services: Services): void {
  // The routes are the Console's: its server calls them for a signed-in person. A deployment without a Console has
  // no such caller, so they answer that they are not configured, before any credential is read.
  const bridge: ConsoleBridge | null = services.consoleBridge;
  const consoleBridge = (): ConsoleBridge => {
    if (!bridge) throw new StackError('Provider sign-in through the Console is not configured', 'NOT_CONFIGURED', 404);
    return bridge;
  };
  const sessionAuth = createAuthMiddleware(services);
  const dashboardSessionOnly = async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.isDashboardSession !== true) {
      consoleBridge().privateResponse(reply);
      throw new UnauthorizedError('A dashboard session is required');
    }
  };
  const withoutConsole = async () => {
    consoleBridge();
  };
  const preHandler = bridge ? [bridge.proxyAuth(), sessionAuth, dashboardSessionOnly] : [withoutConsole];

  // Failures reach the central error handler: a ProviderOAuthError carries the
  // lowercase reason the connect page maps to its message (as `error.code`) and
  // the page to return to (`error.details.return_to`).
  app.post('/internal/provider-oauth/authorize', { preHandler }, async (request, reply) => {
    consoleBridge().privateResponse(reply);
    requireRole(request, 'standard');
    const input = AuthorizeBody.parse(request.body);
    // A connect link binds the consent to the link's own provider and scopes,
    // for exactly the account and member that created it. Its id rides only
    // inside the signed state, so the callback can complete it.
    const link = input.connect_link_token
      ? (await consoleBridge().connectLinks.resolveForSession(consoleBridge().connectLinkPrincipal(request), input.connect_link_token)).row
      : undefined;
    if (link && (link.method !== 'oauth' || (input.provider !== undefined && input.provider !== link.provider))) {
      throw new ForbiddenError('this link does not connect through the provider sign-in');
    }
    const result = await services.providerOAuth.authorize(principal(request), {
      provider: link?.provider ?? input.provider!,
      ...(link
        ? (link.scopes.length > 0 ? { scopes: link.scopes } : {})
        : input.scopes ? { scopes: input.scopes } : {}),
      returnTo: link ? 'connect' : input.return_to,
      ...(input.allowed_hosts ? { allowedHosts: input.allowed_hosts } : {}),
      ...(link ? { connectLinkId: link.id } : {}),
      ...(link
        ? (link.connection_name ? { connectionName: link.connection_name } : {})
        : input.connection_name ? { connectionName: input.connection_name } : {}),
    });
    if (result.codeVerifier) reply.header(PROVIDER_OAUTH_CODE_VERIFIER_HEADER, result.codeVerifier);
    return reply.send({ authorization_url: result.authorizationUrl });
  });

  app.post('/internal/provider-oauth/callback', { preHandler }, async (request, reply) => {
    consoleBridge().privateResponse(reply);
    const startedAt = Date.now();
    requireRole(request, 'standard');
    const input = CallbackBody.parse(request.body);
    const result = await services.providerOAuth.callback(principal(request), {
      code: input.code,
      state: input.state,
      ...(input.code_verifier ? { codeVerifier: input.code_verifier } : {}),
    });
    await services.audit.write({
      ctx: auditCtx(request),
      layer: 'vault',
      action: 'service.connect',
      outcome: 'success',
      duration_ms: Date.now() - startedAt,
    });
    services.analytics.fireOnce(request.operatorId, 'first_service_connected', {
      service_id: result.connectionId,
      kind: 'oauth',
    });
    void services.connectionVerifier.verify(result.connectionId, request.operatorId).catch(() => undefined);
    if (result.connectLinkId) {
      // The connection exists either way; a link already used or expired
      // simply stays as it was.
      await consoleBridge().connectLinks.completeWithOAuth(request.operatorId, result.connectLinkId, result.connectionId)
        .catch(() => request.log.error('connect link completion failed'));
    }
    return reply.send({
      connected: result.provider,
      connection_id: result.connectionId,
      return_to: result.returnTo,
    });
  });
}

function principal(request: FastifyRequest) {
  return {
    operatorId: request.operatorId,
    operatorTier: request.operatorTier as OperatorTier,
    ...(request.memberId ? { memberId: request.memberId } : {}),
    ...(request.memberRole ? { memberRole: request.memberRole } : {}),
    ...(request.allowedConnections ? { allowedConnections: request.allowedConnections } : {}),
  };
}
