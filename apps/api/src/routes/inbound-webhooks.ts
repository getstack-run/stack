// operator CRUD for hosted inbound webhooks.
//
// Authenticated routes (operator scope). Public receiver lives in
// routes/inbound.ts and is mounted in the public no-auth scope.

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { CreateInboundWebhookInput, NotFoundError, ForbiddenError } from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import { auditCtx } from '../middleware/audit.js';

export function registerInboundWebhookRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  // creating an inbound webhook nominates a `forward_url`: a
  // destination STACK will send every matching inbound payload to, signed with
  // STACK's own signature, for as long as the webhook lives. That is an agent
  // choosing where data leaves to, which is the decision the whole epic exists
  // to take away from it. `assertPublicUrl` on the URL is an SSRF guard, not an
  // authorization one — an attacker's server is a perfectly public address.
  //
  // So nomination is governance, and leaves the operational allowlist. Revoke
  // (DELETE, below) stays agent-reachable: tearing down your own egress is
  // safety-increasing, per the asymmetry rule.
  app.post('/v1/operator/inbound-webhooks', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const input = CreateInboundWebhookInput.parse(request.body);
    const start = Date.now();
    const result = await services.inboundWebhooks.create(request.operatorId, input);
    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.agent_id }),
      layer: 'vault',
      action: 'inbound_webhook.create',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });
    return reply.header('Cache-Control', 'no-store').status(201).send(result);
  });

  app.get('/v1/operator/inbound-webhooks', { preHandler: auth }, async (request) => {
    const webhooks = await services.inboundWebhooks.list(request.operatorId);
    return { webhooks };
  });

  app.put<{ Params: { id: string } }>(
    '/v1/operator/inbound-webhooks/:id/provider-signing-secret',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      if (request.oauthScope !== undefined) throw new ForbiddenError('Signing setup requires owner/admin authentication outside OAuth');
      const { signing_secret, downstream_signing_secret } = z.object({ signing_secret: z.string().min(1).max(256),
        downstream_signing_secret: z.string().min(1).max(256).optional() }).strict().parse(request.body);
      const result = await services.inboundWebhooks.setProviderSigningSecret(request.params.id, request.operatorId, signing_secret, downstream_signing_secret);
      await services.audit.write({ ctx: auditCtx(request), layer: 'vault', action: 'inbound_webhook.signing_secret.update',
        outcome: 'success', duration_ms: 0 });
      return reply.header('Cache-Control', 'no-store').send(result);
    },
  );

  // A fresh downstream signing secret, shown once; the one it replaces keeps signing for 24 hours.
  // Closed to OAuth like the provider signing secret: it returns a credential.
  app.post<{ Params: { id: string } }>(
    '/v1/operator/inbound-webhooks/:id/rotate-secret',
    { preHandler: [auth, denyAgentContexts, requireOperatorAdmin] },
    async (request, reply) => {
      if (request.oauthScope !== undefined) {
        throw new ForbiddenError('Rotating a signing secret requires owner/admin authentication outside OAuth');
      }
      const start = Date.now();
      const result = await services.inboundWebhooks.rotateDownstreamSecret(request.params.id, request.operatorId);
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'inbound_webhook.secret.rotate',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.header('Cache-Control', 'no-store').send(result);
    },
  );

  app.get<{ Params: { id: string } }>(
    '/v1/operator/inbound-webhooks/:id',
    { preHandler: auth },
    async (request) => {
      return services.inboundWebhooks.get(request.params.id, request.operatorId);
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/operator/inbound-webhooks/:id',
    { preHandler: auth },
    async (request, reply) => {
      const start = Date.now();
      const result = await services.inboundWebhooks.revoke(request.params.id, request.operatorId);
      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'inbound_webhook.revoke',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });
      return reply.send(result);
    },
  );

  void NotFoundError;
}
