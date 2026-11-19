import type { FastifyInstance } from 'fastify';
import { denyAgentContexts, requireOperatorAdmin } from '../middleware/require-platform.js';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import {
  grantDelegation,
  listClaims,
  revokeClaim,
} from './identity-flows/claims.js';
import {
  createOidcConfig,
  deleteOidcConfig,
  getOidcConfig,
  testOidcConfig,
  updateOidcConfig,
} from './identity-flows/oidc-config.js';
import {
  deleteServiceRequirement,
  getServiceRequirements,
  replaceServiceRequirement,
  setServiceRequirement,
} from './identity-flows/service-requirements.js';
import {
  createTrustDomain,
  deleteTrustDomain,
  getTrustDomain,
  listTrustDomains,
  updateTrustDomain,
} from './identity-flows/spiffe.js';
import {
  handleOidcCallback,
  redeemSsoHandoff,
  startSsoLogin,
} from './identity-flows/sso-login.js';
import {
  completeVerification,
  completeVerificationWithToken,
  getVerificationSession,
  initiateVerification,
  listPendingSessions,
  listProviders,
  syncVerification,
} from './identity-flows/verification.js';
import {
  createWimseIssuer,
  deleteWimseIssuer,
  getWimseIssuer,
  listWimseIssuers,
  updateWimseIssuer,
} from './identity-flows/wimse.js';

export { publicIdentityClaim } from './identity-flows/claims.js';

/**
 * Identity routes. This file declares every route with its auth options and
 * hands the body to the matching module in `identity-flows/`:
 * verification.ts, claims.ts, service-requirements.ts, oidc-config.ts,
 * spiffe.ts, wimse.ts and sso-login.ts.
 */
export function registerIdentityRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  // ── Provider discovery ────────────────────────────────────────────

  app.get('/v1/identity/providers', { preHandler: auth }, async (request) => {
    return listProviders(request, services);
  });

  // ── Verification flow ─────────────────────────────────────────────

  app.post('/v1/identity/verify/initiate', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    return initiateVerification(request, reply, services);
  });

  app.get('/v1/identity/verify/sessions', { preHandler: auth }, async (request) => {
    return listPendingSessions(request, services);
  });

  app.get('/v1/identity/verify/sessions/:id', { preHandler: auth }, async (request) => {
    return getVerificationSession(request, services);
  });

  app.post('/v1/identity/verify/sync', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return syncVerification(request, services);
  });

  app.post('/v1/identity/verify/complete', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    return completeVerification(request, services);
  });

  // ── Inline token verification (a provider's widget token) ─────────────────

  app.post('/v1/identity/verify/token', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    return completeVerificationWithToken(request, reply, services);
  });

  // ── Layer 3: Delegation consent ───────────────────────────────────

  app.post('/v1/identity/delegate', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    return grantDelegation(request, reply, services);
  });

  // ── Claim management ──────────────────────────────────────────────

  app.get('/v1/identity/claims', { preHandler: auth }, async (request) => {
    return listClaims(request, services);
  });

  app.delete<{ Params: { id: string } }>(
    '/v1/identity/claims/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      return revokeClaim(request, services);
    },
  );

  // ── Service identity requirements ─────────────────────────────────

  app.get<{ Params: { id: string } }>(
    '/v1/services/:id/requirements',
    { preHandler: auth },
    async (request) => {
      return getServiceRequirements(request, services);
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/services/:id/requirements',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return setServiceRequirement(request, reply, services);
    },
  );

  app.put<{ Params: { id: string } }>(
    '/v1/services/:id/requirements',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return replaceServiceRequirement(request, reply, services);
    },
  );

  app.delete<{ Params: { id: string; reqId: string } }>(
    '/v1/services/:id/requirements/:reqId',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return deleteServiceRequirement(request, reply, services);
    },
  );

  // ── OIDC IdP configuration (enterprise SSO) ──────────────────────
  //
  // Whoever configures the account's identity provider decides who can sign in as any member, the owner included, so
  // every route here, reads too, is for the owner or an administrator member and refuses an agent context
  // (requireOperatorAdmin does both). Not exposed via the SDKs or as an MCP tool, deliberately: configuring who may log
  // in is a governance action, and under no-self-authorization an agent context must never reach it. What loosens it
  // (a new provider, a changed issuer, client, address or role, turning sign-in on) is also a browser-only governance
  // step-up inside the handlers (`sso_config_change`).

  app.get('/v1/identity/oidc/config', { preHandler: [auth, requireOperatorAdmin] }, async (request) => {
    return getOidcConfig(request, services);
  });

  app.post('/v1/identity/oidc/config', { preHandler: [auth, requireOperatorAdmin] }, async (request, reply) => {
    return createOidcConfig(request, reply, services);
  });

  app.patch<{ Params: { id: string } }>(
    '/v1/identity/oidc/config/:id',
    { preHandler: [auth, requireOperatorAdmin] },
    async (request, reply) => {
      return updateOidcConfig(request, reply, services);
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/identity/oidc/config/:id/test',
    { preHandler: [auth, requireOperatorAdmin] },
    async (request, reply) => {
      return testOidcConfig(request, reply, services);
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/identity/oidc/config/:id',
    { preHandler: [auth, requireOperatorAdmin] },
    async (request, reply) => {
      return deleteOidcConfig(request, reply, services);
    },
  );

  // ── SPIFFE trust domains ──────────────────────────────────────────

  app.get('/v1/identity/spiffe/trust-domains', { preHandler: auth }, async (request) => {
    return listTrustDomains(request, services);
  });

  app.get<{ Params: { id: string } }>(
    '/v1/identity/spiffe/trust-domains/:id',
    { preHandler: auth },
    async (request) => {
      return getTrustDomain(request, services);
    },
  );

  app.post('/v1/identity/spiffe/trust-domains', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    return createTrustDomain(request, reply, services);
  });

  app.patch<{ Params: { id: string } }>(
    '/v1/identity/spiffe/trust-domains/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return updateTrustDomain(request, reply, services);
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/identity/spiffe/trust-domains/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return deleteTrustDomain(request, reply, services);
    },
  );

  // ── WIMSE issuers ─────────────────────────────────────────────────

  app.get('/v1/identity/wimse/issuers', { preHandler: auth }, async (request) => {
    return listWimseIssuers(request, services);
  });

  app.get<{ Params: { id: string } }>(
    '/v1/identity/wimse/issuers/:id',
    { preHandler: auth },
    async (request) => {
      return getWimseIssuer(request, services);
    },
  );

  app.post('/v1/identity/wimse/issuers', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    return createWimseIssuer(request, reply, services);
  });

  app.patch<{ Params: { id: string } }>(
    '/v1/identity/wimse/issuers/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return updateWimseIssuer(request, reply, services);
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/v1/identity/wimse/issuers/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      return deleteWimseIssuer(request, reply, services);
    },
  );

  // ── SSO login: handoff redemption ────────────────────────────────

  app.post('/v1/identity/sso/handoff', async (request, reply) => {
    return redeemSsoHandoff(request, reply);
  });

  // ── SSO login: entry ─────────────────────────────────────────────

  app.get<{ Params: { slug: string }; Querystring: { browser_binding?: string } }>('/v1/identity/sso/:slug/start', async (request, reply) => {
    return startSsoLogin(request, reply, services);
  });

  // ── OIDC IdP callback ────────────────────────────────────────────

  app.get('/v1/identity/oidc/callback', async (request, reply) => {
    return handleOidcCallback(request, reply, services);
  });
}
