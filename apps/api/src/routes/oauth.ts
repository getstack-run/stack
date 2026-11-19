// OAuth 2.1
//
// All endpoints under /.well-known/oauth-authorization-server, /oauth/*.
// Gated by env.OAUTH_ENABLED — when off the registrar returns early and
// no routes are mounted (clients see 404). Design + invariants live at
// the agent auth design § Implementation ADR.
//
// Tokens are stored by sha256 hash. Refresh tokens implement
// rotation-on-use with reuse-detection per OAuth 2.1 §6.1: presenting an
// already-replaced refresh hash revokes the entire token_family_id.
//
// PKCE S256 is mandatory. `plain` is refused. Resource Indicators
// (RFC 8707) bind tokens to the stack:api or stack:mcp audience; MCP tokens
// also carry the exact resource URL (/mcp or /directory) as a signed claim.
// Tokens for the directory resource are clamped to OAUTH_DIRECTORY_SCOPES.
//
// Client ID Metadata Documents: an https client_id is resolved by fetching
// the document at that URL (apps/api/src/lib/oauth-cimd.ts, threat model
// there) and persisted as a public client row.
//
// This file declares every route and its hooks. The handler bodies live in
// routes/oauth-flows/, one module per stage of the protocol.

import type { FastifyInstance } from 'fastify';
import { env } from '../config/env.js';
import type { Services } from '../config/services.js';
import {
  createClientMetadataResolver,
  type ClientMetadataResolver,
} from '../lib/oauth-cimd.js';
import type { OAuthFlowContext } from './oauth-flows/context.js';
import { handleDiscovery } from './oauth-flows/discovery.js';
import { handleClientRegistration } from './oauth-flows/registration.js';
import { handleAuthorizeRequest } from './oauth-flows/authorize.js';
import { handleConsentDecision } from './oauth-flows/consent.js';
import { handleTokenRequest } from './oauth-flows/token-endpoint.js';
import { handleDeviceAuthorize } from './oauth-flows/device-authorize.js';
import { handleDeviceDecision } from './oauth-flows/device-decision.js';
import { handleRevocation } from './oauth-flows/revocation.js';

// ─── Route registrar ─────────────────────────────────────────────────

export function registerOAuthRoutes(
  app: FastifyInstance,
  services: Services,
  options: { clientMetadata?: ClientMetadataResolver } = {},
) {
  if (env.OAUTH_ENABLED !== 'true' && env.OAUTH_ENABLED !== '1') {
    // Off: do not mount any /oauth/* or /.well-known/oauth-* routes.
    return;
  }

  const db = services.db;
  const clientMetadata = options.clientMetadata ?? createClientMetadataResolver();
  const flow: OAuthFlowContext = { services, db, clientMetadata };

  // /oauth/token + /oauth/device/authorize + /oauth/revoke accept
  // application/x-www-form-urlencoded per RFC 6749 / 8628. The default
  // Fastify only handles JSON; register a parser for form bodies.
  // Safe to call repeatedly across registrars (Fastify dedupes).
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    try {
      const params = Object.fromEntries(new URLSearchParams(body as string));
      done(null, params);
    } catch (err) {
      done(err as Error, undefined);
    }
  });

  // ─── Discovery (RFC 8414) ───────────────────────────────────────────
  app.get('/.well-known/oauth-authorization-server', async (_req, reply) => {
    return handleDiscovery(reply);
  });

  // ─── Dynamic Client Registration (RFC 7591) ────────────────────────
  app.post(
    '/oauth/register',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 hour' } },
    },
    async (req, reply) => {
      return handleClientRegistration(flow, req, reply);
    },
  );

  // ─── /oauth/authorize — entry ──────────────────────────────────────
  app.get('/oauth/authorize', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req, reply) => {
    return handleAuthorizeRequest(flow, req, reply);
  });

  // ─── POST /oauth/authorize — consent confirm ───────────────────────
  app.post('/oauth/authorize', async (req, reply) => {
    return handleConsentDecision(flow, req, reply);
  });

  // ─── /oauth/token — multi-grant exchange ──────────────────────────
  app.post('/oauth/token', async (req, reply) => {
    return handleTokenRequest(services, req, reply);
  });

  // ─── /oauth/device/authorize (RFC 8628) ───────────────────────────
  app.post(
    '/oauth/device/authorize',
    {
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      return handleDeviceAuthorize(flow, req, reply);
    },
  );

  // ─── /oauth/device/approve + /oauth/device/deny ──────────────────
  app.post('/oauth/device/approve', async (req, reply) => {
    return handleDeviceDecision(services, req, reply, 'approve');
  });
  app.post('/oauth/device/deny', async (req, reply) => {
    return handleDeviceDecision(services, req, reply, 'deny');
  });

  // ─── /oauth/revoke (RFC 7009) ─────────────────────────────────────
  app.post('/oauth/revoke', async (req, reply) => {
    return handleRevocation(flow, req, reply);
  });
}
