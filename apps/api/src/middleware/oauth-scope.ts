import type { FastifyReply, FastifyRequest } from 'fastify';
import type { OAuthScope } from '@stack/shared';

/**
 * Exact OAuth route ceiling. `null` marks routes whose authentication is a
 * different protocol (dashboard cookie, signed webhook, receiver JWS, or a
 * public endpoint). An OAuth bearer never gains access to an unmapped or null
 * route when enforcement is enabled.
 *
 * The engine owns the ceiling of the routes it serves (`ENGINE_ROUTE_SCOPES`).
 * A deployment's own routes are added to it by registering them with the
 * `routeScopes` registry (`config/registries.ts`) before the server listens;
 * a route nobody mapped is refused to an OAuth bearer, as it always was.
 */
export type OAuthRouteRequirement = OAuthScope | null;

/** The routes one scope reaches, as entries of the ceiling. */
export function scoped(
  scope: OAuthRouteRequirement,
  routes: readonly string[],
): Array<readonly [string, OAuthRouteRequirement]> {
  return routes.map((route) => [route, scope] as const);
}

/** A ceiling table as a frozen record; a route listed twice is a wiring mistake and throws. */
export function routeScopeTable(
  entries: ReadonlyArray<readonly [string, OAuthRouteRequirement]>,
  name: string,
): Readonly<Record<string, OAuthRouteRequirement>> {
  const duplicateKeys = entries
    .map(([key]) => key)
    .filter((key, index, all) => all.indexOf(key) !== index);
  if (duplicateKeys.length > 0) {
    throw new Error(`Duplicate OAuth route scope entries in ${name}: ${[...new Set(duplicateKeys)].join(', ')}`);
  }
  return Object.freeze(Object.fromEntries(entries));
}

const engineRouteEntries: Array<readonly [string, OAuthRouteRequirement]> = [
  ...scoped('account:read', [
    'GET /v1/auth/context',
    'GET /v1/operators/me',
    'GET /v1/operators/me/email-change',
    'GET /v1/operators/me/identity-settings',
    'GET /v1/operators/me/mcp-sessions',
  ]),
  ...scoped('account:write', [
    'DELETE /v1/operators/me/mcp-sessions/:familyId',
    'PATCH /v1/operators/me/identity-settings',
  ]),
  // Erasing the account and changing its e-mail are the owner's, from the Console: no OAuth token stands in, whatever
  // scopes it holds (account:write is in the default /mcp sign-in).
  ...scoped(null, [
    'DELETE /v1/operators/me',
    'POST /v1/operators/me/email-change',
  ]),
  ...scoped('team:read', ['GET /v1/team/members']),
  ...scoped('team:write', [
    'POST /v1/team/members',
    'PATCH /v1/team/members/:id',
    'DELETE /v1/team/members/:id',
    'POST /v1/team/sso-bindings/clear',
  ]),
  ...scoped('oauth-apps:read', [
    'GET /v1/oauth-apps',
  ]),
  ...scoped('oauth-apps:write', [
    'POST /v1/oauth-apps',
    'DELETE /v1/oauth-apps/:provider',
  ]),
  ...scoped('cmek:read', ['GET /v1/operator/cmek']),
  ...scoped('cmek:write', ['POST /v1/operator/cmek', 'DELETE /v1/operator/cmek']),

  ...scoped('agents:read', [
    'GET /v1/agents',
    'GET /v1/agents/:id',
    'GET /v1/agents/:id/stats',
    'GET /v1/agents/:agentId/permissions',
    'GET /v1/fleets',
    'GET /v1/fleets/:id',
    'GET /v1/fleets/membership/:agentId',
    'GET /v1/fleets/:id/members',
  ]),
  ...scoped('agents:write', [
    'POST /v1/agents/register',
    'POST /v1/agents/setup',
    'PATCH /v1/agents/:id',
    'DELETE /v1/agents/:id',
    'POST /v1/agents/:id/enroll',
    'POST /v1/agents/:id/enrollment-challenge',
    'POST /v1/agents/:id/enrollment-tickets',
    'POST /v1/agents/:id/unblock',
    'POST /v1/agents/:id/allowed-skills',
    'DELETE /v1/agents/:id/allowed-skills/:skillId',
    'POST /v1/fleets',
    'PUT /v1/fleets/:id',
    'POST /v1/fleets/:id/revoke',
    'POST /v1/fleets/:id/members/:agentId/revoke',
  ]),
  // The control socket: who decides for the customer's agents and where their
  // record goes. Reading it shows the decisions' targets (recipients, hosts), and
  // changing it moves them, so every route is an operator control, outside the
  // directory ceiling. An address change, a rotation and anything that loosens
  // also need a human approval in a browser (governance step-up, browser-only).
  ...scoped('accounts:manage', [
    'GET /v1/control-socket',
    'PUT /v1/control-socket/decision',
    'PUT /v1/control-socket/events',
    'DELETE /v1/control-socket/:target',
    'POST /v1/control-socket/:target/verify',
    'POST /v1/control-socket/:target/test',
    'POST /v1/control-socket/:target/secret/rotate',
    'PUT /v1/control-socket/mode',
    'PUT /v1/control-socket/on-unavailable',
    'PUT /v1/control-socket/checked-types',
    'GET /v1/control-decisions',
    'GET /v1/control-decisions/:id',
  ]),
  // Policies, the configuration behind hosted controls, and the actions they
  // hold for a person. Operator controls like the socket: outside the directory
  // ceiling. Loosening or deleting a policy also needs a human approval in a
  // browser (governance step-up, browser-only); tightening applies at once.
  ...scoped('accounts:manage', [
    'GET /v1/control-policies',
    'GET /v1/control-policies/default',
    'GET /v1/control-policies/agents/:agentId',
    'PUT /v1/control-policies/default',
    'PUT /v1/control-policies/agents/:agentId',
    'DELETE /v1/control-policies/default',
    'DELETE /v1/control-policies/agents/:agentId',
    'POST /v1/control-policies/agents/:agentId/start-from-current-access',
    'POST /v1/control-policies/simulate',
    'GET /v1/control-policies/:id/revisions',
    'GET /v1/control-reviews',
    'GET /v1/control-reviews/:id',
  ]),

  ...scoped('passports:read', [
    'GET /v1/passports/active',
    'POST /v1/passports/verify',
  ]),
  ...scoped('passports:write', [
    'POST /v1/passports/issue',
    'POST /v1/passports/delegate',
    'POST /v1/passports/refresh',
    'POST /v1/passports/revoke',
    'POST /v1/passports/revoke-agent/:agentId',
    'POST /v1/passports/revoke-all',
    'POST /v1/passports/revoke-session/:sessionId',
    'POST /v1/passports/:jti/checkpoint',
    'POST /v1/passports/:jti/checkout',
  ]),
  ...scoped('reviews:read', [
    'GET /v1/passports/:jti/report',
    'GET /v1/passports/reviews',
  ]),
  ...scoped('reviews:write', ['POST /v1/passports/reviews/:checkoutId/decide']),

  ...scoped('services:read', [
    'GET /v1/services',
    'GET /v1/services/connected',
    'GET /v1/services/templates',
    'GET /v1/services/configurations',
    'GET /v1/services/:id/requirements',
  ]),
  ...scoped('services:connect', [
    'POST /v1/services/connect',
    'POST /v1/services/connect-application',
    'POST /v1/services/custom',
  ]),
  ...scoped('services:write', [
    'POST /v1/services/:id/verify',
    'POST /v1/services/configure',
    'DELETE /v1/services/configurations/:provider',
    'DELETE /v1/services/:id/disconnect',
    'POST /v1/services/grant',
    'DELETE /v1/services/agents/:agentId/revoke',
    'POST /v1/services/:id/proxy-toggle',
    'PATCH /v1/services/:id',
    'POST /v1/services/:id/allowed-hosts',
    'POST /v1/services/:id/requirements',
    'PUT /v1/services/:id/requirements',
    'DELETE /v1/services/:id/requirements/:reqId',
  ]),
  ...scoped('inbound-webhooks:read', [
    'GET /v1/operator/inbound-webhooks',
    'GET /v1/operator/inbound-webhooks/:id',
  ]),
  ...scoped('inbound-webhooks:write', [
    'POST /v1/operator/inbound-webhooks',
    'DELETE /v1/operator/inbound-webhooks/:id',
  ]),

  ...scoped('credentials:read', [
    'GET /v1/credentials/:provider',
    'GET /v1/credentials/by-connection/:connectionId',
  ]),
  ...scoped('proxy:read', [
    'GET /v1/proxy/usage',
    'POST /v1/proxy/operations/get',
  ]),
  ...scoped('proxy:write', ['POST /v1/proxy']),
  ...scoped(null, [
    'POST /v1/dashboard/proxy/operations/get',
    'POST /v1/proxy/operations/reconcile',
    'POST /v1/proxy/operations/authorize-replacement',
    // A self-managed install's licence: an operator's own API key reads it, an OAuth client never.
    'GET /v1/licence',
  ]),

  ...scoped('audit:read', [
    'GET /v1/audit',
    'GET /v1/audit/export',
    'GET /v1/audit/chain-head',
    'GET /v1/audit/verify-chain',
  ]),
  // Reading a control-socket signing secret is the customer's own act in the
  // Console: no OAuth token (a chat assistant) may ever hold one.
  ...scoped(null, ['POST /v1/control-socket/secret/reveal']),

  ...scoped('identity:read', [
    'GET /v1/identity/providers',
    'GET /v1/identity/verify/sessions',
    'GET /v1/identity/verify/sessions/:id',
    'GET /v1/identity/claims',
    'GET /v1/identity/oidc/config',
    'GET /v1/identity/sso-domains',
    'GET /v1/identity/spiffe/trust-domains',
    'GET /v1/identity/spiffe/trust-domains/:id',
    'GET /v1/identity/wimse/issuers',
    'GET /v1/identity/wimse/issuers/:id',
  ]),
  ...scoped('identity:write', [
    'POST /v1/identity/verify/initiate',
    'POST /v1/identity/verify/sync',
    'POST /v1/identity/verify/complete',
    'POST /v1/identity/verify/token',
    'POST /v1/identity/delegate',
    'DELETE /v1/identity/claims/:id',
    'POST /v1/identity/oidc/config',
    'PATCH /v1/identity/oidc/config/:id',
    'POST /v1/identity/oidc/config/:id/test',
    'DELETE /v1/identity/oidc/config/:id',
    'POST /v1/identity/sso-domains',
    'POST /v1/identity/sso-domains/:id/verify',
    'DELETE /v1/identity/sso-domains/:id',
    'POST /v1/identity/spiffe/trust-domains',
    'PATCH /v1/identity/spiffe/trust-domains/:id',
    'DELETE /v1/identity/spiffe/trust-domains/:id',
    'POST /v1/identity/wimse/issuers',
    'PATCH /v1/identity/wimse/issuers/:id',
    'DELETE /v1/identity/wimse/issuers/:id',
  ]),

  ...scoped('authority:read', [
    'GET /v1/authority/bindings',
    'GET /v1/authority/bindings/:bindingId',
    'GET /v1/authority/bindings/:bindingId/approval-requests',
    'GET /v1/authority/enterprise-oidc/requests/:requestId',
    'GET /v1/authority/presentations',
    'GET /v1/authority/presentations/:presentationId',
    'GET /v1/authority/principals',
    'GET /v1/authority/principals/:principalId',
    'GET /v1/authority/proof-collection-sessions/:sessionId',
    'GET /v1/authority/proofs',
    'GET /v1/authority/proofs/:proofId',
    'GET /v1/authority/receivers',
    'GET /v1/authority/receivers/:receiverId',
    'GET /v1/authority/uses',
    'GET /v1/authority/uses/:useId',
  ]),
  ...scoped('authority:write', [
    'POST /v1/authority/bindings',
    'POST /v1/authority/bindings/:bindingId/activate',
    'POST /v1/authority/bindings/:bindingId/approval-requests',
    'POST /v1/authority/bindings/:bindingId/delegate',
    'POST /v1/authority/bindings/:bindingId/erase',
    'POST /v1/authority/bindings/:bindingId/revoke',
    'POST /v1/authority/enterprise-oidc/requests',
    'POST /v1/authority/presentations/:presentationId/erase',
    'POST /v1/authority/principals',
    'POST /v1/authority/principals/:principalId/archive',
    'POST /v1/authority/principals/:principalId/erase',
    'POST /v1/authority/profile-versions',
    'POST /v1/authority/profile-versions/:profileId/activate',
    'POST /v1/authority/proof-collection-sessions',
    'POST /v1/authority/proofs/:proofId/erase',
    'POST /v1/authority/proofs/:proofId/revoke',
    'POST /v1/authority/proofs/import',
    'POST /v1/authority/receivers',
    'POST /v1/authority/receivers/:receiverId/keys',
    'POST /v1/authority/receivers/:receiverId/keys/:keyId/revoke',
    'POST /v1/authority/receivers/:receiverId/verification-challenges',
    'POST /v1/authority/receivers/:receiverId/verify',
  ]),

  ...scoped('governance:read', ['GET /v1/governance/approvals', 'GET /v1/governance/approvals/:id']),
  // Approve needs the hosted MCP server's attestation of the person's
  // confirmation and never reaches a browser-only action; reject is open to any
  // non-agent caller (routes/governance.ts).
  ...scoped('governance:decide', ['POST /v1/governance/approvals/:id/chat-decision']),
  ...scoped('intents:read', ['GET /v1/intents/:id', 'GET /v1/intents/pending']),
  ...scoped('intents:write', ['POST /v1/intents/submit', 'POST /v1/intents/simulate']),
  ...scoped('governance:write', [
    'POST /v1/intents/:id/approve',
    'POST /v1/intents/:id/reject',
  ]),
  ...scoped('missions:read', [
    'GET /v1/missions',
    'GET /v1/missions/:id',
    'GET /v1/missions/:id/dossiers',
    'GET /v1/missions/:id/passports',
    'GET /v1/missions/:id/replay',
  ]),
  ...scoped('missions:write', [
    'POST /v1/missions',
    // The one-call form of opening a Mission and issuing its Passport: the operator form only (the fleet form needs an
    // agent session, which no OAuth token is). It also needs passports:write, see ENGINE_ROUTE_ALSO_REQUIRED_SCOPES.
    'POST /v1/missions/start',
    'POST /v1/missions/:id/complete',
    'POST /v1/missions/:id/dossier',
    'POST /v1/missions/:id/recipients',
    'POST /v1/missions/:id/revoke',
    'POST /v1/missions/:id/review',
    'PUT /v1/missions/:id/making-allowance',
  ]),
  ...scoped('reviews:read', [
    'GET /v1/missions/:id/operator-review-source',
    'GET /v1/missions/:id/operator-reviews',
    'GET /v1/missions/:id/operator-reviews/:claim_id/download',
  ]),
  ...scoped('reviews:write', [
    'POST /v1/missions/:id/operator-reviews',
    'POST /v1/missions/:id/operator-reviews/:claim_id/revisions',
    'POST /v1/operator-decisions',
    'POST /v1/agents/:agentId/dismiss-warnings',
  ]),
  ...scoped('evidence:read', [
    'GET /v1/evidence-packs',
    'GET /v1/evidence-packs/:pack_id',
    'GET /v1/evidence-packs/:pack_id/download',
  ]),
  ...scoped('evidence:write', ['POST /v1/evidence-packs']),
  ...scoped('dropoffs:read', ['GET /v1/dropoffs', 'GET /v1/dropoffs/:id']),
  ...scoped('dropoffs:write', [
    'POST /v1/dropoffs',
    'POST /v1/dropoffs/:id/deposit',
    'POST /v1/dropoffs/:id/collect',
    'POST /v1/dropoffs/:id/expire',
    'POST /v1/a2a/jsonrpc',
  ]),

  ...scoped('notifications:read', [
    'GET /v1/notifications/channels',
    'GET /v1/notifications/destinations',
  ]),
  ...scoped('notifications:write', [
    'POST /v1/notifications/channels',
    'PATCH /v1/notifications/channels/:id',
    'DELETE /v1/notifications/channels/:id',
    'POST /v1/notifications/channels/:id/send-code',
    'POST /v1/notifications/channels/:id/test',
    'POST /v1/notifications/channels/:id/verify',
    'POST /v1/notifications/destinations',
    'DELETE /v1/notifications/destinations/:id',
    'POST /v1/notifications/destinations/:id/send-code',
    'POST /v1/notifications/destinations/:id/rotate-secret',
    'POST /v1/notifications/destinations/:id/test',
    'POST /v1/notifications/destinations/:id/verify',
  ]),
  ...scoped('security-events:read', [
    'GET /v1/security-events',
    'GET /v1/security-events/:id',
  ]),
  ...scoped('security-events:write', ['POST /v1/security-events/:id/resolve']),
  ...scoped('llm:read', ['GET /v1/llm/usage', 'GET /v1/llm/usage/summary']),
  ...scoped('llm:invoke', [
    'POST /v1/llm/anthropic/messages',
    'POST /v1/llm/openai/chat/completions',
    // OpenRouter's whole API, every method: the one wildcard route (the endpoints it reaches are the gateway's to gate).
    'GET /v1/llm/openrouter/*',
    'POST /v1/llm/openrouter/*',
    'PUT /v1/llm/openrouter/*',
    'PATCH /v1/llm/openrouter/*',
    'DELETE /v1/llm/openrouter/*',
    // An image on the customer's own provider key; Anthropic has no image endpoint and answers with the refusal.
    'POST /v1/llm/openai/images',
    'POST /v1/llm/anthropic/images',
  ]),
  ...scoped('scan:read', ['GET /v1/scan/usage']),
  ...scoped('scan:write', ['POST /v1/scan']),
  ...scoped('detectors:read', [
    'GET /v1/detectors/config',
    'GET /v1/detectors/:detector_key/config',
  ]),
  ...scoped('detectors:write', [
    'PUT /v1/detectors/:detector_key/config',
    'DELETE /v1/detectors/:detector_key/config',
  ]),
  ...scoped('pii:read', ['GET /v1/pii/config']),
  ...scoped('pii:write', ['PUT /v1/pii/config', 'DELETE /v1/pii/config']),

  ...scoped('partner:read', [
    'GET /v1/partner/accounts',
    'GET /v1/partner/accounts/:id',
    'GET /v1/partner/accounts/:account_id/inbound-webhooks',
  ]),
  ...scoped('partner:write', [
    'POST /v1/partner/accounts',
    'DELETE /v1/partner/accounts/:id',
    'POST /v1/partner/accounts/:account_id/invite',
    'POST /v1/partner/accounts/:account_id/inbound-webhooks',
    'DELETE /v1/partner/accounts/:account_id/inbound-webhooks/:wh_id',
    'POST /v1/partner/accounts/:account_id/passports/issue',
  ]),

  // These routes have public, cookie, webhook, workload, or receiver-JWS
  // authentication. They are listed so source coverage stays exhaustive,
  // but an OAuth bearer must never be treated as their credential.
  ...scoped(null, [
    'POST /internal/provider-oauth/authorize',
    'POST /internal/provider-oauth/callback',
    'PUT /v1/operator/inbound-webhooks/:id/provider-signing-secret',
    'PUT /v1/partner/accounts/:account_id/inbound-webhooks/:wh_id/provider-signing-secret',
    'POST /v1/operator/inbound-webhooks/:id/rotate-secret',
    'POST /v1/partner/accounts/:account_id/inbound-webhooks/:wh_id/rotate-secret',
    // A new key for an account is a credential, shown once: never to an OAuth bearer.
    'POST /v1/partner/accounts/:account_id/rotate-key',
    'GET /.well-known/agent.json',
    'GET /v1/agents/:id/.well-known/jwks.json',
    'GET /v1/.well-known/jwks.json',
    'GET /v1/internal/jwks',
    'POST /v1/team/invites/accept',
    'POST /v1/operators/email-change/cancel',
    'POST /v1/operators/email-change/confirm',
    'GET /v1/operators/:operator_id/jwks.json',
    'POST /v1/governance/approvals/:id/decide',
    'POST /v1/authority/proof-callbacks/:adapterKey',
    'POST /v1/authority/presentation-requests',
    'GET /v1/authority/presentation-requests/:presentationId',
    'POST /v1/authority/status-checks',
    'POST /v1/authority/presentations/:presentationId/receipts',
    'GET /v1/authority/enterprise-oidc/requests/:requestId/review',
    'POST /v1/authority/enterprise-oidc/requests/:requestId/reject',
    'POST /v1/authority/enterprise-oidc/requests/:requestId/start',
    'POST /v1/authority/enterprise-oidc/requests/:requestId/complete',
    'POST /v1/authority/approval-requests/:approvalId/decide',
    'POST /v1/identity/sso/handoff',
    'GET /v1/identity/sso/:slug/start',
    'GET /v1/identity/oidc/callback',
    'POST /v1/inbound/:provider/:slug',
    'POST /v1/workload/wit',
    'POST /v1/workload/passport',
    // Fleet session and enrollment endpoints require a fresh agent or pinned
    // workload identity; an operator OAuth token cannot stand in for either.
    'POST /v1/fleets/session',
    'POST /v1/fleets/:id/enrollment-challenges',
    'POST /v1/fleets/:id/enroll',
    'POST /v1/fleets/:id/workload/enrollment-challenges',
    'POST /v1/fleets/:id/workload/enroll',
    'POST /v1/missions/:id/renew',
    'GET /.well-known/oauth-authorization-server',
    'GET /oauth/authorize',
    'POST /oauth/authorize',
    'POST /oauth/device/approve',
    'POST /oauth/device/authorize',
    'POST /oauth/device/deny',
    'POST /oauth/register',
    'POST /oauth/revoke',
    'POST /oauth/token',
  ]),
];

/** The ceiling of the routes the engine serves. */
export const ENGINE_ROUTE_SCOPES: Readonly<Record<string, OAuthRouteRequirement>> =
  routeScopeTable(engineRouteEntries, 'the engine');

/**
 * Scopes a route needs besides the one the ceiling maps it to: an OAuth bearer reaches the route only when it holds the
 * mapped scope AND every scope listed here. A route that does in one call what two others do (open a Mission, issue its
 * Passport) needs the scope of each, so the one call is never a way round a scope the two calls ask for.
 */
export const ENGINE_ROUTE_ALSO_REQUIRED_SCOPES: Readonly<Record<string, readonly OAuthScope[]>> = Object.freeze({
  'POST /v1/missions/start': ['passports:write'],
});

/** What a request's route is looked up in: the engine's table, or the registry a deployment has added to. */
export interface RouteScopeLookup {
  get(key: string): OAuthRouteRequirement | undefined;
}

const engineLookup: RouteScopeLookup = { get: (key) => ENGINE_ROUTE_SCOPES[key] };

/** Apply the OAuth scope ceiling after authentication and live revocation checks. */
export function enforceOAuthRouteScope(
  request: FastifyRequest,
  reply: FastifyReply,
  scopes: RouteScopeLookup = engineLookup,
): void {
  // An OAuth principal always hits this ceiling. Scope enforcement is a
  // security boundary, not a rollout switch: accepting an OAuth token while
  // skipping this check turns every token into operator-wide authority.
  if (request.oauthScope === undefined) return;

  const method = request.method === 'HEAD' ? 'GET' : request.method;
  const pattern = request.routeOptions?.url;
  const required = pattern ? scopes.get(`${method} ${pattern}`) : undefined;
  const granted = new Set(request.oauthScope.split(/\s+/).filter(Boolean));
  // A mapped route needs its scope and every scope the all-of table adds; the answer names those the token lacks.
  const needed = required ? [required, ...(ENGINE_ROUTE_ALSO_REQUIRED_SCOPES[`${method} ${pattern}`] ?? [])] : [];
  const missing = needed.filter((scope) => !granted.has(scope));
  if (required && missing.length === 0) return;

  const missingText = missing.join(' ');
  const challenge = required
    ? `Bearer error="insufficient_scope", scope="${missingText}"`
    : 'Bearer error="insufficient_scope"';
  reply.header('WWW-Authenticate', challenge);
  reply.status(403).send({
    error: 'insufficient_scope',
    error_description: required
      ? `This access token does not carry the required ${missingText} scope${missing.length > 1 ? 's' : ''}.`
      : 'This endpoint is not available to OAuth access tokens.',
    ...(required ? { scope: missingText } : {}),
  });
}
