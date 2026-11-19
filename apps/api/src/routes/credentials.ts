import type { FastifyInstance, FastifyReply } from 'fastify';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { z } from 'zod';
import { CREDENTIAL_BURST_WINDOW_SECONDS, CREDENTIAL_BURST_THRESHOLD, ConnectionSelector, ForbiddenError, isServiceInScope } from '@stack/shared';
import { connectionEligibility } from '../lib/agent-runtime.js';
import { scoreScopeDrift } from '../detectors/scope-drift.js';
import { requireOperatorAdmin } from '../middleware/require-platform.js';

/**
 * Raw agent credential boundary (CRITICAL).
 *
 * STACK's core invariant: an agent must NEVER see a raw secret, regardless of
 * its legacy credential_access value. It must go through POST /v1/proxy, which
 * injects the credential at the network boundary without ever handing it back.
 * The older guard lived inside runPassportChecks and only fired when the caller
 * voluntarily sent an X-Passport-Token header — but the SDK's credentials.get()
 * sends no such header, so a proxy_only agent could retrieve the plaintext
 * secret by simply omitting it.
 *
 * This guard is:
 *  - UNCONDITIONAL — runs before any retrieval on every credential-read route,
 *    independent of any header.
 *  - PRINCIPAL-KEYED — checks request.agentId (the authenticated principal set
 *    by the agent-JWT / passport-inbound auth paths), NOT a self-declared token
 *    claim an attacker could shape.
 *  - FAIL-CLOSED — every authenticated agent principal is refused. A plain
 *    operator or member context (no agentId) continues to the owner/admin gate.
 *
 * Exported (not a route closure) so the decision is directly unit-testable —
 * see credentials.test.ts.
 */
export async function assertNotProxyOnlyAgent(
  request: { agentId?: string; operatorId?: string },
): Promise<void> {
  const agentId = request.agentId;
  if (!agentId) return; // operator / member context — not an agent principal
  throw new ForbiddenError(
    'Agents may not retrieve raw credentials. Use POST /v1/proxy, which injects ' +
      'the credential at the network boundary without exposing it.',
  );
}

/**
 * white-label tenants are proxy-only.
 *
 * A tenant's `sk_live_*` key is held by its partner, and it passes
 * requireOperatorAdmin like any operator key. Letting it read decrypted
 * credentials would hand the partner every tenant's provider tokens. Tenants
 * use POST /v1/proxy, which injects the credential without exposing it.
 *
 * FAIL-CLOSED: auth resolves the billing account for every operator context
 * (applyBillingAccount in middleware/auth.ts); if it is missing, refuse.
 */
export async function assertNotTenantCredentialRead(
  request: { billingAccount?: { isTenant: boolean } },
): Promise<void> {
  if (request.billingAccount && !request.billingAccount.isTenant) return;
  throw new ForbiddenError(
    'This account may not retrieve raw credentials. Use POST /v1/proxy, which ' +
      'injects the credential at the network boundary without exposing it.',
  );
}

/** Prevent browsers, intermediaries, and shared caches retaining a reveal. */
export function markCredentialResponseUncacheable(reply: FastifyReply): void {
  reply.header('Cache-Control', 'private, no-store');
  reply.header('Pragma', 'no-cache');
  reply.header('Expires', '0');
}

/** `?connection=` picks one connection of a provider the caller may use several of, by name or id. */
const CredentialReadQuery = z.object({ connection: ConnectionSelector.optional() });

export function registerCredentialRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  /**
   * Shared passport-aware credential checks (Signals 1-3).
   * Reads optional X-Passport-Token header and enforces security signals.
   */
  async function runPassportChecks(
    request: { headers: Record<string, string | string[] | undefined> },
    provider: string,
  ) {
    const passportToken = request.headers['x-passport-token'] as string | undefined;
    if (!passportToken) return undefined;

    const claims = await services.passport.verify(passportToken);
    const jti = claims.jti;
    const agentId = claims.stk.agent_id;
    const operatorId = claims.stk.operator_id;
    const mode = claims.stk.accountability as string | undefined;

    // proxy_only guard — agent must use POST /v1/proxy instead
    if (agentId) {
      const agent = await services.agent.getById(agentId);
      if (agent?.credential_access === 'proxy_only') {
        throw new ForbiddenError(
          'This agent is configured as proxy_only. Use POST /v1/proxy instead of direct credential retrieval.',
        );
      }
    }

    // Signal 2 — credential_after_checkout
    const passportRecord = await services.passport.findByJti(jti);
    if (passportRecord?.checked_out_at) {
      await services.securityEvent.record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'credential_after_checkout',
        severity: 'critical',
        message: `Credential retrieval for ${provider} after passport checkout`,
      });
      throw new ForbiddenError('Passport already checked out');
    }

    // Signal 1 — credential_outside_scope.: the grant is the sole
    // authority; a self-declared intent may only narrow, never widen. (The
    // proxy_only hard-block above already stops proxy_only agents entirely;
    // this stops a `direct` agent from self-authorizing raw retrieval of an
    // ungranted secret via a declared intent.)
    const intentServices = claims.stk.intent_services ?? [];
    const grantedProviders = claims.stk.services.map((s: { service_name: string }) => s.service_name);
    const inScope = isServiceInScope(provider, grantedProviders, intentServices);

    if (!inScope) {
      // Scope narrowing is always enforced — accountability mode only affects severity,
      // not the access decision.
      const severity = mode === 'logged' ? 'warning' : 'critical';
      await services.securityEvent.record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'credential_outside_scope',
        severity,
        message: `Credential retrieval for ${provider} not in passport scope`,
        metadata: { intent_services: intentServices, granted_providers: grantedProviders },
      });
      // denial-path producer. Emit a signed
      // intent_denial alongside the security event so a verifier can
      // walk the chain and see exactly which intent was refused at
      // what shape. Best-effort: claim failures don't break the
      // throw path.
      try {
        await services.claimRegistry.recordIntentDenial({
          operatorId,
          passportJti: jti,
          attemptedIntent: {
            type: 'intent_claim',
            intent_type: 'http_call',
            agent_id: agentId,
            named_intent: `${provider}:credential:retrieve`,
            target: provider,
            action: 'credential_retrieval',
            parameters: { provider },
            estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
            accountability: (mode as 'enforced' | 'logged' | 'standard' | undefined) ?? 'standard',
            reason: null,
            requires: [],
            user_subject: null,
            mission_ref: null,
            submitted_at: Date.now(),
          },
          denialReason: 'scope_mismatch',
          message: `Credential retrieval for ${provider} not in passport scope`,
          metadata: { intent_services: intentServices, granted_providers: grantedProviders },
        });
      } catch (err) {
        console.error('[credentials] intent_denial emission failed for scope_mismatch:', safeErrorSummary(err));
      }
      throw new ForbiddenError(`Service ${provider} not in passport scope`);
    }

    // Signal 3 — credential_burst (rate detection, don't deny)
    const burstKey = `cred_burst:${agentId}:${provider}`;
    const count = await services.redis.incr(burstKey);
    if (count === 1) {
      await services.redis.expire(burstKey, CREDENTIAL_BURST_WINDOW_SECONDS);
    }
    if (count > CREDENTIAL_BURST_THRESHOLD) {
      await services.securityEvent.record({
        operatorId,
        agentId,
        passportJti: jti,
        signalType: 'credential_burst',
        severity: 'critical',
        message: `${count} credential retrievals for ${provider} in ${CREDENTIAL_BURST_WINDOW_SECONDS}s`,
        metadata: { count, provider, window_seconds: CREDENTIAL_BURST_WINDOW_SECONDS },
      });
    }

    // Track credential access for Signal 9 (credential_unreported) at checkout
    await services.redis.sadd(`cred_accessed:${jti}`, provider);
    // Set TTL to 2 hours — passports max out at 1 hour
    await services.redis.expire(`cred_accessed:${jti}`, 7200);

    // Signal: scope_drift — behavioral scoring once service-scope has
    // already passed. For direct retrieval, novelty is per-service (no
    // URL to incorporate).
    await scoreScopeDrift(
      {
        jti,
        operatorId,
        agentId,
        service: provider,
        intentServices,
        grantedProviders,
        noveltyKey: provider,
        accountabilityMode: mode,
      },
      { redis: services.redis, securityEvent: services.securityEvent, passport: services.passport },
    );
    return claims;
  }

  app.get<{ Params: { provider: string } }>(
    '/v1/credentials/:provider',
    { preHandler: [auth, requireOperatorAdmin] },
    async (request, reply) => {
      const start = Date.now();

      // Deny raw retrieval for every agent principal, including legacy
      // `credential_access=direct` agents,
      // BEFORE the header-gated passport checks (which an agent can skip).
      await assertNotProxyOnlyAgent(request);
      await assertNotTenantCredentialRead(request);

      const claims = await runPassportChecks(request, request.params.provider);
      const { connection } = CredentialReadQuery.parse(request.query);

      // One pick among the connections this caller may use (a second connection needs `?connection=`), then the
      // credential of exactly that one.
      const picked = await services.serviceConnection.resolveProxyConnection(
        request.operatorId,
        request.params.provider,
        connectionEligibility(request, request.params.provider, claims),
        connection,
      );
      const result = await services.serviceConnection.retrieveCredentialByConnectionId(
        request.operatorId,
        picked.connection_id,
        request.allowedConnections,
      );

      markCredentialResponseUncacheable(reply);

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'credential.retrieve',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return result;
    },
  );

  app.get<{ Params: { connectionId: string } }>(
    '/v1/credentials/by-connection/:connectionId',
    { preHandler: [auth, requireOperatorAdmin] },
    async (request, reply) => {
      const start = Date.now();

      // Same unconditional agent guard as the main route.
      // This by-connection route previously had NO credential_access check at
      // all (not even the header-gated one), so it was the softer bypass.
      await assertNotProxyOnlyAgent(request);
      await assertNotTenantCredentialRead(request);

      // For connection-based retrieval, we check passport after resolving the provider
      const passportToken = request.headers['x-passport-token'] as string | undefined;
      if (passportToken) {
        // We don't know the provider yet from the connection ID, so run a minimal check
        const claims = await services.passport.verify(passportToken);
        const jti = claims.jti;
        const agentId = claims.stk.agent_id;
        const operatorId = claims.stk.operator_id;

        // Signal 2 — credential_after_checkout
        const passportRecord = await services.passport.findByJti(jti);
        if (passportRecord?.checked_out_at) {
          await services.securityEvent.record({
            operatorId,
            agentId,
            passportJti: jti,
            signalType: 'credential_after_checkout',
            severity: 'critical',
            message: `Credential retrieval by connection ${request.params.connectionId} after passport checkout`,
          });
          throw new ForbiddenError('Passport already checked out');
        }

        // Track access by connection ID (resolved at checkout)
        await services.redis.sadd(`cred_accessed:${jti}`, `conn:${request.params.connectionId}`);
        await services.redis.expire(`cred_accessed:${jti}`, 7200);
      }

      const result = await services.serviceConnection.retrieveCredentialByConnectionId(
        request.operatorId,
        request.params.connectionId,
        request.allowedConnections,
      );

      markCredentialResponseUncacheable(reply);

      await services.audit.write({
        ctx: auditCtx(request),
        layer: 'vault',
        action: 'credential.retrieve',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return result;
    },
  );
}
import { safeErrorSummary } from '@stack/shared';
