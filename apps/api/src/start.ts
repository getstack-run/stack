// Sentry init must happen BEFORE any other imports that might throw
// on module load - otherwise their errors aren't captured.
import * as Sentry from '@sentry/node';
import './secret-files.js';
import { ZodError } from 'zod';
import { API_HTTP_OPTIONS } from './lib/http-options.js';
import {
  installSafeConsoleTelemetry,
  registerSafeRouteTemplate,
  safeErrorSummary,
  deployment,
  safeSentryRelease,
  sanitizeSentryEvent,
  type JobReport,
} from '@stack/shared';

installSafeConsoleTelemetry();

/**
 * Classify postgres-js null-socket-write errors. The `postgres` library
 * schedules writes via setImmediate; if the underlying TCP socket is
 * destroyed (DB blip, pgbouncer kill, network hiccup) between scheduling
 * and execution, `socket.write` is null → TypeError thrown out of an
 * async hook with no JS-land try/catch above it. STACK-API-8.
 *
 * The library's connection pool self-heals on the next query, so the
 * customer's request usually already succeeded or will retry. Treat as
 * transient: don't crash the process, don't pollute Sentry.
 */
function isPostgresNullSocketWrite(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { message?: string; stack?: string };
  if (typeof e.message !== 'string') return false;
  if (!/Cannot read prop.*null.*reading.*['"]?write['"]?/i.test(e.message)) return false;
  if (typeof e.stack === 'string' && /node_modules[\\/]postgres[\\/].*connection\.js/.test(e.stack)) return true;
  return false;
}

const sentryDsn = process.env['SENTRY_DSN'];
if (sentryDsn) {
  Sentry.init({
    dsn: sentryDsn,
    environment: process.env['NODE_ENV'] ?? 'development',
    tracesSampleRate: 0,
    sendDefaultPii: false,
    // `stack-api@<40-hex>` from the deploy workflow's validated candidate
    // SHA, or unset. An image reference contains '/', which Sentry rejects.
    release: safeSentryRelease('api', process.env['STACK_RELEASE_SHA']),
    initialScope: { tags: { site: 'api' } },
    beforeSend(event, hint) {
      // Drop 4xx-class noise that doesn't belong in error reporting.
      // - Rate-limit: @fastify/rate-limit throws plain Error('Rate limit exceeded...'),
      //   which is expected client misbehavior, not a server bug.
      // - StackError subclasses with statusCode < 500: handled domain errors.
      // - ZodError (validation): user sent malformed input — error handler maps
      //   to 400 at response time, but Sentry's fastify auto-instrumentation
      //   captures it before our handler translates the status. apps/api and
      //   @stack/shared resolve one zod instance, so instanceof is reliable.
      const err = hint?.originalException;
      const msg = err instanceof Error ? err.message : String(err ?? '');
      if (/^Rate limit exceeded/i.test(msg)) return null;
      const statusCode = (err as { statusCode?: number })?.statusCode;
      if (typeof statusCode === 'number' && statusCode < 500) return null;
      if (err instanceof ZodError) return null;
      // Transient postgres-js null-socket write.
      if (isPostgresNullSocketWrite(err)) return null;
      return sanitizeSentryEvent(event, hint);
    },
  });
}

// Process-level guards for the postgres null-socket pattern. Without
// these, an uncaught TypeError from the library's setImmediate write
// crashes the API machine (the platform restarts it, but it's a brief blip).
// With these, the process keeps running and the postgres pool reconnects
// transparently on the next query.
process.on('uncaughtException', (err) => {
  if (isPostgresNullSocketWrite(err)) {
    console.warn('[api] postgres null-socket write swallowed', safeErrorSummary(err));
    return;
  }
  console.error('Uncaught exception', safeErrorSummary(err));
  // Re-raise: Node's default behavior + the platform's restart handles real bugs.
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  if (isPostgresNullSocketWrite(reason)) {
    console.warn('[api] postgres null-socket write rejection swallowed', safeErrorSummary(reason));
    return;
  }
  console.error('Unhandled rejection', safeErrorSummary(reason));
});

import type { FastifyInstance } from 'fastify';
import { sql } from 'drizzle-orm';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { env } from './config/env.js';
import { apiLoggerOptions } from './config/logger.js';
import { createServices, type Services } from './config/services.js';
import { createErrorHandler } from './middleware/error-handler.js';
import { notFoundHandler } from './middleware/not-found.js';
import { jsonBodyParser } from './middleware/json-body-parser.js';
import { registerMeterRefund } from './middleware/meter.js';
import { registerRequestAnswerObserver } from './lib/request-answer.js';
import { registerMissionActionSettle } from './middleware/mission-action.js';
import { registerControlSettle } from './middleware/control-settle.js';
import { registerApprovalRelease, registerScanAbort } from './middleware/request-cleanup.js';
import { registerOperatorRoutes } from './routes/operators.js';
import { registerCmekRoutes } from './routes/cmek.js';
import { registerAgentRoutes } from './routes/agents.js';
import { registerServiceRoutes } from './routes/services.js';
import { registerPassportRoutes } from './routes/passports.js';
import { registerIntentsRoutes } from './routes/intents.js';
import { registerMissionsRoutes } from './routes/missions.js';
import { registerFleetRoutes } from './routes/fleets.js';
import { registerControlSocketRoutes } from './routes/control-socket.js';
import { registerControlPolicyRoutes } from './routes/control-policies.js';
import { registerFleetWorkloadRoutes } from './routes/fleets-workload.js';
import { registerFleetRuntimeLifecycle } from './lib/agent-runtime.js';
import { registerEvidencePacksRoutes } from './routes/evidence-packs.js';
import { registerOperatorReviewRoutes } from './routes/operator-reviews.js';
import { registerDropoffRoutes } from './routes/dropoffs.js';
import { registerIdentityRoutes } from './routes/identity.js';
import { registerCredentialRoutes } from './routes/credentials.js';
import { registerMemberRoutes, registerMemberAcceptRoutes } from './routes/members.js';
import { registerSsoDomainRoutes } from './routes/sso-domains.js';
import { registerOauthAppRoutes } from './routes/oauth-apps.js';
import { registerAuditRoutes } from './routes/audit.js';
import { registerInboundWebhookRoutes } from './routes/inbound-webhooks.js';
import { registerInboundReceiverRoute } from './routes/inbound.js';
import { registerAccountabilityRoutes } from './routes/accountability.js';
import { registerSecurityEventRoutes } from './routes/security-events.js';
import { registerProxyRoutes } from './routes/proxy.js';
import { registerProxyOperationRoutes } from './routes/proxy-operations.js';
import { registerLlmRoutes } from './routes/llm.js';
import { registerScanRoutes } from './routes/scan.js';
import { registerDetectorConfigRoutes } from './routes/detector-config.js';
import { registerPiiConfigRoutes } from './routes/pii-config.js';
import { registerProviderOAuthRoutes } from './routes/provider-oauth.js';
import { registerOAuthRoutes } from './routes/oauth.js';
import { registerWorkloadRoutes } from './routes/workload.js';
import { registerWorkloadWitRoutes } from './routes/workload-wit.js';
import { registerA2aAgentCardRoute, registerA2aRpcRoute } from './routes/a2a.js';
import { registerAgentJwksRoute } from './routes/agent-jwks.js';
import { registerOperatorJwksRoute } from './routes/operator-jwks.js';
import { createAuthMiddleware } from './middleware/auth.js';
import { globalRateLimitOptions } from './middleware/global-rate-limit.js';
import { registerStagingNoindex } from './middleware/staging-noindex.js';
import { requireOperatorAdmin, requirePartner } from './middleware/require-platform.js';
import { registerPartnerRoutes } from './routes/partner.js';
import { registerOperatorEmailChangePublicRoutes } from './routes/operator-email-change-public.js';
import { registerGovernanceRoutes, registerGovernancePublicRoutes } from './routes/governance.js';
import {
  registerAuthorityProofCallbackRoutes,
  registerAuthorityPublicRoutes,
  registerAuthorityReceiverRoutes,
  registerAuthorityRoutes,
} from './routes/authority.js';
import { startControlEventsRunner } from './config/control-events-runner.js';
import { startSsoDomainRunner } from './config/sso-domain-runner.js';
import { startDecisionEndsRunner } from './config/decision-ends-runner.js';
import { memoiseHealth, type HealthAnswer } from './lib/health-probe.js';
import { startArchiveStoreProbe } from './config/archive-store-probe.js';
import { requireFeatureHook } from './config/licence-service.js';
import { createSiemExporter } from './config/siem-export.js';
import { registerLicenceRoutes } from './routes/licence.js';
import { assertHostedSeams, type ApiExtension } from './extension.js';

/**
 * Starts the API. `ext` is what a deployment adds to the engine: the engine entry
 * (`server.ts`) passes null and serves a self-managed install; STACK's own
 * deployment passes its own extension, which supplies its
 * services, plugins, routes and background work.
 */
export async function startApi<H extends object = object>(ext: ApiExtension<H> | null): Promise<void> {
  const app = Fastify({
    logger: apiLoggerOptions(env.isDev ? 'info' : 'warn'),
    // The platform edge terminates TLS and proxies to us. Without trustProxy,
    // request.ip records the proxy's address, so every token row would show the
    // same IP and a replay after theft would be indistinguishable from a
    // self-race. The edge sets X-Forwarded-For; trusting it is safe because
    // clients cannot reach the app except through that proxy.
    trustProxy: true,
    // A Passport travels in a request header and may be up to PASSPORT_TOKEN_MAX_CHARS long; Node's own 16 KB would
    // refuse a large one before any route saw it.
    http: API_HTTP_OPTIONS,
  });

  // Record every route TEMPLATE as it is registered. Logs and
  // Sentry carry a `route` only when it is one of these, so a raw request
  // path can never pass for a template. Added before any route or plugin so
  // every encapsulated child context inherits it.
  app.addHook('onRoute', (routeOptions) => {
    registerSafeRouteTemplate(routeOptions.url);
  });

  // A staging deployment marks every answer noindex, before anything else can answer.
  registerStagingNoindex(app);

  // CORS — lock to specific origins
  const allowedOrigins = env.ALLOWED_ORIGINS
    ? env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
    : [deployment().siteUrl];
  if (env.isDev) {
    allowedOrigins.push('http://localhost:3100', 'http://localhost:3000');
  }
  await app.register(cors, { origin: allowedOrigins, credentials: true });

  // Security headers
  await app.register(helmet, {
    contentSecurityPolicy: false, // API returns JSON, not HTML
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  });

  // Rate limiting — one bucket per source address, 500 a minute for a bearer and 100 a minute
  // otherwise (`globalRateLimitOptions`). The key is chosen before authentication and never
  // trusts a decoded token claim or a credential-shaped string; authentication verifies the
  // credential later, in the per-route middleware. Buckets:
  //   - a bearer value of bounded length → bearer-ip:<address> (500/min)
  //   - everything else                  → ip:<address> (100/min)
  //
  // The address is the caller's own, `request.ip`, except behind the Console's server: it forwards
  // every customer's calls from its own address, so it signs the end-user address it saw into
  // `x-stack-forwarded-client` with its proxy secret, and a header that verifies (fresh, with a
  // valid MAC) puts the call in that address's bucket instead of the Console server's. Any other
  // header is ignored. A deployment without one (`ext.forwardedClientSecrets` absent) keys
  // every call by its source address.
  //
  // Per-route stricter caps (/v1/passports/issue 20/min etc) inherit the key. The store is
  // in-memory and per machine, so two API machines allow about twice the cap across one
  // address's load-balanced traffic: headroom, not a bug.
  await app.register(rateLimit, globalRateLimitOptions(ext?.forwardedClientSecrets));

  // The hosted call relay's WebSocket plugin goes in before any route.
  if (ext) await ext.plugins(app);

  // Stricter rate limits on auth-sensitive endpoints
  app.after(() => {
    app.addHook('onRoute', (routeOptions) => {
      const path = routeOptions.url;
      const method = Array.isArray(routeOptions.method) ? routeOptions.method : [routeOptions.method];

      // Auth & identity endpoints
      if (
        (path === '/v1/passports/issue' && method.includes('POST')) ||
        (path === '/v1/passports/verify' && method.includes('POST')) ||
        (path === '/v1/passports/revoke-all' && method.includes('POST')) ||
        (path === '/v1/identity/verify/initiate' && method.includes('POST')) ||
        (path.startsWith('/v1/webhooks/') && method.includes('POST'))
      ) {
        routeOptions.config = {
          ...routeOptions.config,
          rateLimit: { max: 20, timeWindow: '1 minute' },
        };
      }
    });
  });

  // Capture raw body alongside parsed JSON. Webhook providers that sign with
  // HMAC over the request bytes (payment and identity providers) verify the exact bytes they
  // sent, so stringify(parsed) won't round-trip. Keep rawBody on the request
  // for handlers that need it.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, jsonBodyParser);


  // OAuth token + device endpoints — RATE-LIMIT EXCLUDED.
  //
  // Same flap pattern as /health: during normal CLI use the operator
  // hits /oauth/token frequently for refresh-token rotation, plus the
  // device_authorize / device/poll cycle during interactive login. On
  // a busy session those alone can blow the 100/min/IP global cap,
  // surfacing as `INTERNAL_ERROR: An unexpected error occurred` in the
  // CLI's auth-login or refresh path. Worse, the rate-limit `Error`
  // hits Fastify's onError before the OAuth error envelope is set, so
  // the response shape doesn't match what the CLI parses.
  //
  // Safe to exempt: each /oauth/token call already does its own
  // expensive crypto/DB work (signature verify, token hash lookup,
  // family-reuse check) so it's self-throttling. /oauth/device/*
  // routes are bound by the device-code TTL (15 min) and re-issued
  // device codes are independent rows; no abuse vector beyond what
  // the platform's proxy already protects against.
  app.after(() => {
    app.addHook('onRoute', (routeOptions) => {
      const path = routeOptions.url;
      if (
        path === '/oauth/token' ||
        path.startsWith('/oauth/device/') ||
        path === '/oauth/revoke'
      ) {
        routeOptions.config = {
          ...routeOptions.config,
          rateLimit: false,
        };
      }
    });
  });

  // Initialize services
  // The server waits for Redis for as long as it takes (a machine that exits is restarted only a few times); every other caller of createServices is a one-shot command and gives up.
  const services = await createServices(ext, { redisAttempts: Infinity });
  // STACK's deployment never serves with an engine seam on its null implementation (that would run unmetered).
  if (ext) assertHostedSeams(services, ext);
  // STACK's own deployment serves its business surfaces (accounts and their
  // pieces, billing, the marketplace, its public pages, staff tools). A
  // self-managed install serves the engine only.

  // Error handler. Pass `services.cmek` in so `CmekRevokedError` bubbling
  // through from any route handler triggers `recordRevoked` — flips the
  // operator's `cmek_status` to `revoked` and publishes the cache
  // invalidation event. Without this the 503 still fires correctly (KMS
  // rethrow + per-machine cache eviction), but every subsequent request
  // continues to hit KMS and fail the same way; status flip stops that.
  app.setErrorHandler(createErrorHandler({ cmek: services.cmek, missions: services.mission }));
  app.setNotFoundHandler(notFoundHandler);

  // What a request leaves open is settled when it ends, including when its
  // client hangs up (Fastify's onResponse does not run then; see
  // middleware/request-end.ts): a denied call, or one STACK could not serve,
  // does not burn allowance; a decision's open lease or approval is told how
  // the action ended; an approval reserved at the gate and not consumed is
  // released for retry; an early-started L3 scan nobody used is cancelled; a
  // fleet admission left open is finished or cancelled.
  registerMeterRefund(app);
  if (ext?.observeRequestEnd) registerRequestAnswerObserver(app, (answer) => ext.observeRequestEnd!(services, answer));
  registerMissionActionSettle(app);
  registerControlSettle(app);
  registerApprovalRelease(app);
  registerScanAbort(app);
  registerFleetRuntimeLifecycle(app);

  await registerEngineRoutes(app, services, ext);
  await listenAndRun(app, services, ext);
}

/**
 * Every route the API serves: the engine's, and the extension's when a deployment adds routes. It runs on
 * the app `startApi` builds and on the one `route-table.ts` builds to list the routes, so the route table
 * the OpenAPI document is generated from is the one the server registers.
 */
export async function registerEngineRoutes<H extends object = object>(
  app: FastifyInstance,
  services: Services & H,
  ext: ApiExtension<H> | null,
): Promise<void> {
  const hosted = ext !== null;

  // Health check.
  //
  // Rate-limit-EXCLUDED. The global rate limit counts per IP across all
  // routes, so an uptime monitor's /health pings sharing an upstream IP with
  // bursty operator traffic would be answered 429 while the API itself is up.
  // Excluding /health is safe: the handler is cheap and an unauthenticated
  // DOS surface here would hit the edge's protection ahead of us.
  // The check is not constant-time: a cheap SELECT 1 with a 2s cap gates the
  // answer, so a machine whose DB pool has died is pulled out of rotation by
  // the platform's health check instead of serving failures (as bogus 401s).
  // If the DB is down globally, every machine reports degraded: requests
  // would fail regardless, and the uptime monitor SHOULD page. Still
  // rate-limit excluded (see block comment above) and still cheap: one
  // SELECT 1 per ping, not per request.
  // Redis is probed beside the database: the auth path reads a revocation or
  // replay flag from it on most requests, so a machine that cannot reach it
  // fails those requests exactly as a database-dead one does. The answer names
  // the dependency (`reason`), never its address or the driver's error.
  // The answer is shared for a second (`memoiseHealth`), so an unauthenticated flood
  // of pings costs one probe a second, not one per request.
  const health = memoiseHealth(
    {
      database: () => services.db.execute(sql`select 1`),
      redis: () => services.redis.ping(),
    },
    {
      onDegraded: (answer) => {
        app.log.error({ failures: answer.failures }, 'health: a dependency is unreachable - reporting degraded');
      },
      ...(ext?.observeHealthProbe ? { onProbe: (answer: HealthAnswer) => ext.observeHealthProbe!(services, answer) } : {}),
    },
  );
  app.get('/health', { config: { rateLimit: false } }, async (_request, reply) => {
    const answer = await health();
    reply.code(answer.statusCode);
    return answer.body;
  });

  // ─── (auth refactor): three-scope encapsulation ────────────
  // Every route is mounted through ONE of these scope blocks. The gate
  // is a property of the path (encapsulation), not a per-route choice
  // a developer can forget. The scopes are listed below.
  //
  //   public         → no auth (health, JWKS, OAuth discovery,
  //                    webhooks, public events, member-accept)
  //   operator       → auth required, no privilege gate (default; the
  //                    bulk of /v1/* routes — currently use per-route
  //                    `preHandler: auth` declarations inside their
  //                    register* fns; equivalent to this block)
  //   operator-admin → auth + requireOperatorAdmin (members admin,
  //                    oauth-apps; one operator's own admin authority)
  //   /v1/admin/*    → auth + requirePlatformStaff (cross-operator
  //                    + STACK staff routes — repo introspection,
  //                    self-tests, Sentry, marketplace approvals)
  const auth = createAuthMiddleware(services);

  // Public scope (no auth at all). The webhook registrar is the only
  // async one — it internally calls app.register() to install a
  // buffer-mode JSON parser scoped to the Stripe-webhook subtree (so
  // signature verification can hash the raw bytes). Dropping its
  // `await` leaks a pending plugin promise into the Fastify queue and
  // hangs `app.listen()`: the app boots through createServices and never
  // reaches listen.
  // public inbound webhook receiver. Mounted in
  // the public no-auth section: slug (URL) + HMAC signature (header,
  // verified against the KMS-decrypted webhook secret) IS the auth.
  // Encapsulated buffer parser preserves raw body for HMAC. See
  // structural test at middleware/require-public-inbound.test.ts.
  await registerInboundReceiverRoute(app, services);
  registerProviderOAuthRoutes(app, services);
  registerOAuthRoutes(app, services); // gated by env.OAUTH_ENABLED inside
  registerMemberAcceptRoutes(app, services);
  // Email transfer, public half. The single-use token is the auth, and
  // cancelling has to work with no session at all - the person stopping a
  // hijack may be the one who cannot log in.
  registerOperatorEmailChangePublicRoutes(app, services);
  // governance approval DECIDE: public scope because its auth
  // is the dashboard cookie session (a Bearer credential must never be
  // able to approve its own elevation).
  registerGovernancePublicRoutes(app, services);
  // Authority approval decisions deliberately use the dashboard cookie,
  // never a Bearer credential, so the watched system cannot approve itself.
  registerAuthorityPublicRoutes(app, services);
  registerAuthorityProofCallbackRoutes(app, services);
  // Receiver protocol requests carry their own compact JWS. The verifier
  // derives receiver + key identity from the signature and exact request,
  // never from a caller-controlled body field.
  registerAuthorityReceiverRoutes(app, services);
  // SPIFFE consumer (P1.7). Mounted in the public-no-auth section by
  // design (R4): the SVID Bearer IS the auth. Operator + agent come
  // from the trust-domain config + SPIFFE-ID-to-agent mapping. The
  // structural test in middleware/require-platform.test.ts asserts
  // /v1/workload/* is the ONLY route in this file and that no auth
  // middleware is wired to it.
  registerWorkloadRoutes(app, services);
  // WIMSE consumer. Same security posture — the WIT
  // bearer IS the auth. Parallel structural test for workload-wit.ts.
  registerWorkloadWitRoutes(app, services);
  // A2A AgentCard. Public, no-auth — discovery URI
  // per the A2A protocol spec.
  registerA2aAgentCardRoute(app, services, { tagline: ext?.agentCardTagline });
  // Agent JWKS. Public, no-auth — per-agent
  // JWKS endpoint exposing the agent's pubkey(s) so external SCITT
  // verifiers can validate COSE_Sign1 claim envelopes signed by an
  // agent's key. Pubkeys are by definition public material; this is
  // the same posture as /v1/.well-known/jwks.json which exposes the
  // operator's key.
  registerAgentJwksRoute(app, services);

  // Operator JWKS. Public, no-auth — per-operator JWKS
  // endpoint exposing the operator's claim-signing pubkey(s). Returns
  // 404 for op_stack_system (data-layer carve-out — no rows in
  // operator_signing_keys for the system operator).
  registerOperatorJwksRoute(app, services);

  // Operator scope (auth required; no privilege gate)
  // Routes inside these registrars carry `preHandler: auth` per-route
  // already; the encapsulation block here is documentary — moving them
  // through a hook-based scope would require touching every route
  // declaration and offers no security benefit (auth-required is the
  // default, not the privileged exception).
  registerOperatorRoutes(app, services);
  // CMEK. Enterprise-tier gate enforced inside the
  // service; route-level gate is operator-admin (members with role=admin
  // can touch CMEK; non-admin members cannot).
  registerCmekRoutes(app, services);
  // operator CRUD for hosted inbound webhooks. Public
  // receiver lives in routes/inbound.ts (registered above in the
  // public-no-auth section).
  registerInboundWebhookRoutes(app, services);
  // governance approvals list (operator scope).
  registerGovernanceRoutes(app, services);
  registerAgentRoutes(app, services);
  registerServiceRoutes(app, services);
  registerPassportRoutes(app, services);
  registerIntentsRoutes(app, services);
  // mission lifecycle REST surface.
  registerMissionsRoutes(app, services);
  registerFleetRoutes(app, services);
  registerControlSocketRoutes(app, services);
  registerControlPolicyRoutes(app, services);
  registerFleetWorkloadRoutes(app, services);
  registerOperatorReviewRoutes(app, services);
  // evidence-pack read surface (list + get-by-id).
  // POST /v1/evidence-packs lands with 5.4.7 alongside SDK + CLI + MCP.
  registerEvidencePacksRoutes(app, services);
  registerDropoffRoutes(app, services);
  // A2A JSON-RPC dispatcher. Auth-protected like the
  // /v1/dropoffs/* routes it wraps.
  registerA2aRpcRoute(app, services);
  registerIdentityRoutes(app, services);
  registerAuthorityRoutes(app, services);
  registerCredentialRoutes(app, services);
  registerAuditRoutes(app, services);
  registerAccountabilityRoutes(app, services);
  registerSecurityEventRoutes(app, services);
  registerProxyRoutes(app, services);
  registerProxyOperationRoutes(app, services);
  registerLlmRoutes(app, services);
  registerScanRoutes(app, services);
  registerDetectorConfigRoutes(app, services);
  registerPiiConfigRoutes(app, services);
  // The install's own licence: what it grants and until when. A self-managed
  // install only; STACK's hosted deployment gates by plan.
  if (!hosted) registerLicenceRoutes(app, services);

  // Operator-admin scope: members admin (invite/list/update/revoke), the
  // verified e-mail domains of single sign-on + oauth-apps. Routes inside these files do NOT declare per-route
  // preHandler — the chain is inherited from the scope.
  await app.register(async (operatorAdmin) => {
    operatorAdmin.addHook('preHandler', auth);
    operatorAdmin.addHook('preHandler', requireOperatorAdmin);
    registerMemberRoutes(operatorAdmin, services);
    registerSsoDomainRoutes(operatorAdmin, services);
    registerOauthAppRoutes(operatorAdmin, services);
  });

  // partner-tenancy scope, /v1/partner/* prefix. Same
  // encapsulation pattern: route file declares paths starting with
  // /v1/partner/ and inherits [auth, requirePartner] from this block.
  // Partner authority is granted at the operator row level via
  // operators.is_partner = true. Non-partners get 403 before the handler runs.
  await app.register(async (partner) => {
    // A self-managed install without the partner feature answers before any
    // other check, so nothing about partners is discoverable without a licence.
    if (!hosted) partner.addHook('onRequest', requireFeatureHook(services.features, 'partners'));
    partner.addHook('preHandler', auth);
    partner.addHook('preHandler', requirePartner);
    registerPartnerRoutes(partner, services);
  });

  // STACK's own business (accounts and their pieces, billing, the marketplace,
  // its public pages, staff tools): its own module, registered
  // by the hosted deployment only.
  if (ext) await ext.routes(app, services, auth);
}

/** Listens, starts the background work and arranges the graceful shutdown. */
async function listenAndRun<H extends object = object>(
  app: FastifyInstance,
  services: Services & H,
  ext: ApiExtension<H> | null,
): Promise<void> {
  const hosted = ext !== null;
  // Start
  // Bind on `::` (IPv6 wildcard, dual-stack-accepts IPv4) instead of
  // `0.0.0.0`, so the API is reachable on IPv6-only private networks as well.
  await app.listen({ port: env.PORT, host: '::' });
  console.log(`STACK API running on port ${env.PORT}`);

  const noop = (): void => {};

  // The deployment's own background work, when it adds any.
  const stopHostedRunners = ext ? ext.runners(services) : async () => {};
  // The control socket's record: each customer's events, delivered signed and in order.
  // Each runner reports how its passes end through the deployment's seam; an install with no deployment records nothing.
  const observeJob = ext?.observeJob ? (report: JobReport): void => ext.observeJob!(services, report) : undefined;
  const stopControlEvents = startControlEventsRunner(services, observeJob);
  // The verified e-mail domains of single sign-on: their DNS records looked up again, lapsed ones released.
  const stopSsoDomains = startSsoDomainRunner(services, observeJob);
  // Pending items whose time ran out (approvals, held actions' reviews, authority requests, unresolved proxied writes)
  // end, and the agent that waited on each is told.
  const stopDecisionEnds = startDecisionEndsRunner(services, observeJob);
  // HeadBucket on the audit object store at boot and every ten minutes, for the admin health view.
  const stopArchiveStoreProbe = startArchiveStoreProbe(
    services,
    ext?.observeArchiveStoreProbe ? (result) => ext.observeArchiveStoreProbe!(services, result) : undefined,
  );
  // A self-managed install's licence, checked again every day.
  const stopLicenceCheck = services.features.startDailyCheck();
  // STACK's live detection rules, for a self-managed install that chose them.
  const stopNetworkRules = services.networkClient.rules?.start() ?? noop;
  // The security-monitoring connector (a licensed feature): events to the customer's collector.
  const stopSiem = hosted
    ? noop
    : (createSiemExporter(process.env, { db: services.db, redis: services.redis, features: services.features })?.start() ?? noop);

  // Graceful shutdown
  const shutdown = async () => {
    console.log('Shutting down...');
    stopControlEvents();
    stopSsoDomains();
    stopDecisionEnds();
    stopArchiveStoreProbe();
    stopLicenceCheck();
    stopNetworkRules();
    stopSiem();
    await app.close();
    await stopHostedRunners();
    // Deferred L3 verdicts (non enforced modes) are recorded after
    // their request was answered. Give them a bounded window so a deploy does
    // not drop them; Redis and the database must still be up for that.
    const undrained = await services.detector.drainBackground(5_000);
    if (undrained > 0) console.error('[detector] deferred layer three verdicts not recorded before shutdown:', undrained);
    services.redis.disconnect();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
