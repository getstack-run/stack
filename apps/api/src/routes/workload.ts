import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { decodeJwt } from 'jose';
import {
  MissionRequiredError,
  PASSPORT_DEFAULT_TTL_SECONDS,
  RateLimitedError,
  UnauthorizedError,
  WorkloadAttestationError,
  ids,
} from '@stack/shared';
import { SpiffeValidationError, type AuditContext } from '@stack/vault';
import type { Services } from '../config/services.js';
import { enforceOverage } from '../middleware/meter.js';

/**
 * POST /v1/workload/passport — workload identity passport issuance.
 *
 * The route layer where everything connects. SVID Bearer in →
 * trust-domain lookup → cryptographic validation (P1.3) → SPIFFE-ID-to-
 * agent mapping (P1.5) → passport mint (existing P1) → svid_attestation
 * claim attached via passport-service.attachClaim → audit
 * write that auto-binds the new claim hash into the chain.
 *
 * SECURITY POSTURE — auth via the SVID, not via STACK middleware:
 * the workload presents a JWT-SVID Bearer that proves cryptographically
 * which workload it is. No prior session, no API key. The SVID's
 * SPIFFE ID + the operator's configured SPIFFE-ID-to-agent map decides
 * which operator+agent owns the request.
 *
 * R1 — performance:
 *   - Warm cache: <100ms p95 (Redis JWKS hit + jose verify + 2 DB reads)
 *   - Cold cache: <500ms p95 (gated by upstream JWKS fetch)
 *
 * R2 — rate limits (Redis fixed-window, 1-second buckets):
 *   - 10 req/sec per source IP
 *   - 1000 req/sec per trust_domain
 *   A trust domain's own rate_limit_per_second, when set, adds a third bucket
 *   for that configuration; it can lower the rate, never raise the two above.
 *
 * R4 — mounted OUTSIDE all auth-encapsulation scopes. The structural
 *   test in middleware/require-platform.test.ts asserts /v1/workload/*
 *   is the ONLY route declared in this file and that no auth middleware
 *   is wired to it.
 *
 * R5 — passport TTL ≤ SVID remaining TTL. If remaining < 60s, refuse:
 *   the SVID is too close to expiry to mint a useful passport.
 *
 * ERRORS — failures are thrown and serialised by the central error handler
 *   into the API error envelope. No external spec fixes a body shape here:
 *   the SPIFFE JWT-SVID standard (section 5.2) only says how the token rides
 *   in the Authorization header and defines no HTTP error body, and this is
 *   a STACK passport-mint endpoint, not an RFC 6749 token endpoint, so the
 *   flat `error`/`error_description` shape of RFC 6749 section 5.2 does not
 *   apply. Rate-limit refusals carry the exhausted bucket in `details.scope`.
 */

const WORKLOAD_RATE_IP_PER_SECOND = 10;
const WORKLOAD_RATE_TRUST_DOMAIN_PER_SECOND = 1000;
const SVID_MIN_REMAINING_SECONDS = 60;
const SPIFFE_URI_RE = /^spiffe:\/\/([^/]+)(\/.*)?$/;

/** every workload Passport is issued for exactly one live Mission. */
const WorkloadPassportBody = z.object({
  mission_id: z.string().regex(/^ms_[\w-]+$/),
}).strict();

export function registerWorkloadRoutes(app: FastifyInstance, services: Services) {
  app.post('/v1/workload/passport', async (request, reply) => {
    const start = Date.now();

    // ── 1. Extract Bearer ─────────────────────────────────────────
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('Authorization: Bearer <jwt-svid> header required');
    }
    const token = authHeader.slice(7);

    // the minted Passport is bound to one live Mission the
    // operator opened for this workload. Checked before any work.
    const body = WorkloadPassportBody.safeParse(request.body ?? {});
    if (!body.success) {
      throw new MissionRequiredError();
    }

    // ── 2. R2 — per-IP rate limit (cheap; pre-decode) ─────────────
    const sourceIp = request.ip || 'unknown';
    if (!(await tryConsumeBucket(services, `wl:ip:${sourceIp}`, WORKLOAD_RATE_IP_PER_SECOND))) {
      throw new RateLimitedError(`Per-IP rate limit (${WORKLOAD_RATE_IP_PER_SECOND}/s) exceeded`, { scope: 'ip' });
    }

    // ── 3. Decode (no verify) to extract trust_domain + sub ───────
    let claims;
    try {
      claims = decodeJwt(token);
    } catch {
      throw new WorkloadAttestationError('malformed_jwt', 'JWT-SVID is not parseable');
    }
    const sub = typeof claims.sub === 'string' ? claims.sub : '';
    const match = SPIFFE_URI_RE.exec(sub);
    if (!match) {
      throw new WorkloadAttestationError('invalid_spiffe_id', `Bearer's sub claim is not a SPIFFE URI: ${sub || '(empty)'}`);
    }
    const trustDomain = match[1]!;

    // ── 4. R2 — per-trust-domain rate limit ───────────────────────
    if (!(await tryConsumeBucket(services, `wl:td:${trustDomain}`, WORKLOAD_RATE_TRUST_DOMAIN_PER_SECOND))) {
      throw new RateLimitedError(
        `Per-trust-domain rate limit (${WORKLOAD_RATE_TRUST_DOMAIN_PER_SECOND}/s) exceeded`,
        { scope: 'trust_domain' },
      );
    }

    // ── 5. Resolve trust-domain configs + SPIFFE-ID-to-agent map ──
    const candidateConfigs = await services.spiffeTrustDomainRepo.findActiveByTrustDomain(trustDomain);
    if (candidateConfigs.length === 0) {
      throw new WorkloadAttestationError('not_configured', `No active trust_domain configuration for "${trustDomain}"`);
    }

    let chosenConfig: typeof candidateConfigs[number] | null = null;
    let agentId: string | null = null;
    for (const cfg of candidateConfigs) {
      const policy = cfg.spiffe_id_mapping_policy_json as Record<string, { agent_id: string }>;
      const mapping = policy[sub];
      if (mapping?.agent_id) {
        chosenConfig = cfg;
        agentId = mapping.agent_id;
        break;
      }
    }
    if (!chosenConfig || !agentId) {
      throw new WorkloadAttestationError('not_mapped', `No mapping policy in any active config for spiffe_id "${sub}"`);
    }
    if (chosenConfig.rate_limit_per_second && !(await tryConsumeBucket(services, `wl:cfg:${chosenConfig.id}`, chosenConfig.rate_limit_per_second))) {
      throw new RateLimitedError(`Per-configuration rate limit (${chosenConfig.rate_limit_per_second}/s) exceeded`, { scope: 'configuration' });
    }

    // ── 6. Cryptographic validate via the workload provider ───────
    const provider = services.workloadProviderRegistry.get('spiffe');
    if (!provider) {
      throw new WorkloadAttestationError('provider_unavailable', 'SPIFFE workload provider is not available');
    }
    let acceptResult;
    try {
      acceptResult = await provider.acceptSvid(token, {
        kind: 'spiffe',
        id: chosenConfig.id,
        trust_domain: chosenConfig.trust_domain,
        jwks_uri: chosenConfig.jwks_uri,
        audience: chosenConfig.audience,
        jwks_cache_ttl_seconds: chosenConfig.jwks_cache_ttl_seconds,
        jwks_cached_jwks_json:
          chosenConfig.jwks_cached_jwks_json &&
          typeof chosenConfig.jwks_cached_jwks_json === 'object' &&
          'keys' in chosenConfig.jwks_cached_jwks_json &&
          Array.isArray((chosenConfig.jwks_cached_jwks_json as { keys: unknown }).keys)
            ? (chosenConfig.jwks_cached_jwks_json as { keys: unknown[] })
            : null,
      });
    } catch (err) {
      if (err instanceof SpiffeValidationError) throw new WorkloadAttestationError(err.code, err.message);
      throw err;
    }

    // ── 7. R5 — TTL invariant: passport ≤ SVID remaining; ≥ 60s ──
    const nowSec = Math.floor(Date.now() / 1000);
    const remaining = acceptResult.not_after - nowSec;
    if (remaining < SVID_MIN_REMAINING_SECONDS) {
      throw new WorkloadAttestationError(
        'too_close_to_expiry',
        `SVID expires in ${remaining}s; STACK requires ≥ ${SVID_MIN_REMAINING_SECONDS}s remaining`,
      );
    }
    const ttlSeconds = Math.min(remaining, PASSPORT_DEFAULT_TTL_SECONDS);

    // ── 7b. Meter the mint ────────────────────────────────────────
    // A workload-attested passport is a passport: same recorded action as
    // POST /v1/passports/issue, which this route bypasses by minting through
    // the service directly.
    //
    // Placed after cryptographic validation on purpose — an unverified SVID
    // must never be able to spend somebody's allowance. The operator comes
    // from the trust-domain config rather than an auth middleware, so the
    // plan is read here rather than off the request.
    // The plan is resolved from the operator's billing account inside
    // enforceOverage, which also refuses an inactive account.
    // Every refusal comes before the action is counted and the passport minted: the
    // attestation is checked against its claim schema here, so the claim attached
    // below cannot refuse a passport that already exists.
    services.claimRegistry.assertRegistrable('svid_attestation', acceptResult.attestation_claim);
    let handBack: (() => Promise<void>) | undefined;
    await enforceOverage(services, chosenConfig.operator_id, 'action', undefined, (rollback) => {
      handBack = rollback;
    });

    // ── 8. Mint the passport ──────────────────────────────────────
    // A refusal of the mint itself (the Mission is not live, the agent is not active) hands the action back.
    let signedPassport: Awaited<ReturnType<typeof services.passport.issue>>;
    try {
      signedPassport = await services.passport.issue(chosenConfig.operator_id, {
        agent_id: agentId,
        mission_ids: [body.data.mission_id],
        ttl_seconds: ttlSeconds,
        intent: {
          summary: `Workload-attested via SPIFFE: ${acceptResult.spiffe_id}`,
          services: [],
        },
      });
    } catch (err) {
      await handBack?.().catch(() => {});
      throw err;
    }

    // ── 9. Attach the svid_attestation claim via the COSE_Sign1 envelope
    // path. The legacy JWS-shape path (services.passport.attachClaim) is
    // retained on the service for legacy callers and for rows written before
    // the envelope existed.
    const attached = await services.claimRegistry.registerClaim({
      operatorId: chosenConfig.operator_id,
      passportJti: signedPassport.jti,
      claimType: 'svid_attestation',
      payload: acceptResult.attestation_claim,
    });

    // ── 10. Audit row — chain auto-binds the just-attached claim hash ──
    const ctx: AuditContext = {
      trace_id: request.id ?? ids.session(),
      span_id: ids.session(),
      operator_id: chosenConfig.operator_id,
      agent_id: agentId,
      passport_jti: signedPassport.jti,
    };
    await services.audit.write({
      ctx,
      layer: 'vault',
      action: 'workload.passport.mint',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.code(201).send({
      passport: signedPassport.token,
      jti: signedPassport.jti,
      expires_at: signedPassport.expires_at,
      spiffe_id: acceptResult.spiffe_id,
      trust_domain: acceptResult.trust_domain,
      claim_id: attached.claimId,
      ttl_seconds: ttlSeconds,
    });
  });
}

/**
 * Fixed-window rate limiter. Returns true when the request is within
 * the per-second budget; false when exhausted. Single Redis round-trip
 * (INCR + best-effort EXPIRE on first use). Buckets are 1-second
 * windows so a burst at 23:59:59.999 + 00:00:00.001 gets two budgets,
 * which is a deliberate trade for simplicity over sliding-window.
 */
async function tryConsumeBucket(
  services: Services,
  scope: string,
  perSecond: number,
): Promise<boolean> {
  const sec = Math.floor(Date.now() / 1000);
  const key = `${scope}:${sec}`;
  const count = await services.redis.incr(key);
  if (count === 1) {
    // 2-second TTL so the key disappears after the bucket is no longer
    // referenced; INCR-then-EXPIRE means a brief overhang where the key
    // exists across buckets, but the per-bucket count never bleeds.
    await services.redis.expire(key, 2).catch(() => {});
  }
  return count <= perSecond;
}
