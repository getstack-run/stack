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
import { WimseValidationError, type AuditContext } from '@stack/vault';
import type { Services } from '../config/services.js';
import { enforceOverage } from '../middleware/meter.js';

/**
 * POST /v1/workload/wit — WIMSE Workload Identity Token passport
 * issuance. Part of the Signed Primitive epic.
 *
 * Sibling of /v1/workload/passport (which accepts SPIFFE JWT-SVID
 * bearers). WIMSE generalises the workload-attestation pattern: the
 * workload presents a WIT (a JWT with `iss`, `sub`, optional `cnf`),
 * we validate cryptographically against the configured issuer's JWKS,
 * then mint a passport with an attached workload_attestation claim
 * via the claim registry.
 *
 * SECURITY POSTURE — auth via the WIT, not STACK middleware. The same
 * R4 invariant as workload.ts applies: this route is mounted OUTSIDE
 * all auth-encapsulation scopes. The structural test in
 * middleware/require-platform.test.ts asserts /v1/workload/wit is the
 * ONLY route in this file and no auth middleware is wired to it.
 *
 * ERRORS — failures are thrown and serialised by the central error handler
 * into the API error envelope. No external spec fixes a body shape here:
 * the WIMSE workload-to-workload draft (draft-ietf-wimse-s2s-protocol,
 * section 3.5) suggests 400 for verification failures and only optionally
 * points at RFC 9457 for detail, and this is a STACK passport-mint endpoint,
 * not an RFC 6749 token endpoint, so the flat `error`/`error_description`
 * shape of RFC 6749 section 5.2 does not apply. Rate-limit refusals carry
 * the exhausted bucket in `details.scope`.
 *
 * What is NOT in v1:
 *   - DPoP-like proof-of-possession verification of the WIT `cnf`
 *     key. The WIT is accepted bearer-style, mirroring the SPIFFE
 *     consumer's posture. The `cnf` claim is RECORDED on the
 *     workload_attestation claim for audit purposes but not verified.
 *   - X.509-style WIT (out of scope; WIMSE JWT only in v1).
 */

const WORKLOAD_RATE_IP_PER_SECOND = 10;
const WORKLOAD_RATE_ISSUER_PER_SECOND = 1000;
const WIT_MIN_REMAINING_SECONDS = 60;

/** every workload Passport is issued for exactly one live Mission. */
const WorkloadPassportBody = z.object({
  mission_id: z.string().regex(/^ms_[\w-]+$/),
}).strict();

export function registerWorkloadWitRoutes(app: FastifyInstance, services: Services) {
  app.post('/v1/workload/wit', async (request, reply) => {
    const start = Date.now();

    // ── 1. Extract Bearer ─────────────────────────────────────────
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('Authorization: Bearer <wimse-wit> header required');
    }
    const token = authHeader.slice(7);

    // the minted Passport is bound to one live Mission the
    // operator opened for this workload. Checked before any work.
    const body = WorkloadPassportBody.safeParse(request.body ?? {});
    if (!body.success) {
      throw new MissionRequiredError();
    }

    // ── 2. Per-IP rate limit (cheap; pre-decode) ──────────────────
    const sourceIp = request.ip || 'unknown';
    if (!(await tryConsumeBucket(services, `wit:ip:${sourceIp}`, WORKLOAD_RATE_IP_PER_SECOND))) {
      throw new RateLimitedError(`Per-IP rate limit (${WORKLOAD_RATE_IP_PER_SECOND}/s) exceeded`, { scope: 'ip' });
    }

    // ── 3. Decode (no verify) to extract iss + sub ────────────────
    let claims;
    try {
      claims = decodeJwt(token);
    } catch {
      throw new WorkloadAttestationError('malformed_jwt', 'WIT is not parseable');
    }
    const issClaim = typeof claims.iss === 'string' ? claims.iss : '';
    const subClaim = typeof claims.sub === 'string' ? claims.sub : '';
    if (!issClaim) {
      throw new WorkloadAttestationError('missing_iss', 'WIT missing iss claim');
    }
    if (!subClaim) {
      throw new WorkloadAttestationError('missing_sub', 'WIT missing sub claim');
    }

    // ── 4. Per-issuer rate limit ──────────────────────────────────
    if (!(await tryConsumeBucket(services, `wit:iss:${issClaim}`, WORKLOAD_RATE_ISSUER_PER_SECOND))) {
      throw new RateLimitedError(
        `Per-issuer rate limit (${WORKLOAD_RATE_ISSUER_PER_SECOND}/s) exceeded`,
        { scope: 'issuer' },
      );
    }

    // ── 5. Resolve issuer configs + workload-id mapping ───────────
    const candidateConfigs = await services.wimseIssuerRepo.findActiveByIssuerUri(issClaim);
    if (candidateConfigs.length === 0) {
      throw new WorkloadAttestationError('not_configured', `No active wimse_issuers configuration for "${issClaim}"`);
    }

    let chosenConfig: typeof candidateConfigs[number] | null = null;
    let agentId: string | null = null;
    for (const cfg of candidateConfigs) {
      const policy = cfg.workload_id_mapping_policy_json as Record<string, { agent_id: string }>;
      const mapping = policy[subClaim];
      if (mapping?.agent_id) {
        chosenConfig = cfg;
        agentId = mapping.agent_id;
        break;
      }
    }
    if (!chosenConfig || !agentId) {
      throw new WorkloadAttestationError('not_mapped', `No mapping policy in any active config for workload_id "${subClaim}"`);
    }
    // The issuer's own rate_limit_per_second, when set, can lower the rate above, never raise it.
    if (chosenConfig.rate_limit_per_second && !(await tryConsumeBucket(services, `wit:cfg:${chosenConfig.id}`, chosenConfig.rate_limit_per_second))) {
      throw new RateLimitedError(`Per-configuration rate limit (${chosenConfig.rate_limit_per_second}/s) exceeded`, { scope: 'configuration' });
    }

    // ── 6. Cryptographic validate via the WIMSE provider ──────────
    let acceptResult;
    try {
      acceptResult = await services.wimseWorkloadProvider.acceptWit(token, {
        id: chosenConfig.id,
        issuer_uri: chosenConfig.issuer_uri,
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
      if (err instanceof WimseValidationError) throw new WorkloadAttestationError(err.code, err.message);
      throw err;
    }

    // ── 7. TTL invariant: passport ≤ WIT remaining; ≥ 60s ─────────
    const nowSec = Math.floor(Date.now() / 1000);
    const remaining = acceptResult.not_after - nowSec;
    if (remaining < WIT_MIN_REMAINING_SECONDS) {
      throw new WorkloadAttestationError(
        'too_close_to_expiry',
        `WIT expires in ${remaining}s; STACK requires ≥ ${WIT_MIN_REMAINING_SECONDS}s remaining`,
      );
    }
    const ttlSeconds = Math.min(remaining, PASSPORT_DEFAULT_TTL_SECONDS);

    // ── 7b. Meter the mint ────────────────────────────────────────
    // Same reasoning as the SPIFFE consumer: a workload-attested passport
    // is a passport, and this route mints through the service directly
    // rather than through POST /v1/passports/issue. Metered after
    // cryptographic validation so an unverified WIT cannot spend an
    // operator's allowance; the plan is read from the issuer config's operator
    // because there is no auth middleware on this path.
    // The plan is resolved from the operator's billing account inside
    // enforceOverage, which also refuses an inactive account.
    // Every refusal comes before the action is counted and the passport minted: the
    // attestation is checked against its claim schema here, so the claim attached
    // below cannot refuse a passport that already exists.
    services.claimRegistry.assertRegistrable('workload_attestation', acceptResult.attestation_claim);
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
          summary: `Workload-attested via WIMSE: ${acceptResult.workload_id}`,
          services: [],
        },
      });
    } catch (err) {
      await handBack?.().catch(() => {});
      throw err;
    }

    // ── 9. Attach the workload_attestation claim via the COSE_Sign1
    // envelope path. Same registry the SPIFFE consumer writes to,
    // different claim type. Cascade-revoke + tamper-binding fall out
    // automatically from the architecture.
    const attached = await services.claimRegistry.registerClaim({
      operatorId: chosenConfig.operator_id,
      passportJti: signedPassport.jti,
      claimType: 'workload_attestation',
      payload: acceptResult.attestation_claim,
    });

    // ── 10. Audit row — chain auto-binds the attached claim hash ──
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
      action: 'workload.wit.mint',
      outcome: 'success',
      duration_ms: Date.now() - start,
    });

    return reply.code(201).send({
      passport: signedPassport.token,
      jti: signedPassport.jti,
      expires_at: signedPassport.expires_at,
      workload_id: acceptResult.workload_id,
      issuer: acceptResult.issuer,
      claim_id: attached.claimId,
      ttl_seconds: ttlSeconds,
    });
  });
}

/**
 * Fixed-window rate limiter. Same shape as the SPIFFE consumer's; one-
 * second buckets, INCR + EXPIRE on first use. Sliding-window is a
 * follow-up if buckets become a real abuse vector.
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
    await services.redis.expire(key, 2).catch(() => {});
  }
  return count <= perSecond;
}
