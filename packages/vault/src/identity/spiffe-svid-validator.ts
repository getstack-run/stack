import {
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from 'jose';
import type { Redis } from 'ioredis';
import { assertPublicUrl, publicFetch, sha256 } from '@stack/shared';
import { safeErrorSummary } from '@stack/shared';

/**
 * SPIFFE JWT-SVID validator with stale-while-revalidate JWKS caching.
 *
 * Performance targets (per CTO refinement R1):
 *   - Warm cache: <100ms p95
 *   - Cold cache: <500ms p95 (gated by upstream JWKS fetch latency)
 *
 * Cache discipline (per R3):
 *   - Cache key: spiffe:jwks:<sha256(jwks_uri)>. Hash so URL-unsafe chars
 *     don't leak into Redis keys; URL is the natural cache identity (multiple
 *     operators pointing at the same JWKS endpoint share the cache safely
 *     because per-SVID validation independently re-checks trust_domain match).
 *   - Default TTL 5 minutes, configurable per trust domain.
 *   - Stale grace: serve stale up to 60s past TTL while a single-flight
 *     background refresh runs (Redis SETNX lock). All concurrent callers
 *     during the stale window get the stale value; only one fetches.
 *   - Fail-open: if a blocking refresh hits an upstream outage, serve the
 *     last-known-good JWKS persisted on the trust-domain DB row.
 *     Background-refresh failures do NOT fail open — the existing stale
 *     value keeps serving until grace expires.
 *
 * Defense:
 *   - Trust domain pinned by config: SVID's `sub` SPIFFE-URI trust domain
 *     must match the configured `trust_domain` exactly. A workload from
 *     another trust domain cannot use this config to mint a passport.
 *   - Audience pin (optional): if `config.audience` is set, jose enforces
 *     the JWT-SVID `aud` claim equals it. NULL = accept any (operator
 *     consciously chose not to pin).
 *   - Expiry strict: jose checks `exp`; we additionally double-check.
 *   - kid required: header.kid must be present and resolve to a key in
 *     the JWKS. Untyped or missing kid → reject.
 */

const JWKS_CACHE_KEY_PREFIX = 'spiffe:jwks:';
const JWKS_REFRESH_LOCK_PREFIX = 'spiffe:jwks-refreshing:';
const STALE_GRACE_SECONDS = 60;
const REFRESH_LOCK_TTL_SECONDS = 30;
const FETCH_TIMEOUT_MS = 5000;
/** The signature algorithms a trusted key may give: asymmetric ones only, so a published key can never be an HMAC secret. */
const ASYMMETRIC_JWS_ALGS: ReadonlySet<string> = new Set([
  'ES256', 'ES384', 'ES512', 'EdDSA', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
]);
const SPIFFE_URI_RE = /^spiffe:\/\/([^/]+)(\/.*)?$/;

interface CachedJwks {
  jwks: { keys: JWK[] };
  fetched_at: number;       // unix ms
}

/**
 * Subset of the spiffe_trust_domains row that the validator needs.
 * The repo's full row satisfies this via structural typing.
 */
export interface TrustDomainConfig {
  id: string;
  trust_domain: string;
  jwks_uri: string;
  audience: string | null;
  jwks_cache_ttl_seconds: number;
  jwks_cached_jwks_json: { keys: JWK[] } | null;
}

export interface JwksPersistor {
  /** Persist last-known-good JWKS to DB for fail-open durability. */
  persistLastKnownGood(
    trustDomainId: string,
    jwks: { keys: JWK[] },
    fetchedAt: Date,
  ): Promise<void>;
}

/**
 * The decoded result of a successful validation. The route layer uses
 * `spiffe_id` to find the operator+agent mapping in the trust-domain
 * config and `not_after` to cap the minted passport's TTL.
 */
export interface SvidValidationResult {
  spiffe_id: string;          // e.g. "spiffe://acme.example/ns/payments/sa/orders"
  trust_domain: string;       // matched against config; same as config.trust_domain
  not_after: number;          // unix seconds from JWT `exp`
  issuer: string;             // JWT `iss`; for federated SPIRE this is the issuer's trust domain
  audience?: string;          // JWT `aud` if present
  raw_claims: JWTPayload;
}

export type SpiffeValidationCode =
  | 'malformed_jwt'
  | 'missing_sub'
  | 'invalid_spiffe_id'
  | 'trust_domain_mismatch'
  | 'missing_kid'
  | 'unknown_kid'
  | 'expired'
  | 'audience_mismatch'
  | 'signature_invalid'
  | 'verify_failed'
  | 'jwks_unavailable';

export class SpiffeValidationError extends Error {
  constructor(public code: SpiffeValidationCode, message: string) {
    super(message);
    this.name = 'SpiffeValidationError';
  }
}

/** Injectable fetcher so tests can swap in fixtures without globals. */
export type FetchFn = typeof fetch;
export type SpiffeUrlGuardFn = typeof assertPublicUrl;

export class SpiffeSvidValidator {
  constructor(
    private redis: Redis,
    private persistor: JwksPersistor,
    private fetcher: FetchFn = publicFetch,
    private urlGuard: SpiffeUrlGuardFn = assertPublicUrl,
  ) {}

  async validateJwtSvid(token: string, config: TrustDomainConfig): Promise<SvidValidationResult> {
    // 1. Decode without verifying — extract SPIFFE ID from `sub`. We
    //    haven't verified anything yet; treat all values as untrusted.
    let claims: JWTPayload;
    try {
      claims = decodeJwt(token);
    } catch {
      throw new SpiffeValidationError('malformed_jwt', 'JWT-SVID is malformed');
    }

    const spiffeId = typeof claims.sub === 'string' ? claims.sub : null;
    if (!spiffeId) throw new SpiffeValidationError('missing_sub', 'JWT-SVID missing sub claim');

    const match = SPIFFE_URI_RE.exec(spiffeId);
    if (!match) {
      throw new SpiffeValidationError('invalid_spiffe_id', `Not a SPIFFE URI: ${spiffeId}`);
    }
    const trustDomain = match[1]!;

    if (trustDomain !== config.trust_domain) {
      throw new SpiffeValidationError(
        'trust_domain_mismatch',
        `SVID trust_domain "${trustDomain}" does not match configured "${config.trust_domain}"`,
      );
    }

    // 2. Resolve JWKS — Redis cache → background refresh → blocking fetch
    //    → fail-open to last-known-good
    const jwks = await this.getJwks(config);

    // 3. Resolve verification key by kid. Untyped header or absent kid is
    //    reject — the SPIFFE JWT-SVID spec requires kid for routing across
    //    a multi-key JWKS.
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new SpiffeValidationError('malformed_jwt', 'JWT-SVID header is malformed');
    }
    if (!header.kid) {
      throw new SpiffeValidationError('missing_kid', 'JWT-SVID header missing kid');
    }
    const jwk = jwks.keys.find((k) => k.kid === header.kid);
    if (!jwk) {
      throw new SpiffeValidationError(
        'unknown_kid',
        `JWKS for trust_domain "${config.trust_domain}" has no key matching kid="${header.kid}"`,
      );
    }

    // 4. Cryptographic verify + standard JWT claims (exp, aud if pinned).
    //
    // SPIRE 1.x publishes JWKs without an `alg` field on the JWK
    // (only kty + crv + key material). jose's importJWK requires
    // `alg` either on the JWK or as the second argument. Infer from
    // (kty, crv) to a standard JWS algorithm when the JWK omits it
    // — keeps the validator portable across SPIRE versions and any
    // issuer that follows the SPIFFE Trust Bundle Format spec which
    // does not require alg.
    const algForJwk = jwk.alg ?? algFromJwk(jwk);
    // The algorithm is the key's, never the token's: a token cannot pick a weaker one, and a key set
    // that gives no usable asymmetric algorithm for a key is refused (spec/workload-identity section 4).
    if (!algForJwk || !ASYMMETRIC_JWS_ALGS.has(algForJwk)) {
      throw new SpiffeValidationError('verify_failed', 'JWKS key has no supported asymmetric algorithm');
    }
    let verified;
    try {
      const key = await importJWK(jwk, algForJwk);
      verified = await jwtVerify(token, key, {
        algorithms: [algForJwk],
        ...(config.audience ? { audience: config.audience } : {}),
      });
    } catch (err) {
      const code = mapJoseError(err);
      const message = err instanceof Error ? err.message : 'verify failed';
      throw new SpiffeValidationError(code, message);
    }

    // 5. Belt-and-braces: jose already enforces exp, but assert it as a
    //    documented gate so the cap-TTL invariant is unmistakable.
    const exp = typeof verified.payload.exp === 'number' ? verified.payload.exp : 0;
    if (exp <= Math.floor(Date.now() / 1000)) {
      throw new SpiffeValidationError('expired', 'JWT-SVID expired');
    }

    return {
      spiffe_id: spiffeId,
      trust_domain: trustDomain,
      not_after: exp,
      issuer: typeof verified.payload.iss === 'string' ? verified.payload.iss : '',
      audience: typeof verified.payload.aud === 'string' ? verified.payload.aud : undefined,
      raw_claims: verified.payload,
    };
  }

  // ── JWKS cache ──────────────────────────────────────────────────────

  private async getJwks(config: TrustDomainConfig): Promise<{ keys: JWK[] }> {
    const cacheKey = JWKS_CACHE_KEY_PREFIX + sha256(config.jwks_uri);
    const ttlMs = config.jwks_cache_ttl_seconds * 1000;
    const staleGraceMs = STALE_GRACE_SECONDS * 1000;
    const now = Date.now();

    const cachedRaw = await this.redis.get(cacheKey);
    if (cachedRaw) {
      try {
        const cached = JSON.parse(cachedRaw) as CachedJwks;
        const ageMs = now - cached.fetched_at;

        if (ageMs <= ttlMs) {
          // Fresh — serve cached.
          return cached.jwks;
        }
        if (ageMs <= ttlMs + staleGraceMs) {
          // Stale — serve cached, refresh in background single-flight.
          // Don't await: the caller proceeds with the stale JWKS.
          void this.refreshInBackground(config, cacheKey);
          return cached.jwks;
        }
        // Past grace — fall through to blocking fetch.
      } catch {
        // Corrupt cache entry — ignore and refetch.
      }
    }

    try {
      return await this.fetchAndCache(config, cacheKey);
    } catch (err) {
      // Fail-open: upstream is unreachable AND cache is gone.
      // The DB last-known-good is the durability layer of last resort.
      if (config.jwks_cached_jwks_json && Array.isArray(config.jwks_cached_jwks_json.keys)) {
        return config.jwks_cached_jwks_json;
      }
      throw new SpiffeValidationError(
        'jwks_unavailable',
        `JWKS fetch failed and no last-known-good available: ${(err as Error).message}`,
      );
    }
  }

  private async refreshInBackground(config: TrustDomainConfig, cacheKey: string): Promise<void> {
    const lockKey = JWKS_REFRESH_LOCK_PREFIX + sha256(config.jwks_uri);
    // Single-flight: SETNX with TTL. Only the first concurrent caller
    // through the stale window wins the lock and refreshes; others see
    // their own stale read and proceed.
    const acquired = await this.redis.set(
      lockKey,
      '1',
      'EX',
      REFRESH_LOCK_TTL_SECONDS,
      'NX',
    );
    if (acquired !== 'OK') return;
    try {
      await this.fetchAndCache(config, cacheKey);
    } catch (err) {
      // SWR background-refresh failure is non-fatal: the stale value
      // keeps serving until the grace window expires. Log once.
      console.warn('[spiffe] background JWKS refresh failed:', safeErrorSummary(err));
    }
  }

  private async fetchAndCache(config: TrustDomainConfig, cacheKey: string): Promise<{ keys: JWK[] }> {
    await this.urlGuard(config.jwks_uri, { allowedProtocols: ['https:'] });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let response: Response;
    try {
      response = await this.fetcher(config.jwks_uri, { signal: controller.signal, redirect: 'manual' });
    } finally {
      clearTimeout(timeout);
    }
    if (response.status >= 300 && response.status < 400) throw new Error('JWKS endpoint redirected');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${config.jwks_uri}`);
    }
    const parsed = (await response.json()) as { keys?: JWK[] };
    if (!parsed.keys || !Array.isArray(parsed.keys) || parsed.keys.length === 0) {
      throw new Error('JWKS response missing non-empty `keys` array');
    }
    const jwks: { keys: JWK[] } = { keys: parsed.keys };

    const fetchedAt = Date.now();
    const cacheValue = JSON.stringify({ jwks, fetched_at: fetchedAt } satisfies CachedJwks);
    // Redis TTL = config TTL + grace, so the entry survives long enough
    // for SWR to use it. Past grace, blocking fetch always runs.
    await this.redis.set(
      cacheKey,
      cacheValue,
      'EX',
      config.jwks_cache_ttl_seconds + STALE_GRACE_SECONDS,
    );

    // Persist last-known-good asynchronously of the cache write so the
    // DB row stays current for fail-open during Redis unavailability.
    // Failure is non-fatal — the JWKS still serves from the just-written
    // Redis cache.
    try {
      await this.persistor.persistLastKnownGood(config.id, jwks, new Date(fetchedAt));
    } catch (err) {
      console.warn('[spiffe] last-known-good persist failed:', safeErrorSummary(err));
    }

    return jwks;
  }
}

/**
 * Infer the JWS algorithm a JWK is intended for from its key parameters.
 * Used when the JWK itself omits `alg` (SPIRE 1.x bundle format does
 * exactly this). Returns undefined for unrecognized shapes, which the
 * caller refuses: the token's own header never chooses the algorithm.
 */
function algFromJwk(jwk: JWK): string | undefined {
  if (jwk.kty === 'EC') {
    if (jwk.crv === 'P-256') return 'ES256';
    if (jwk.crv === 'P-384') return 'ES384';
    if (jwk.crv === 'P-521') return 'ES512';
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'RSA') return 'RS256';
  return undefined;
}

function mapJoseError(err: unknown): SpiffeValidationCode {
  if (err && typeof err === 'object' && 'code' in err) {
    const code = (err as { code: string }).code;
    if (code === 'ERR_JWT_EXPIRED') return 'expired';
    if (code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
      const claim = (err as { claim?: string }).claim;
      if (claim === 'aud') return 'audience_mismatch';
    }
    if (code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') return 'signature_invalid';
  }
  return 'verify_failed';
}
