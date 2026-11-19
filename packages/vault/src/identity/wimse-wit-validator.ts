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
 * WIMSE Workload Identity Token (WIT) validator. of the
 * Signed Primitive epic.
 *
 * WIMSE is an IETF working-group draft family describing workload
 * identity across multi-system environments. The WIT itself is a JWT
 * carrying `iss` (issuer URI), `sub` (workload identifier URI), `exp`,
 * standard JWT claims, and an optional `cnf` (confirmation) claim for
 * proof-of-possession. Cryptographic posture mirrors the SPIFFE JWT-
 * SVID validator: the issuer publishes a JWKS at a known URI and the
 * recipient verifies the WIT signature against it.
 *
 * Caching discipline matches SpiffeSvidValidator (Redis SWR + DB
 * last-known-good fail-open). Implementations are intentionally
 * duplicated in v1 of WIMSE — both validators share the same shape but
 * different glue, and the SpiffeSvidValidator just shipped; a
 * DRY refactor into a shared JwksResolver is a follow-up after OIDC
 * lands (chunk E which is the third JWKS consumer).
 *
 * What this validator does NOT do in v1:
 *   - Proof-of-possession (DPoP-like) verification of the WIT's `cnf`
 *     key. The WIT is accepted bearer-style, mirroring the JWT-SVID
 *     posture. The `cnf` claim is RECORDED on the workload_attestation
 *     claim for audit but not verified. Follow-up tracked at the route
 *     boundary.
 *   - X.509-style WIT (out of scope for v1; WIMSE JWT only).
 */

const JWKS_CACHE_KEY_PREFIX = 'wimse:jwks:';
const JWKS_REFRESH_LOCK_PREFIX = 'wimse:jwks-refreshing:';
const STALE_GRACE_SECONDS = 60;
const REFRESH_LOCK_TTL_SECONDS = 30;
const FETCH_TIMEOUT_MS = 5000;
/** The signature algorithms a trusted key may give: asymmetric ones only, so a published key can never be an HMAC secret. */
const ASYMMETRIC_JWS_ALGS: ReadonlySet<string> = new Set([
  'ES256', 'ES384', 'ES512', 'EdDSA', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
]);

interface CachedJwks {
  jwks: { keys: JWK[] };
  fetched_at: number;
}

/**
 * Subset of the wimse_issuers row the validator needs. The repo's
 * full row satisfies this via structural typing.
 */
export interface WimseIssuerConfig {
  id: string;
  issuer_uri: string;
  jwks_uri: string;
  audience: string | null;
  jwks_cache_ttl_seconds: number;
  // Wider than the validator's internal use ({ keys: JWK[] }) so the
  // route layer can pass through the DB row's parsed JSON without a
  // structural narrowing step. The validator re-checks Array.isArray
  // before use; mismatched shapes fall through to the upstream-fetch
  // path.
  jwks_cached_jwks_json: { keys: unknown[] } | null;
}

export interface WimseJwksPersistor {
  persistLastKnownGood(
    issuerId: string,
    jwks: { keys: JWK[] },
    fetchedAt: Date,
  ): Promise<void>;
}

/**
 * Successful WIT validation result. The route layer uses `sub` plus the
 * issuer config's mapping policy to resolve the agent, and `not_after`
 * to cap the minted passport's TTL.
 */
export interface WitValidationResult {
  workload_id: string;        // WIT `sub`
  issuer: string;             // WIT `iss`; matched against config.issuer_uri
  audience?: string;          // WIT `aud` if present
  not_after: number;          // unix seconds from WIT `exp`
  confirmation_jwk?: JWK;     // WIT `cnf` JWK if present (recorded, not verified)
  raw_claims: JWTPayload;
}

export type WimseValidationCode =
  | 'malformed_jwt'
  | 'missing_sub'
  | 'missing_iss'
  | 'issuer_mismatch'
  | 'missing_kid'
  | 'unknown_kid'
  | 'expired'
  | 'audience_mismatch'
  | 'signature_invalid'
  | 'verify_failed'
  | 'jwks_unavailable';

export class WimseValidationError extends Error {
  constructor(public code: WimseValidationCode, message: string) {
    super(message);
    this.name = 'WimseValidationError';
  }
}

export type FetchFn = typeof fetch;
export type WimseUrlGuardFn = typeof assertPublicUrl;

export class WimseWitValidator {
  constructor(
    private redis: Redis,
    private persistor: WimseJwksPersistor,
    private fetcher: FetchFn = publicFetch,
    private urlGuard: WimseUrlGuardFn = assertPublicUrl,
  ) {}

  async validateWit(token: string, config: WimseIssuerConfig): Promise<WitValidationResult> {
    // 1. Decode without verifying — extract iss + sub from the body.
    let claims: JWTPayload;
    try {
      claims = decodeJwt(token);
    } catch {
      throw new WimseValidationError('malformed_jwt', 'WIT is malformed');
    }

    const issClaim = typeof claims.iss === 'string' ? claims.iss : null;
    if (!issClaim) throw new WimseValidationError('missing_iss', 'WIT missing iss claim');
    if (issClaim !== config.issuer_uri) {
      throw new WimseValidationError(
        'issuer_mismatch',
        `WIT iss "${issClaim}" does not match configured issuer_uri "${config.issuer_uri}"`,
      );
    }

    const workloadId = typeof claims.sub === 'string' ? claims.sub : null;
    if (!workloadId) throw new WimseValidationError('missing_sub', 'WIT missing sub claim');

    // 2. Resolve JWKS via Redis cache → background refresh → blocking fetch
    //    → fail-open to DB last-known-good.
    const jwks = await this.getJwks(config);

    // 3. Resolve verification key by kid.
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new WimseValidationError('malformed_jwt', 'WIT header is malformed');
    }
    if (!header.kid) {
      throw new WimseValidationError('missing_kid', 'WIT header missing kid');
    }
    const jwk = jwks.keys.find((k) => k.kid === header.kid);
    if (!jwk) {
      throw new WimseValidationError(
        'unknown_kid',
        `JWKS for issuer "${config.issuer_uri}" has no key matching kid="${header.kid}"`,
      );
    }

    // 4. Cryptographic verify + standard JWT claims.
    const algForJwk = jwk.alg ?? algFromJwk(jwk);
    // The algorithm is the key's, never the token's: a token cannot pick a weaker one, and a key set
    // that gives no usable asymmetric algorithm for a key is refused (spec/workload-identity section 4).
    if (!algForJwk || !ASYMMETRIC_JWS_ALGS.has(algForJwk)) {
      throw new WimseValidationError('verify_failed', 'JWKS key has no supported asymmetric algorithm');
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
      throw new WimseValidationError(code, message);
    }

    // 5. Belt-and-braces exp check (jose already enforces, but assert
    //    the TTL invariant explicitly).
    const exp = typeof verified.payload.exp === 'number' ? verified.payload.exp : 0;
    if (exp <= Math.floor(Date.now() / 1000)) {
      throw new WimseValidationError('expired', 'WIT expired');
    }

    // 6. Extract optional cnf for audit recording.
    let confirmation_jwk: JWK | undefined;
    const cnfRaw = verified.payload['cnf'];
    if (cnfRaw && typeof cnfRaw === 'object' && 'jwk' in cnfRaw) {
      const inner = (cnfRaw as { jwk: unknown }).jwk;
      if (inner && typeof inner === 'object') {
        confirmation_jwk = inner as JWK;
      }
    }

    return {
      workload_id: workloadId,
      issuer: issClaim,
      audience: typeof verified.payload.aud === 'string' ? verified.payload.aud : undefined,
      not_after: exp,
      confirmation_jwk,
      raw_claims: verified.payload,
    };
  }

  // ── JWKS cache (mirrors SpiffeSvidValidator pattern; DRY follow-up) ──

  private async getJwks(config: WimseIssuerConfig): Promise<{ keys: JWK[] }> {
    const cacheKey = JWKS_CACHE_KEY_PREFIX + sha256(config.jwks_uri);
    const ttlMs = config.jwks_cache_ttl_seconds * 1000;
    const staleGraceMs = STALE_GRACE_SECONDS * 1000;
    const now = Date.now();

    const cachedRaw = await this.redis.get(cacheKey);
    if (cachedRaw) {
      try {
        const cached = JSON.parse(cachedRaw) as CachedJwks;
        const ageMs = now - cached.fetched_at;

        if (ageMs <= ttlMs) return cached.jwks;
        if (ageMs <= ttlMs + staleGraceMs) {
          void this.refreshInBackground(config, cacheKey);
          return cached.jwks;
        }
      } catch {
        // Corrupt cache entry — ignore and refetch.
      }
    }

    try {
      return await this.fetchAndCache(config, cacheKey);
    } catch (err) {
      if (config.jwks_cached_jwks_json && Array.isArray(config.jwks_cached_jwks_json.keys)) {
        return config.jwks_cached_jwks_json as { keys: JWK[] };
      }
      throw new WimseValidationError(
        'jwks_unavailable',
        `JWKS fetch failed and no last-known-good available: ${(err as Error).message}`,
      );
    }
  }

  private async refreshInBackground(config: WimseIssuerConfig, cacheKey: string): Promise<void> {
    const lockKey = JWKS_REFRESH_LOCK_PREFIX + sha256(config.jwks_uri);
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
      console.warn('[wimse] background JWKS refresh failed:', safeErrorSummary(err));
    }
  }

  private async fetchAndCache(config: WimseIssuerConfig, cacheKey: string): Promise<{ keys: JWK[] }> {
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
    await this.redis.set(
      cacheKey,
      cacheValue,
      'EX',
      config.jwks_cache_ttl_seconds + STALE_GRACE_SECONDS,
    );

    try {
      await this.persistor.persistLastKnownGood(config.id, jwks, new Date(fetchedAt));
    } catch (err) {
      console.warn('[wimse] last-known-good persist failed:', safeErrorSummary(err));
    }

    return jwks;
  }
}

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

function mapJoseError(err: unknown): WimseValidationCode {
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
