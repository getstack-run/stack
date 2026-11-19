import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import {
  SpiffeSvidValidator,
  type TrustDomainConfig,
  type JwksPersistor,
  type FetchFn,
  type SpiffeUrlGuardFn,
} from './spiffe-svid-validator.js';
import type { Redis } from 'ioredis';

/**
 * SPIFFE JWT-SVID validator — threat-model coverage.
 *
 * Every test below maps to a threat:
 *   T1: malformed JWT → reject (not a JWT)
 *   T2: missing `sub` → reject
 *   T3: invalid SPIFFE URI in sub → reject
 *   T4: SVID's trust_domain ≠ config's trust_domain → reject
 *       (cross-trust-domain SVID cannot impersonate this config)
 *   T5: missing kid in header → reject
 *   T6: kid not in JWKS → reject
 *   T7: signature signed by a key NOT in the JWKS → reject
 *   T8: expired JWT → reject
 *   T9: audience mismatch (when pinned) → reject
 *   T10: audience absent in config → accept any audience
 *   T11: happy path → returns spiffe_id, trust_domain, not_after, etc.
 *
 *   Cache:
 *   C1: cold cache → fetch + cache + persist last-known-good
 *   C2: warm cache (fresh) → no fetch
 *   C3: stale cache (within grace) → serve stale + single-flight refresh
 *   C4: stale cache past grace → blocking fetch
 *   C5: blocking fetch fails + no last-known-good → throw jwks_unavailable
 *   C6: blocking fetch fails + last-known-good present → fail-open
 *   C7: SWR refresh single-flight: 2 concurrent stale reads → 1 fetch
 *   C8: corrupt cache value → ignore + refetch
 */

// ─── Test fixtures ─────────────────────────────────────────────────

const TRUST_DOMAIN = 'test.example';
const SPIFFE_ID = `spiffe://${TRUST_DOMAIN}/workload/orders`;
const AUDIENCE = 'https://api.getstack.run/v1/workload/passport';

let signingKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let publicJwk: JWK;
let foreignKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  signingKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.kid = 'test-key-1';
  publicJwk.use = 'sig';
  publicJwk.alg = 'EdDSA';

  // Foreign key — used to forge an SVID that the configured JWKS will
  // reject (T7).
  const foreign = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  foreignKey = foreign.privateKey;
});

interface SignOpts {
  sub?: string;
  kid?: string;
  aud?: string;
  iss?: string;
  exp?: number;          // unix seconds
  signWith?: 'real' | 'foreign';
}

async function signSvid(opts: SignOpts = {}): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = opts.exp ?? nowSec + 60;
  const sub = opts.sub ?? SPIFFE_ID;
  const iss = opts.iss ?? `https://spire.${TRUST_DOMAIN}`;
  const aud = opts.aud ?? AUDIENCE;
  const kid = opts.kid ?? 'test-key-1';
  const key = opts.signWith === 'foreign' ? foreignKey : signingKey;

  return new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(nowSec)
    .setExpirationTime(exp)
    .sign(key);
}

function jwksJson(): { keys: JWK[] } {
  return { keys: [publicJwk] };
}

function makeConfig(overrides: Partial<TrustDomainConfig> = {}): TrustDomainConfig {
  return {
    id: 'std_test',
    trust_domain: TRUST_DOMAIN,
    jwks_uri: 'https://spire.test.example/jwks.json',
    audience: AUDIENCE,
    jwks_cache_ttl_seconds: 300,
    jwks_cached_jwks_json: null,
    ...overrides,
  };
}

// ─── Mocks ─────────────────────────────────────────────────────────

class StubRedis {
  store = new Map<string, { value: string; expires_at: number | null }>();
  setNx_calls = 0;
  setNx_acquired = 0;

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expires_at !== null && entry.expires_at < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ...rest: unknown[]): Promise<'OK' | null> {
    let ttlSeconds: number | null = null;
    let nx = false;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === 'EX' && typeof rest[i + 1] === 'number') {
        ttlSeconds = rest[i + 1] as number;
        i++;
      } else if (rest[i] === 'NX') {
        nx = true;
      }
    }
    if (nx) {
      this.setNx_calls++;
      const existing = this.store.get(key);
      if (existing && (existing.expires_at === null || existing.expires_at >= Date.now())) {
        return null; // not acquired
      }
      this.setNx_acquired++;
    }
    this.store.set(key, {
      value,
      expires_at: ttlSeconds === null ? null : Date.now() + ttlSeconds * 1000,
    });
    return 'OK';
  }
}

class StubPersistor implements JwksPersistor {
  calls: { id: string; jwks: { keys: JWK[] }; fetchedAt: Date }[] = [];
  async persistLastKnownGood(id: string, jwks: { keys: JWK[] }, fetchedAt: Date): Promise<void> {
    this.calls.push({ id, jwks, fetchedAt });
  }
}

class CountingFetcher {
  call_count = 0;
  inflight_concurrent = 0;
  max_inflight = 0;
  last_url: string | null = null;
  fail_with: Error | null = null;
  delay_ms = 0;

  fetcher: FetchFn = async (input) => {
    this.call_count++;
    this.inflight_concurrent++;
    this.max_inflight = Math.max(this.max_inflight, this.inflight_concurrent);
    const url = typeof input === 'string' ? input : (input instanceof URL ? input.toString() : (input as Request).url);
    this.last_url = url;
    try {
      if (this.delay_ms > 0) await new Promise((r) => setTimeout(r, this.delay_ms));
      if (this.fail_with) throw this.fail_with;
      return new Response(JSON.stringify(jwksJson()), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    } finally {
      this.inflight_concurrent--;
    }
  };
}

function makeValidator() {
  const redis = new StubRedis();
  const persistor = new StubPersistor();
  const fetcher = new CountingFetcher();
  const urlGuard: SpiffeUrlGuardFn = async (url) => new URL(url);
  const validator = new SpiffeSvidValidator(
    redis as unknown as Redis,
    persistor,
    fetcher.fetcher,
    urlGuard,
  );
  return { redis, persistor, fetcher, validator };
}

// ─── Threat-model tests ────────────────────────────────────────────

describe('SpiffeSvidValidator — threat model', () => {
  let env: ReturnType<typeof makeValidator>;
  beforeEach(() => {
    env = makeValidator();
  });

  it('T1: malformed JWT → reject', async () => {
    await expect(env.validator.validateJwtSvid('not-a-jwt', makeConfig()))
      .rejects.toMatchObject({ code: 'malformed_jwt' });
  });

  it('T2: missing sub → reject', async () => {
    // jose forces sub when setSubject is called; build a custom JWT
    // with no sub.
    const nowSec = Math.floor(Date.now() / 1000);
    const noSub = await new SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-key-1' })
      .setIssuer(`https://spire.${TRUST_DOMAIN}`)
      .setAudience(AUDIENCE)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + 60)
      .sign(signingKey);
    await expect(env.validator.validateJwtSvid(noSub, makeConfig()))
      .rejects.toMatchObject({ code: 'missing_sub' });
  });

  it('T3: invalid SPIFFE URI in sub → reject', async () => {
    const bad = await signSvid({ sub: 'http://not-spiffe.example/' });
    await expect(env.validator.validateJwtSvid(bad, makeConfig()))
      .rejects.toMatchObject({ code: 'invalid_spiffe_id' });
  });

  it('T4: cross-trust-domain SVID cannot use this config', async () => {
    const otherTd = await signSvid({ sub: 'spiffe://other.example/workload/foo' });
    await expect(env.validator.validateJwtSvid(otherTd, makeConfig()))
      .rejects.toMatchObject({ code: 'trust_domain_mismatch' });
  });

  it('T5: missing kid in header → reject', async () => {
    // jose accepts undefined kid via setProtectedHeader with no kid prop.
    const nowSec = Math.floor(Date.now() / 1000);
    const noKid = await new SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer(`https://spire.${TRUST_DOMAIN}`)
      .setSubject(SPIFFE_ID)
      .setAudience(AUDIENCE)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + 60)
      .sign(signingKey);
    // Pre-seed the cache so we get past the JWKS fetch.
    env.fetcher.fetcher = async () =>
      new Response(JSON.stringify(jwksJson()), { status: 200 });
    await expect(env.validator.validateJwtSvid(noKid, makeConfig()))
      .rejects.toMatchObject({ code: 'missing_kid' });
  });

  it('T6: kid not in JWKS → reject', async () => {
    const wrongKid = await signSvid({ kid: 'no-such-kid' });
    await expect(env.validator.validateJwtSvid(wrongKid, makeConfig()))
      .rejects.toMatchObject({ code: 'unknown_kid' });
  });

  it('T7: SVID signed by a foreign key → signature_invalid', async () => {
    const forged = await signSvid({ signWith: 'foreign' });
    await expect(env.validator.validateJwtSvid(forged, makeConfig()))
      .rejects.toMatchObject({ code: 'signature_invalid' });
  });

  it('T8: expired JWT → reject', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const expired = await signSvid({ exp: nowSec - 10 });
    await expect(env.validator.validateJwtSvid(expired, makeConfig()))
      .rejects.toMatchObject({ code: 'expired' });
  });

  it('T9: audience mismatch when pinned → reject', async () => {
    const wrongAud = await signSvid({ aud: 'https://attacker.example/' });
    await expect(env.validator.validateJwtSvid(wrongAud, makeConfig()))
      .rejects.toMatchObject({ code: 'audience_mismatch' });
  });

  it('T10: config audience NULL → accept any audience', async () => {
    const anyAud = await signSvid({ aud: 'https://different-audience.example/' });
    const result = await env.validator.validateJwtSvid(
      anyAud,
      makeConfig({ audience: null }),
    );
    expect(result.spiffe_id).toBe(SPIFFE_ID);
    expect(result.audience).toBe('https://different-audience.example/');
  });

  it('T11: happy path → returns full result', async () => {
    const svid = await signSvid();
    const result = await env.validator.validateJwtSvid(svid, makeConfig());
    expect(result.spiffe_id).toBe(SPIFFE_ID);
    expect(result.trust_domain).toBe(TRUST_DOMAIN);
    expect(result.audience).toBe(AUDIENCE);
    expect(result.not_after).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(result.issuer).toBe(`https://spire.${TRUST_DOMAIN}`);
  });
});

describe('SpiffeSvidValidator — JWKS cache', () => {
  let env: ReturnType<typeof makeValidator>;
  beforeEach(() => {
    env = makeValidator();
  });

  it('C1: cold cache → fetch + cache + persist last-known-good', async () => {
    const svid = await signSvid();
    expect(env.fetcher.call_count).toBe(0);
    await env.validator.validateJwtSvid(svid, makeConfig());
    expect(env.fetcher.call_count).toBe(1);
    expect(env.persistor.calls).toHaveLength(1);
    expect(env.persistor.calls[0]?.id).toBe('std_test');
  });

  it('C2: warm fresh cache → no fetch on second call', async () => {
    const svid1 = await signSvid();
    const svid2 = await signSvid();
    await env.validator.validateJwtSvid(svid1, makeConfig());
    await env.validator.validateJwtSvid(svid2, makeConfig());
    expect(env.fetcher.call_count).toBe(1);
  });

  it('C3: stale-but-within-grace → serve stale + single-flight refresh', async () => {
    const svid = await signSvid();
    // Prime cache with stale entry by directly seeding redis with an
    // old fetched_at.
    const cacheKey = [...env.redis.store.keys()].find((k) => k.startsWith('spiffe:jwks:'));
    // First call to seed cache
    await env.validator.validateJwtSvid(svid, makeConfig());
    expect(env.fetcher.call_count).toBe(1);
    // Backdate the fetched_at to make it stale (300s TTL + within grace
    // means age in (300s, 360s] is the stale-grace window). Set age to 320s.
    const realCacheKey = [...env.redis.store.keys()].find((k) => k.startsWith('spiffe:jwks:'))!;
    void cacheKey;
    const entry = env.redis.store.get(realCacheKey)!;
    const parsed = JSON.parse(entry.value) as { jwks: unknown; fetched_at: number };
    parsed.fetched_at = Date.now() - 320 * 1000;
    entry.value = JSON.stringify(parsed);

    // Second call — within stale-grace window → serves stale, schedules
    // a background refresh.
    const result = await env.validator.validateJwtSvid(svid, makeConfig());
    expect(result.spiffe_id).toBe(SPIFFE_ID);
    // Background refresh runs as a fire-and-forget; give it a tick.
    await new Promise((r) => setTimeout(r, 20));
    expect(env.fetcher.call_count).toBe(2); // background refresh fired
  });

  it('C4: stale past grace → blocking fetch', async () => {
    const svid = await signSvid();
    await env.validator.validateJwtSvid(svid, makeConfig());
    expect(env.fetcher.call_count).toBe(1);
    // Backdate to past grace (TTL 300s + grace 60s = 360s; set 400s old).
    const cacheKey = [...env.redis.store.keys()].find((k) => k.startsWith('spiffe:jwks:'))!;
    const entry = env.redis.store.get(cacheKey)!;
    const parsed = JSON.parse(entry.value) as { jwks: unknown; fetched_at: number };
    parsed.fetched_at = Date.now() - 400 * 1000;
    entry.value = JSON.stringify(parsed);

    await env.validator.validateJwtSvid(svid, makeConfig());
    expect(env.fetcher.call_count).toBe(2); // blocking fetch on this call
  });

  it('C5: upstream fail + no last-known-good → jwks_unavailable', async () => {
    env.fetcher.fail_with = new Error('connection refused');
    const svid = await signSvid();
    await expect(env.validator.validateJwtSvid(svid, makeConfig({ jwks_cached_jwks_json: null })))
      .rejects.toMatchObject({ code: 'jwks_unavailable' });
  });

  it('C6: upstream fail + last-known-good present → fail-open', async () => {
    env.fetcher.fail_with = new Error('connection refused');
    const svid = await signSvid();
    const result = await env.validator.validateJwtSvid(
      svid,
      makeConfig({ jwks_cached_jwks_json: jwksJson() }),
    );
    expect(result.spiffe_id).toBe(SPIFFE_ID);
  });

  it('C7: SWR single-flight — 2 concurrent stale reads → 1 background fetch', async () => {
    const svid = await signSvid();
    await env.validator.validateJwtSvid(svid, makeConfig());
    expect(env.fetcher.call_count).toBe(1);

    // Stale window
    const cacheKey = [...env.redis.store.keys()].find((k) => k.startsWith('spiffe:jwks:'))!;
    const entry = env.redis.store.get(cacheKey)!;
    const parsed = JSON.parse(entry.value) as { jwks: unknown; fetched_at: number };
    parsed.fetched_at = Date.now() - 320 * 1000;
    entry.value = JSON.stringify(parsed);

    // Two concurrent calls during stale window — only one should win
    // the SETNX lock and refresh.
    env.fetcher.delay_ms = 30;
    await Promise.all([
      env.validator.validateJwtSvid(svid, makeConfig()),
      env.validator.validateJwtSvid(svid, makeConfig()),
    ]);
    // Wait for background refreshes to settle
    await new Promise((r) => setTimeout(r, 80));
    // Initial fetch (1) + at most one background refresh (1) = 2
    expect(env.fetcher.call_count).toBeLessThanOrEqual(2);
    // SETNX lock acquired by exactly one caller
    expect(env.redis.setNx_acquired).toBe(1);
  });

  it('C8: corrupt cache entry → ignore + refetch', async () => {
    const svid = await signSvid();
    // Pre-seed redis with garbage at the cache key.
    const cacheKey = `spiffe:jwks:${(await import('node:crypto')).createHash('sha256').update('https://spire.test.example/jwks.json').digest('hex')}`;
    await env.redis.set(cacheKey, 'not-json{[', 'EX', 300);
    await env.validator.validateJwtSvid(svid, makeConfig());
    expect(env.fetcher.call_count).toBe(1); // re-fetched past corruption
  });
});
