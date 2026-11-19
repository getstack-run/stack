import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import {
  WimseWitValidator,
  type WimseIssuerConfig,
  type WimseJwksPersistor,
  type FetchFn,
  type WimseUrlGuardFn,
} from './wimse-wit-validator.js';
import type { Redis } from 'ioredis';

/**
 * WIMSE WIT validator — threat-model coverage. Mirrors the
 * SpiffeSvidValidator test shape; WIMSE-specific assertions diverge.
 *
 *   T1: malformed JWT → reject
 *   T2: missing `iss` → reject
 *   T3: WIT iss ≠ config issuer_uri → reject (cross-issuer can't
 *       impersonate this config)
 *   T4: missing `sub` → reject
 *   T5: missing kid in header → reject
 *   T6: kid not in JWKS → reject
 *   T7: signature by a key NOT in the JWKS → reject
 *   T8: expired WIT → reject
 *   T9: audience mismatch (when pinned) → reject
 *   T10: audience absent in config → accept any audience
 *   T11: happy path → returns workload_id, issuer, not_after, etc.
 *   T12: WIT carries `cnf` claim → recorded on result, not verified
 */

// ─── Fixtures ──────────────────────────────────────────────────────

const ISSUER_URI = 'https://issuer.example.com/wimse';
const WORKLOAD_ID = 'urn:workload:orders:prod-eu-1';
const AUDIENCE = 'https://api.getstack.run/v1/workload/wit';

let signingKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let publicJwk: JWK;
let foreignKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  signingKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.kid = 'wimse-test-key-1';
  publicJwk.use = 'sig';
  publicJwk.alg = 'EdDSA';

  const foreign = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  foreignKey = foreign.privateKey;
});

interface SignOpts {
  iss?: string;
  sub?: string;
  kid?: string;
  aud?: string;
  exp?: number;
  cnf?: { jwk: JWK };
  signWith?: 'real' | 'foreign';
  includeKidHeader?: boolean;
}

async function signWit(opts: SignOpts = {}): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = opts.exp ?? nowSec + 60;
  const iss = opts.iss ?? ISSUER_URI;
  const sub = opts.sub ?? WORKLOAD_ID;
  const aud = opts.aud ?? AUDIENCE;
  const kid = opts.kid ?? 'wimse-test-key-1';
  const key = opts.signWith === 'foreign' ? foreignKey : signingKey;

  const builder = new SignJWT(opts.cnf ? { cnf: opts.cnf } : {})
    .setProtectedHeader(opts.includeKidHeader === false ? { alg: 'EdDSA' } : { alg: 'EdDSA', kid })
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setIssuedAt(nowSec)
    .setExpirationTime(exp);

  return builder.sign(key);
}

function jwksJson(): { keys: JWK[] } {
  return { keys: [publicJwk] };
}

function makeConfig(overrides: Partial<WimseIssuerConfig> = {}): WimseIssuerConfig {
  return {
    id: 'wim_test',
    issuer_uri: ISSUER_URI,
    jwks_uri: 'https://issuer.example.com/.well-known/jwks.json',
    audience: AUDIENCE,
    jwks_cache_ttl_seconds: 300,
    jwks_cached_jwks_json: null,
    ...overrides,
  };
}

// ─── Mocks ─────────────────────────────────────────────────────────

class StubRedis {
  store = new Map<string, { value: string; expires_at: number | null }>();

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expires_at !== null && entry.expires_at < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ..._args: unknown[]): Promise<string> {
    // Approximate: parse the EX value if present for staleness simulation.
    let expires_at: number | null = null;
    if (_args[0] === 'EX' && typeof _args[1] === 'number') {
      expires_at = Date.now() + (_args[1] as number) * 1000;
    }
    const nxIdx = _args.indexOf('NX');
    if (nxIdx !== -1 && this.store.has(key)) return null as unknown as string;
    this.store.set(key, { value, expires_at });
    return 'OK';
  }
}

class StubPersistor implements WimseJwksPersistor {
  calls: Array<{ issuerId: string; jwks: { keys: JWK[] }; fetchedAt: Date }> = [];
  async persistLastKnownGood(issuerId: string, jwks: { keys: JWK[] }, fetchedAt: Date) {
    this.calls.push({ issuerId, jwks, fetchedAt });
  }
}

function makeJwksFetch(response: { keys: JWK[] }): FetchFn {
  return (async () =>
    new Response(JSON.stringify(response), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as unknown as FetchFn;
}

const passGuard: WimseUrlGuardFn = async (url) => new URL(url);

function makeValidator(): WimseWitValidator {
  return new WimseWitValidator(
    redis as unknown as Redis,
    persistor,
    makeJwksFetch(jwksJson()),
    passGuard,
  );
}

// ─── Tests ─────────────────────────────────────────────────────────

let redis: StubRedis;
let persistor: StubPersistor;

beforeEach(() => {
  redis = new StubRedis();
  persistor = new StubPersistor();
});

describe('WimseWitValidator', () => {
  it('T1: rejects malformed JWT', async () => {
    const v = makeValidator();
    await expect(v.validateWit('not-a-jwt', makeConfig())).rejects.toMatchObject({
      code: 'malformed_jwt',
    });
  });

  it('T2: rejects WIT missing iss', async () => {
    const wit = await new SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA', kid: 'wimse-test-key-1' })
      .setSubject(WORKLOAD_ID)
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(signingKey);
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({ code: 'missing_iss' });
  });

  it('T3: rejects WIT whose iss does not match config issuer_uri', async () => {
    const wit = await signWit({ iss: 'https://other.example.com/wimse' });
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({
      code: 'issuer_mismatch',
    });
  });

  it('T4: rejects WIT missing sub', async () => {
    const wit = await new SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA', kid: 'wimse-test-key-1' })
      .setIssuer(ISSUER_URI)
      .setExpirationTime(Math.floor(Date.now() / 1000) + 60)
      .sign(signingKey);
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({ code: 'missing_sub' });
  });

  it('T5: rejects WIT missing kid in header', async () => {
    const wit = await signWit({ includeKidHeader: false });
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({ code: 'missing_kid' });
  });

  it('T6: rejects WIT whose kid is absent from JWKS', async () => {
    const wit = await signWit({ kid: 'unknown-kid' });
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({ code: 'unknown_kid' });
  });

  it('T7: rejects WIT signed by a foreign key not in the JWKS', async () => {
    const wit = await signWit({ signWith: 'foreign' });
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({
      code: 'signature_invalid',
    });
  });

  it('T8: rejects expired WIT', async () => {
    const wit = await signWit({ exp: Math.floor(Date.now() / 1000) - 1 });
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({ code: 'expired' });
  });

  it('T9: rejects WIT with audience mismatch when audience is pinned', async () => {
    const wit = await signWit({ aud: 'https://wrong-audience.example.com' });
    const v = makeValidator();
    await expect(v.validateWit(wit, makeConfig())).rejects.toMatchObject({
      code: 'audience_mismatch',
    });
  });

  it('T10: accepts any audience when config.audience is null', async () => {
    const wit = await signWit({ aud: 'https://anything.example.com' });
    const v = makeValidator();
    const result = await v.validateWit(wit, makeConfig({ audience: null }));
    expect(result.workload_id).toBe(WORKLOAD_ID);
    expect(result.audience).toBe('https://anything.example.com');
  });

  it('T11: happy path returns workload_id, issuer, not_after', async () => {
    const wit = await signWit();
    const v = makeValidator();
    const result = await v.validateWit(wit, makeConfig());
    expect(result.workload_id).toBe(WORKLOAD_ID);
    expect(result.issuer).toBe(ISSUER_URI);
    expect(result.audience).toBe(AUDIENCE);
    expect(result.not_after).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(result.confirmation_jwk).toBeUndefined();
  });

  it('T12: records cnf claim on result when present', async () => {
    const cnfJwk: JWK = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'fake-public-key-material-for-test-only',
      kid: 'workload-pop-key',
    };
    const wit = await signWit({ cnf: { jwk: cnfJwk } });
    const v = makeValidator();
    const result = await v.validateWit(wit, makeConfig());
    expect(result.confirmation_jwk).toEqual(cnfJwk);
  });
});
