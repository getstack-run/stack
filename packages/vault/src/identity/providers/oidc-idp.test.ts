// Tests for OidcIdpProvider.
//
// 521 lines of security-critical crypto shipped with no test file at all,
// while the constructor carried an injectable OidcFetchFn built expressly
// to make it testable. This uses it.
//
// The ID-token cases are the point: every one of them is a way an
// attacker-or-broken-IdP gets a token accepted that should not be.

import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, type JWK } from 'jose';
import { sha256 } from '@stack/shared';
import { OidcIdpProvider, assertReturnUrlAllowed } from './oidc-idp.js';

// The fake IdP host does not resolve, so the real assertPublicUrl would
// reject it before any test logic ran. Tests inject a parse-only guard and
// assert the guard's BEHAVIOUR separately, below.
const passGuard = (url: string) => {
  new URL(url);
};

const ISSUER = 'https://idp.example.test';
const CLIENT_ID = 'stack-client';
const REDIRECT = 'https://api.getstack.run/v1/identity/oidc/callback';
const DASHBOARD = 'https://getstack.run';

// ── Fakes ───────────────────────────────────────────────────────────

/** Minimal in-memory Redis covering the commands the provider uses. */
function fakeRedis() {
  const store = new Map<string, string>();
  return {
    store,
    async get(k: string) {
      return store.get(k) ?? null;
    },
    async set(k: string, v: string, _ex?: string, _ttl?: number, nx?: string) {
      if (nx === 'NX' && store.has(k)) return null;
      store.set(k, v);
      return 'OK';
    },
    async del(...keys: string[]) {
      let n = 0;
      for (const k of keys) if (store.delete(k)) n += 1;
      return n;
    },
  };
}

const BASE_CONFIG = {
  id: 'oidc_1',
  operator_id: 'op_acme',
  display_name: 'Acme IdP',
  issuer_uri: ISSUER,
  client_id: CLIENT_ID,
  client_secret_encrypted: 'ciphertext',
  audience: null as string | null,
  redirect_uri: REDIRECT,
  scopes_json: ['openid', 'email', 'profile'],
  claim_mapping_policy_json: null as Record<string, unknown> | null,
  discovery_cached_json: null,
  jwks_cached_jwks_json: null,
  jwks_cached_at: null,
  jwks_cache_ttl_seconds: 300,
  allowed_return_origins: null as string[] | null,
  sso_slug: null,
  sso_login_enabled: false,
  default_member_role: 'standard',
  active: true,
};

function fakeConfigRepo(overrides: Partial<typeof BASE_CONFIG> = {}) {
  const config = { ...BASE_CONFIG, ...overrides };
  return {
    config,
    async findActiveByOperator(operatorId: string) {
      return config.operator_id === operatorId && config.active ? config : undefined;
    },
    async findById(id: string) {
      return config.id === id ? config : undefined;
    },
    async persistLastKnownGoodJwks() {
      /* no-op */
    },
  };
}

const fakeKms = {
  async encrypt(plaintext: string) {
    return { ciphertext: `enc:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test' };
  },
  async decrypt(ciphertext: string, context?: Record<string, unknown>) {
    if (context?.['store'] === 'authority_oidc_evidence' && ciphertext.startsWith('enc:')) {
      return Buffer.from(ciphertext.slice(4), 'base64url').toString('utf8');
    }
    return 'super-secret';
  },
};

/** Discovery + JWKS + token endpoint, driven by a per-test token factory. */
function fakeFetcher(opts: {
  jwks: { keys: JWK[] };
  idToken?: () => Promise<string>;
  tokenStatus?: number;
}) {
  return (async (input: unknown) => {
    const url = String(input);
    if (url.endsWith('/.well-known/openid-configuration')) {
      return new Response(
        JSON.stringify({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (url === `${ISSUER}/jwks`) {
      return new Response(JSON.stringify(opts.jwks), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url === `${ISSUER}/token`) {
      if (opts.tokenStatus && opts.tokenStatus !== 200) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: opts.tokenStatus });
      }
      return new Response(
        JSON.stringify({ id_token: await opts.idToken!(), token_type: 'Bearer' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
}

// ── Shared key material ─────────────────────────────────────────────

type SignKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let priv: SignKey;
let jwks: { keys: JWK[] };
const KID = 'idp-key-1';

beforeEach(async () => {
  const pair = await generateKeyPair('RS256');
  priv = pair.privateKey;
  const pubJwk = await exportJWK(pair.publicKey);
  pubJwk.kid = KID;
  pubJwk.alg = 'RS256';
  jwks = { keys: [pubJwk] };
});

async function idToken(claims: Record<string, unknown>, kid = KID, key = priv) {
  return new SignJWT({ email: 'e@acme.test', ...claims })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);
}

/** Run initiate → callback → complete, returning complete()'s result. */
async function runFlow(opts: {
  nonceOverride?: string;
  claims?: Record<string, unknown>;
  kid?: string;
  key?: SignKey;
  issuer?: string;
  audience?: string;
  requestedClaims?: string[];
  configOverrides?: Partial<typeof BASE_CONFIG>;
}) {
  const redis = fakeRedis();
  const repo = fakeConfigRepo(opts.configOverrides);
  let capturedNonce = '';

  const provider = new OidcIdpProvider(
    redis as never,
    repo as never,
    fakeKms as never,
    fakeFetcher({
      jwks,
      idToken: async () =>
        idToken(
          {
            iss: opts.issuer ?? ISSUER,
            aud: opts.audience ?? CLIENT_ID,
            sub: 'idp-user-1',
            nonce: opts.nonceOverride ?? capturedNonce,
            ...(opts.claims ?? {}),
          },
          opts.kid ?? KID,
          opts.key ?? priv,
        ),
    }),
    DASHBOARD,
    passGuard,
  );

  const init = await provider.initiate('op_acme', { requested_claims: opts.requestedClaims ?? ['verified_human'] } as never);
  capturedNonce = new URL(init.verification_url!).searchParams.get('nonce')!;

  await provider.acceptCallback(init.session_ref, 'auth-code-123');
  return { provider, result: await provider.complete('op_acme', init.session_ref), redis, init };
}

// ── initiate ────────────────────────────────────────────────────────

describe('initiate', () => {
  it('builds an authorize URL with PKCE S256 and 256-bit state/nonce', async () => {
    const redis = fakeRedis();
    const provider = new OidcIdpProvider(
      redis as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );

    const init = await provider.initiate('op_acme', {
      requested_claims: ['verified_human'],
    } as never);
    const url = new URL(init.verification_url!);

    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('response_type')).toBe('code');
    // 32 bytes base64url = 43 chars
    expect(url.searchParams.get('state')!.length).toBeGreaterThanOrEqual(43);
    expect(url.searchParams.get('nonce')!.length).toBeGreaterThanOrEqual(43);
    // The verifier must never leave the server.
    expect(init.verification_url).not.toContain('code_verifier');
  });

  it('refuses an operator with no active config', async () => {
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );
    await expect(
      provider.initiate('op_someone_else', { requested_claims: [] } as never),
    ).rejects.toThrow(/No active OIDC/);
  });

  it('refuses an off-allowlist return_url before parking anything', async () => {
    const redis = fakeRedis();
    const provider = new OidcIdpProvider(
      redis as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );

    await expect(
      provider.initiate('op_acme', {
        requested_claims: [],
        return_url: 'https://evil.example/steal',
      } as never),
    ).rejects.toThrow(/allowed return origins/);
    // Nothing parked — the bad value never reached Redis.
    expect(redis.store.size).toBe(0);
  });

  it('accepts a return_url on the operator allowlist', async () => {
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo({ allowed_return_origins: ['https://app.acme.test'] }) as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );
    await expect(
      provider.initiate('op_acme', {
        requested_claims: [],
        return_url: 'https://app.acme.test/done?x=1',
      } as never),
    ).resolves.toBeTruthy();
  });
});

describe('Authority evidence redemption', () => {
  it('caches the verified native token encrypted before consuming OIDC state', async () => {
    const redis = fakeRedis();
    let nonce = '';
    const provider = new OidcIdpProvider(
      redis as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({
        jwks,
        idToken: async () => idToken({
          iss: ISSUER,
          aud: CLIENT_ID,
          sub: 'approver-1',
          nonce,
          roles: ['finance-approver'],
        }),
      }),
      DASHBOARD,
      passGuard,
    );
    const init = await provider.initiate('op_acme', {
      requested_claims: ['verified_identity'],
      return_url: `${DASHBOARD}/authority`,
    } as never);
    nonce = new URL(init.verification_url!).searchParams.get('nonce')!;
    await provider.acceptCallback(init.session_ref, 'authority-code');

    const first = await provider.completeForAuthority('op_acme', init.session_ref);
    expect(first.payload.sub).toBe('approver-1');
    expect(first.signature_algorithm).toBe('RS256');
    expect(first.issuer_key_thumbprint).toHaveLength(43);
    expect(redis.store.has(`oidc:state:${init.session_ref}`)).toBe(false);
    expect(redis.store.get(`oidc:authority-evidence:${init.session_ref}`)).toMatch(/^enc:/);

    const retry = await provider.completeForAuthority('op_acme', init.session_ref);
    expect(retry.id_token).toBe(first.id_token);
    await provider.discardAuthorityEvidence(init.session_ref);
    expect(redis.store.has(`oidc:authority-evidence:${init.session_ref}`)).toBe(false);
  });
});

// ── callback ────────────────────────────────────────────────────────

describe('acceptCallback', () => {
  it('refuses an unknown state', async () => {
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );
    await expect(provider.acceptCallback('never-issued', 'code')).rejects.toThrow(
      /unknown or expired/,
    );
  });

  it('is single-use — a replayed callback cannot overwrite the parked code', async () => {
    const redis = fakeRedis();
    const provider = new OidcIdpProvider(
      redis as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );
    const init = await provider.initiate('op_acme', { requested_claims: [] } as never);

    await expect(provider.acceptCallback(init.session_ref, 'first-code')).resolves.toBeTruthy();
    await expect(provider.acceptCallback(init.session_ref, 'attacker-code')).rejects.toThrow(
      /already been used/,
    );
    // The first code is still the one parked.
    expect(redis.store.get(`oidc:code:${init.session_ref}`)).toBe('first-code');
  });
});

// ── ID-token verification ───────────────────────────────────────────

describe('ID token verification', () => {
  it('accepts a well-formed token and maps claims', async () => {
    const { result } = await runFlow({ claims: { email_verified: true } });
    expect(result.success).toBe(true);
    expect(result.claims.length).toBeGreaterThan(0);
    expect(result.claims[0]!.claim_type).toBe('verified_human');
    expect((result.raw_response as Record<string, unknown>)['sub']).toBe('idp-user-1');
  });

  it('does NOT assert verified_human without email_verified or MFA', async () => {
    // The default policy is the whole value of the humanity claim. An IdP
    // that merely says "someone signed in" has not verified a human, and
    // the claim must not be minted on that basis.
    const { result } = await runFlow({});
    expect(result.success).toBe(true);
    expect(result.claims).toHaveLength(0);
  });

  it('accepts MFA in amr as humanity evidence', async () => {
    const { result } = await runFlow({ claims: { amr: ['pwd', 'mfa'] } });
    expect(result.claims.map((c) => c.claim_type)).toContain('verified_human');
  });

  it('refuses a token signed by a key not in the JWKS (unknown kid)', async () => {
    await expect(runFlow({ kid: 'attacker-kid' })).rejects.toThrow();
  });

  it('refuses a token signed by a DIFFERENT key under a known kid', async () => {
    // Right kid, wrong private key — signature must fail, not just the
    // kid lookup. This is the case a kid-only check would wave through.
    const other = await generateKeyPair('RS256');
    await expect(runFlow({ key: other.privateKey })).rejects.toThrow();
  });

  it('refuses a replayed nonce', async () => {
    await expect(runFlow({ nonceOverride: 'not-the-issued-nonce' })).rejects.toThrow();
  });

  it('refuses a token from the wrong issuer', async () => {
    await expect(runFlow({ issuer: 'https://evil.example' })).rejects.toThrow();
  });

  it('refuses a token minted for a different audience', async () => {
    // Audience defaults to client_id when config.audience is unset. The
    // header comment claims unset means "accept any aud"; the code pins,
    // and pinning is the correct behaviour.
    await expect(runFlow({ audience: 'some-other-client' })).rejects.toThrow();
  });

  it('pins to the configured audience when one is set', async () => {
    await expect(
      runFlow({ audience: CLIENT_ID, configOverrides: { audience: 'explicit-aud' } }),
    ).rejects.toThrow();
    await expect(
      runFlow({ audience: 'explicit-aud', configOverrides: { audience: 'explicit-aud' } }),
    ).resolves.toBeTruthy();
  });

  it('refuses an unsigned alg:none token', async () => {
    const redis = fakeRedis();
    const provider = new OidcIdpProvider(
      redis as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({
        jwks,
        idToken: async () => {
          const header = Buffer.from(JSON.stringify({ alg: 'none', kid: KID })).toString('base64url');
          const body = Buffer.from(
            JSON.stringify({ iss: ISSUER, aud: CLIENT_ID, sub: 'x', email: 'e@acme.test' }),
          ).toString('base64url');
          return `${header}.${body}.`;
        },
      }),
      DASHBOARD,
      passGuard,
    );
    const init = await provider.initiate('op_acme', { requested_claims: [] } as never);
    await provider.acceptCallback(init.session_ref, 'c');
    await expect(provider.complete('op_acme', init.session_ref)).rejects.toThrow();
  });

  it('refuses a token with no expiry or no subject: OpenID Connect Core makes both required, and no expiry means never', async () => {
    for (const [why, build] of [
      ['no expiry', (nonce: string) => new SignJWT({ email: 'e@acme.test', nonce, sub: 'idp-user-1' }).setProtectedHeader({ alg: 'RS256', kid: KID }).setIssuer(ISSUER).setAudience(CLIENT_ID).setIssuedAt().sign(priv)],
      ['no subject', (nonce: string) => new SignJWT({ email: 'e@acme.test', nonce }).setProtectedHeader({ alg: 'RS256', kid: KID }).setIssuer(ISSUER).setAudience(CLIENT_ID).setExpirationTime('5m').sign(priv)],
    ] as const) {
      let nonce = '';
      const provider = new OidcIdpProvider(
        fakeRedis() as never,
        fakeConfigRepo() as never,
        fakeKms as never,
        fakeFetcher({ jwks, idToken: () => build(nonce) }),
        DASHBOARD,
        passGuard,
      );
      const init = await provider.initiate('op_acme', { requested_claims: [] } as never);
      nonce = new URL(init.verification_url!).searchParams.get('nonce')!;
      await provider.acceptCallback(init.session_ref, 'c');
      await expect(provider.complete('op_acme', init.session_ref), why).rejects.toThrow();
    }
  });
});

// ── complete ────────────────────────────────────────────────────────

describe('complete', () => {
  it('refuses to complete for a different operator than initiated', async () => {
    const redis = fakeRedis();
    const provider = new OidcIdpProvider(
      redis as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks, idToken: async () => idToken({ iss: ISSUER, aud: CLIENT_ID, sub: 's' }) }),
      DASHBOARD,
      passGuard,
    );
    const init = await provider.initiate('op_acme', { requested_claims: [] } as never);
    await provider.acceptCallback(init.session_ref, 'code');

    const res = await provider.complete('op_intruder', init.session_ref);
    expect(res.success).toBe(false);
    expect((res.raw_response as Record<string, unknown>)['error']).toBe('operator_mismatch');
  });

  it('reports code_not_received when the callback has not fired', async () => {
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );
    const init = await provider.initiate('op_acme', { requested_claims: [] } as never);
    const res = await provider.complete('op_acme', init.session_ref);
    expect(res.success).toBe(false);
    expect((res.raw_response as Record<string, unknown>)['error']).toBe('code_not_received');
  });

  it('reports state_expired_or_unknown for an unknown session_ref', async () => {
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      passGuard,
    );
    const res = await provider.complete('op_acme', 'nope');
    expect(res.success).toBe(false);
    expect((res.raw_response as Record<string, unknown>)['error']).toBe('state_expired_or_unknown');
  });
});

// ── the guard in isolation ──────────────────────────────────────────

describe('assertReturnUrlAllowed', () => {
  it('allows the dashboard origin when no allowlist is configured', () => {
    expect(() => assertReturnUrlAllowed(`${DASHBOARD}/identity`, null, DASHBOARD)).not.toThrow();
  });

  it('refuses any other origin when no allowlist is configured', () => {
    expect(() => assertReturnUrlAllowed('https://evil.test/x', null, DASHBOARD)).toThrow();
  });

  it('compares origin, so a lookalike path cannot smuggle a host', () => {
    expect(() =>
      assertReturnUrlAllowed(`https://evil.test/${DASHBOARD}`, null, DASHBOARD),
    ).toThrow();
  });

  it('does not treat a malformed configured origin as a wildcard', () => {
    expect(() =>
      assertReturnUrlAllowed('https://evil.test/x', ['not a url'], DASHBOARD),
    ).toThrow();
  });

  it('refuses a non-absolute return_url', () => {
    expect(() => assertReturnUrlAllowed('/relative/path', null, DASHBOARD)).toThrow();
  });

  it('distinguishes ports', () => {
    expect(() =>
      assertReturnUrlAllowed('https://app.acme.test:8443/x', ['https://app.acme.test'], DASHBOARD),
    ).toThrow();
  });
});

// ── the outbound SSRF guard ───────────────────────────────

describe('outbound request guarding', () => {
  it('guards every outbound URL before fetching it', async () => {
    // issuer_uri is operator-supplied; token_endpoint and jwks_uri come
    // from a discovery document whose host the operator chose. All three
    // must be checked, not just the first.
    const seen: string[] = [];
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({
        jwks,
        idToken: async () => idToken({ iss: ISSUER, aud: CLIENT_ID, sub: 's' }),
      }),
      DASHBOARD,
      (url: string) => {
        seen.push(url);
        new URL(url);
      },
    );

    const init = await provider.initiate('op_acme', { requested_claims: [] } as never);
    await provider.acceptCallback(init.session_ref!, 'code');
    // complete() rejects on the nonce (this token deliberately carries
    // none) but only AFTER all three outbound calls have been made, which
    // is what this test is about.
    await provider.complete('op_acme', init.session_ref!).catch(() => undefined);

    expect(seen.some((u) => u.includes('/.well-known/openid-configuration'))).toBe(true);
    expect(seen).toContain(`${ISSUER}/token`);
    expect(seen).toContain(`${ISSUER}/jwks`);
  });

  it('refuses when the guard rejects the destination', async () => {
    // What a private-address issuer looks like from in here: the real
    // assertPublicUrl throws, and nothing may be fetched anyway.
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks }),
      DASHBOARD,
      () => {
        throw new Error('blocked private address');
      },
    );
    await expect(
      provider.initiate('op_acme', { requested_claims: [] } as never),
    ).rejects.toThrow(/blocked private address/);
  });

  it('does not follow redirects — a 302 is a failure, not a hop', async () => {
    // The bypass this closes: a host that passes the guard answers 302 and
    // points at a private address the guard never sees.
    const redirecting = (async () =>
      new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } })) as
      unknown as typeof fetch;

    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      redirecting,
      DASHBOARD,
      passGuard,
    );
    await expect(
      provider.initiate('op_acme', { requested_claims: [] } as never),
    ).rejects.toThrow(/redirected/);
  });
});

// ── Assurance ───────────────────────────────────────────────────────
describe('assurance level of mapped claims', () => {
  const BOTH = ['verified_human', 'verified_identity'];

  it('defaults to the lowest level when the token carries no acr or amr', async () => {
    // An email-and-password login proves nothing stronger than "this IdP
    // vouches for a subject". It must not become a strong identity claim.
    const { result } = await runFlow({ requestedClaims: BOTH, claims: { email_verified: true } });
    expect(result.claims.map((c) => c.claim_type).sort()).toEqual(['verified_human', 'verified_identity']);
    for (const claim of result.claims) expect(claim.assurance_level).toBe('low');
  });

  it('stays low for an acr or amr value the operator has not mapped', async () => {
    const { result } = await runFlow({
      requestedClaims: BOTH,
      claims: { email_verified: true, acr: 'urn:example:mfa', amr: ['pwd', 'mfa'] },
      configOverrides: { claim_mapping_policy_json: { assurance_map: { acr: { 'urn:other': 'high' } } } },
    });
    expect(result.claims).toHaveLength(2);
    for (const claim of result.claims) expect(claim.assurance_level).toBe('low');
  });

  it('uses the level the operator mapped to the token acr', async () => {
    const { result } = await runFlow({
      requestedClaims: BOTH,
      claims: { email_verified: true, acr: 'urn:example:ial2' },
      configOverrides: { claim_mapping_policy_json: { assurance_map: { acr: { 'urn:example:ial2': 'high' } } } },
    });
    expect(result.claims).toHaveLength(2);
    for (const claim of result.claims) expect(claim.assurance_level).toBe('high');
  });

  it('uses the highest level mapped from any amr value', async () => {
    const { result } = await runFlow({
      requestedClaims: BOTH,
      claims: { email_verified: true, amr: ['pwd', 'otp', 'hwk'] },
      configOverrides: {
        claim_mapping_policy_json: { assurance_map: { amr: { otp: 'substantial', hwk: 'high' } } },
      },
    });
    expect(result.claims).toHaveLength(2);
    for (const claim of result.claims) expect(claim.assurance_level).toBe('high');
  });

  it('ignores an assurance_map entry that is not a valid level', async () => {
    const { result } = await runFlow({
      requestedClaims: BOTH,
      claims: { email_verified: true, acr: 'urn:example:ial2' },
      configOverrides: {
        claim_mapping_policy_json: { assurance_map: { acr: { 'urn:example:ial2': 'maximum' } } },
      },
    });
    expect(result.claims).toHaveLength(2);
    for (const claim of result.claims) expect(claim.assurance_level).toBe('low');
  });

  it('keeps the level low when a custom claim policy is set but no assurance_map is', async () => {
    const { result } = await runFlow({
      requestedClaims: BOTH,
      claims: { acr: 'urn:example:ial2' },
      configOverrides: {
        claim_mapping_policy_json: {
          verified_human: { require: [{ claim: 'sub', exists: true }] },
          verified_identity: { require: [{ claim: 'sub', exists: true }] },
        },
      },
    });
    expect(result.claims).toHaveLength(2);
    for (const claim of result.claims) expect(claim.assurance_level).toBe('low');
  });
});

// ── Clock tolerance ─────────────────────────────────────────────────
describe('ID token clock tolerance', () => {
  async function tokenExpiredSecondsAgo(seconds: number, nonce: string) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ email: 'e@acme.test', email_verified: true, sub: 'idp-user-1', nonce })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt(now - 3600)
      .setExpirationTime(now - seconds)
      .sign(priv);
  }

  async function flowWith(seconds: number) {
    let nonce = '';
    const provider = new OidcIdpProvider(
      fakeRedis() as never,
      fakeConfigRepo() as never,
      fakeKms as never,
      fakeFetcher({ jwks, idToken: () => tokenExpiredSecondsAgo(seconds, nonce) }),
      DASHBOARD,
      passGuard,
    );
    const init = await provider.initiate('op_acme', { requested_claims: ['verified_human'] } as never);
    nonce = new URL(init.verification_url!).searchParams.get('nonce')!;
    await provider.acceptCallback(init.session_ref, 'auth-code-123');
    return provider.complete('op_acme', init.session_ref);
  }

  it('accepts a token that expired a few seconds ago (IdP clock skew)', async () => {
    const result = await flowWith(10);
    expect(result.success).toBe(true);
  });

  it('refuses a token that expired well outside the tolerance', async () => {
    await expect(flowWith(120)).rejects.toThrow();
  });
});

// ── JWKS rotation ───────────────────────────────────────────────────
function countingFetcher(inner: typeof fetch, counter: { jwks: number }) {
  return (async (input: unknown, init?: unknown) => {
    if (String(input) === `${ISSUER}/jwks`) counter.jwks += 1;
    return (inner as unknown as (i: unknown, n?: unknown) => Promise<Response>)(input, init);
  }) as unknown as typeof fetch;
}

describe('JWKS refetch on an unknown kid', () => {
  it('refetches once when the token kid is missing from the cached JWKS', async () => {
    const rotated = await generateKeyPair('RS256');
    const rotatedJwk = await exportJWK(rotated.publicKey);
    rotatedJwk.kid = 'idp-key-2';
    rotatedJwk.alg = 'RS256';

    // The cache still holds the pre-rotation key set; the IdP now serves the new key.
    const redis = fakeRedis();
    redis.store.set('oidc:jwks:' + sha256(`${ISSUER}/jwks`), JSON.stringify(jwks));

    const counter = { jwks: 0 };
    let nonce = '';
    const fetcher = countingFetcher(
      fakeFetcher({
        jwks: { keys: [rotatedJwk] },
        idToken: () =>
          idToken(
            { iss: ISSUER, aud: CLIENT_ID, sub: 'idp-user-1', nonce, email_verified: true },
            'idp-key-2',
            rotated.privateKey,
          ),
      }),
      counter,
    );

    const provider = new OidcIdpProvider(redis as never, fakeConfigRepo() as never, fakeKms as never, fetcher, DASHBOARD, passGuard);
    const init = await provider.initiate('op_acme', { requested_claims: ['verified_human'] } as never);
    nonce = new URL(init.verification_url!).searchParams.get('nonce')!;
    await provider.acceptCallback(init.session_ref, 'auth-code-123');
    const result = await provider.complete('op_acme', init.session_ref);

    expect(result.success).toBe(true);
    expect(counter.jwks).toBe(1);
  });

  it('does not keep refetching for a kid the issuer never publishes', async () => {
    const counter = { jwks: 0 };
    const redis = fakeRedis();
    let nonce = '';
    const fetcher = countingFetcher(
      fakeFetcher({
        jwks,
        idToken: () => idToken({ iss: ISSUER, aud: CLIENT_ID, sub: 'idp-user-1', nonce }, 'attacker-kid'),
      }),
      counter,
    );

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const provider = new OidcIdpProvider(redis as never, fakeConfigRepo() as never, fakeKms as never, fetcher, DASHBOARD, passGuard);
      const init = await provider.initiate('op_acme', { requested_claims: ['verified_human'] } as never);
      nonce = new URL(init.verification_url!).searchParams.get('nonce')!;
      await provider.acceptCallback(init.session_ref, 'auth-code-123');
      await expect(provider.complete('op_acme', init.session_ref)).rejects.toThrow();
    }
    // One fetch fills the cache and one forced refetch follows; the cooldown stops the rest.
    expect(counter.jwks).toBe(2);
  });
});
