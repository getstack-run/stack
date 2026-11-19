// What an SSO sign-in reads of an ID token about the address (spec/sso-login/SPEC.md sections 8 and 9.5):
// whether the provider said `email_verified` at all, and whether the issuer vouches for the address's domain
// in its own documented claim (Microsoft Entra's `xms_edov`).

import { beforeEach, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { OidcIdpProvider } from './oidc-idp.js';

const CLIENT_ID = 'stack-client';
const REDIRECT = 'https://api.example.test/v1/identity/oidc/callback';
const DASHBOARD = 'https://dashboard.example.test';
const TENANT = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
const ENTRA = `https://login.microsoftonline.com/${TENANT}/v2.0`;
const KID = 'key-1';

const passGuard = (url: string) => {
  new URL(url);
};

function fakeRedis() {
  const store = new Map<string, string>();
  return {
    async get(k: string) {
      return store.get(k) ?? null;
    },
    async set(k: string, v: string) {
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

let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let jwks: { keys: JWK[] };

beforeEach(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = KID;
  jwk.alg = 'RS256';
  jwks = { keys: [jwk] };
});

async function signIn(issuer: string, claims: Record<string, unknown>) {
  const config = {
    id: 'oidc_1',
    operator_id: 'op_acme',
    display_name: null,
    issuer_uri: issuer,
    client_id: CLIENT_ID,
    client_secret_encrypted: 'ciphertext',
    audience: null,
    redirect_uri: REDIRECT,
    scopes_json: ['openid', 'email', 'profile'],
    claim_mapping_policy_json: null,
    discovery_cached_json: null,
    jwks_cached_jwks_json: null,
    jwks_cached_at: null,
    jwks_cache_ttl_seconds: 300,
    allowed_return_origins: null,
    sso_slug: 'acme',
    sso_login_enabled: true,
    default_member_role: 'standard',
    active: true,
  };
  const repo = {
    async findById(id: string) {
      return id === config.id ? config : undefined;
    },
    async findActiveByOperator() {
      return config;
    },
    async persistLastKnownGoodJwks() {},
  };
  let nonce = '';
  const base = issuer.replace(/\/$/, '');
  const fetcher = (async (input: unknown) => {
    const url = String(input);
    const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    if (url === `${base}/.well-known/openid-configuration`) {
      return json({ issuer, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, jwks_uri: `${base}/jwks` });
    }
    if (url === `${base}/jwks`) return json(jwks);
    if (url === `${base}/token`) {
      const token = await new SignJWT({ iss: issuer, aud: CLIENT_ID, sub: 'user-1', nonce, email: 'Jane@Corp.Example.com', ...claims })
        .setProtectedHeader({ alg: 'RS256', kid: KID })
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);
      return json({ id_token: token, token_type: 'Bearer' });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
  const kms = { async encrypt() { return { ciphertext: 'x', keyRef: 'k' }; }, async decrypt() { return 'secret'; } };
  const provider = new OidcIdpProvider(fakeRedis() as never, repo as never, kms as never, fetcher, DASHBOARD, passGuard);
  const init = await provider.initiate('op_acme', { requested_claims: ['verified_human'] } as never);
  nonce = new URL(init.verification_url!).searchParams.get('nonce')!;
  await provider.acceptCallback(init.session_ref!, 'auth-code');
  return provider.completeForLogin(init.session_ref!);
}

describe('OidcIdpProvider.completeForLogin: what the token says about the address', () => {
  const generic = 'https://idp.example.test';

  it('reads email_verified true as verified', async () => {
    expect(await signIn(generic, { email_verified: true })).toMatchObject({
      email: 'jane@corp.example.com',
      email_verified: true,
      email_verified_absent: false,
      issuer_vouches_email_domain: false,
    });
  });

  it('tells a missing email_verified apart from one that says false or says something else', async () => {
    expect(await signIn(generic, {})).toMatchObject({ email_verified: false, email_verified_absent: true });
    expect(await signIn(generic, { email_verified: false })).toMatchObject({ email_verified: false, email_verified_absent: false });
    expect(await signIn(generic, { email_verified: 'true' })).toMatchObject({ email_verified: false, email_verified_absent: false });
    expect(await signIn(generic, { email_verified: null })).toMatchObject({ email_verified: false, email_verified_absent: false });
  });

  describe('the issuer\'s own claim that the domain is verified (Microsoft Entra xms_edov)', () => {
    it('is read for one tenant of Entra\'s v2 issuer whose token names that tenant, as the boolean true', async () => {
      const identity = await signIn(ENTRA, { tid: TENANT, xms_edov: true });
      expect(identity).toMatchObject({ email_verified: false, email_verified_absent: true, issuer_vouches_email_domain: true });
    });

    it.each([
      ['a string', 'true'],
      ['the number 1', 1],
      ['false', false],
    ])('is not read when it is %s', async (_why, value) => {
      expect((await signIn(ENTRA, { tid: TENANT, xms_edov: value })).issuer_vouches_email_domain).toBe(false);
    });

    it('is not read for another tenant\'s token, or one with no tenant', async () => {
      expect((await signIn(ENTRA, { tid: '11111111-1111-1111-1111-111111111111', xms_edov: true })).issuer_vouches_email_domain).toBe(false);
      expect((await signIn(ENTRA, { xms_edov: true })).issuer_vouches_email_domain).toBe(false);
    });

    it('is not read from a provider that is not one tenant of Entra, whatever it puts in the token', async () => {
      for (const issuer of [generic, `https://login.microsoftonline.com.evil.example/${TENANT}/v2.0`, 'https://login.microsoftonline.com/common/v2.0']) {
        expect((await signIn(issuer, { tid: TENANT, xms_edov: true })).issuer_vouches_email_domain).toBe(false);
      }
    });
  });
});
