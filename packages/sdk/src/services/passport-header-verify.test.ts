import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { verifyPassportHeader } from './passport-header-verify.js';

/**
 * verifyPassportHeader invariants — hardening.
 *
 *   H1: verifies a known-good token signed under the deployment JWKS
 *   H2: rejects missing/empty header
 *   H3: rejects token with no `sub` claim
 *   H4: rejects token signed by the wrong key (bad signature)
 *   H5: rejects token with wrong issuer/audience
 */

const TENANT_ID = 'op_tenant_test';
const AGENT_ID = 'agt_x';
const ISSUER = 'getstack.run';
const AUDIENCE = 'stack:passport';

// jose's generateKeyPair returns the runtime key type (a CryptoKey under the
// hood). Derive it from jose rather than naming the bare DOM `CryptoKey` global,
// which isn't in this package's tsconfig lib (ES2022, no DOM/WebWorker).
type GeneratedPrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

interface KeyPair {
  privateKey: GeneratedPrivateKey;
  publicJwk: JWK;
}

async function makeKeyPair(): Promise<KeyPair> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = 'test-key-1';
  publicJwk.alg = 'EdDSA';
  publicJwk.use = 'sig';
  return { privateKey, publicJwk };
}

async function signPassport(
  privateKey: GeneratedPrivateKey,
  overrides: {
    sub?: string;
    iss?: string;
    aud?: string;
    expSecondsFromNow?: number;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    stk: {
      operator_id: TENANT_ID,
      agent_id: AGENT_ID,
      agent_name: 'test agent',
      services: [],
      identity_claims: [],
      delegation_depth: 0,
      session_id: 'ses_x',
      authority_refs: [{
        binding_id: 'abn_test',
        binding_version: 1,
        binding_claim_id: 'pc_test',
        binding_digest: `sha256:${'a'.repeat(64)}`,
        receiver_id: 'rcv_test',
        receiver_profile_version_id: 'apv_test',
        expires_at: now + 900,
      }],
    },
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'test-key-1' })
    .setSubject(overrides.sub ?? AGENT_ID)
    .setIssuer(overrides.iss ?? ISSUER)
    .setAudience(overrides.aud ?? AUDIENCE)
    .setJti('pas_test_' + Math.random().toString(36).slice(2, 10))
    .setIssuedAt(now)
    .setExpirationTime(now + (overrides.expSecondsFromNow ?? 900))
    .sign(privateKey);
}

describe('verifyPassportHeader hardening', () => {
  let keypair: KeyPair;
  let wrongKeypair: KeyPair;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeAll(async () => {
    keypair = await makeKeyPair();
    wrongKeypair = await makeKeyPair();
  });

  beforeEach(() => {
    // Mock global fetch so JWKS lookup returns our test key.
    fetchSpy = vi.fn(async (url: string) => {
      if (url.includes('/v1/.well-known/jwks.json')) {
        return new Response(JSON.stringify({ keys: [keypair.publicJwk] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('not found', { status: 404 });
    });
    globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch;
  });

  it('H1 verifies a known-good token signed under the deployment JWKS', async () => {
    const token = await signPassport(keypair.privateKey);
    const claims = await verifyPassportHeader(token, {
      baseUrl: 'https://api.test',
    });
    expect(claims.sub).toBe(AGENT_ID);
    expect(claims.iss).toBe(ISSUER);
    expect(claims.aud).toBe(AUDIENCE);
    expect(claims.stk.operator_id).toBe(TENANT_ID);
    expect(claims.stk.authority_refs?.[0]?.binding_id).toBe('abn_test');
  });

  it('rejects a token whose sub does not match stk.agent_id', async () => {
    const token = await signPassport(keypair.privateKey, { sub: 'agt_other' });
    await expect(verifyPassportHeader(token, { baseUrl: 'https://api.test' })).rejects.toThrow(
      /sub must match stk\.agent_id/i,
    );
  });

  it('H2 rejects missing/empty header', async () => {
    await expect(verifyPassportHeader(undefined, { baseUrl: 'https://api.test' })).rejects.toThrow(
      /missing header/i,
    );
    // Empty string + empty array both reject (any error message is fine).
    await expect(verifyPassportHeader('', { baseUrl: 'https://api.test' })).rejects.toThrow();
    await expect(verifyPassportHeader([], { baseUrl: 'https://api.test' })).rejects.toThrow();
  });

  it('H3 rejects token with no sub claim', async () => {
    // Sign a token WITHOUT setSubject() — sub will be missing.
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-key-1' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setJti('pas_no_sub')
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .sign(keypair.privateKey);

    await expect(verifyPassportHeader(token, { baseUrl: 'https://api.test' })).rejects.toThrow(
      /required claims/i,
    );
  });

  it('H4 rejects token signed by the wrong key (bad signature)', async () => {
    // Sign with the WRONG keypair — JWKS returns the right key only,
    // so verification fails.
    const token = await signPassport(wrongKeypair.privateKey);
    await expect(verifyPassportHeader(token, { baseUrl: 'https://api.test' })).rejects.toThrow();
  });

  it('H5 rejects token with wrong issuer', async () => {
    const token = await signPassport(keypair.privateKey, { iss: 'evil.example.com' });
    await expect(verifyPassportHeader(token, { baseUrl: 'https://api.test' })).rejects.toThrow();
  });

  it('H5b rejects token with wrong audience', async () => {
    const token = await signPassport(keypair.privateKey, { aud: 'stack:not-passport' });
    await expect(verifyPassportHeader(token, { baseUrl: 'https://api.test' })).rejects.toThrow();
  });
});
