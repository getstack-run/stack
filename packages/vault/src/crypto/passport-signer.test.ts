import { describe, it, expect, beforeAll, vi } from 'vitest';
import { decodeJwt, generateKeyPair, exportJWK, SignJWT } from 'jose';
import { PassportSigner } from './passport-signer.js';
import {
  OAUTH_ACCESS_TOKEN_AUDIENCE_API,
  OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
  SESSION_JWT_AUDIENCE,
  PASSPORT_ISSUER,
  OAUTH_ISSUER,
  OAUTH_METADATA_ISSUER,
  AGENT_JWT_ISSUER,
  AGENT_JWT_AUDIENCE,
} from '@stack/shared';

describe('PassportSigner — OAuth', () => {
  let signer: PassportSigner;

  beforeAll(async () => {
    signer = new PassportSigner();
    await signer.init(); // ephemeral keypair, dev mode
  });

  describe('signAccessToken / verifyAccessOrSession', () => {
    it('mints a stack:api access token with the expected claim shape', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        clientId: 'oclient_test',
        scope: 'passports:read agents:read',
        jti: 'oat_jti_1',
        ttlSeconds: 300,
      });

      const decoded = decodeJwt(token);
      expect(decoded.iss).toBe(OAUTH_ISSUER);
      expect(decoded.sub).toBe('op_test');
      expect(decoded.aud).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_API);
      expect(decoded['client_id']).toBe('oclient_test');
      expect(decoded['scope']).toBe('passports:read agents:read');
      expect(decoded['token_use']).toBe('access');
      expect(decoded.jti).toBe('oat_jti_1');
      expect(decoded.exp! - decoded.iat!).toBe(300);
    });

    it('mints a stack:mcp access token when audience is mcp', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
        clientId: 'oclient_test',
        scope: 'agents:read',
        jti: 'oat_jti_2',
        ttlSeconds: 300,
      });
      const decoded = decodeJwt(token);
      expect(decoded.aud).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_MCP);
    });

    it('signs the exact resource URL into the token when provided', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
        clientId: 'https://client.example/metadata.json',
        scope: 'agents:read',
        jti: 'oat_jti_resource',
        ttlSeconds: 300,
        resource: 'https://mcp.getstack.run/directory',
      });
      const verified = await signer.verifyAccessOrSession(token);
      expect(verified.aud).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_MCP);
      expect(verified.payload['resource']).toBe('https://mcp.getstack.run/directory');
      const legacy = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
        clientId: 'oclient_test',
        scope: 'agents:read',
        jti: 'oat_jti_no_resource',
        ttlSeconds: 300,
      });
      expect(decodeJwt(legacy)['resource']).toBeUndefined();
    });

    it('includes member_id when provided', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_parent',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        clientId: 'oclient_test',
        scope: 'passports:read',
        jti: 'oat_jti_3',
        ttlSeconds: 300,
        memberId: 'mem_alice',
      });
      const decoded = decodeJwt(token);
      expect(decoded['member_id']).toBe('mem_alice');
      expect(decoded.sub).toBe('op_parent');
    });

    it('verifyAccessOrSession routes stack:api tokens correctly', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        clientId: 'oclient_test',
        scope: 'passports:read',
        jti: 'oat_jti_4',
        ttlSeconds: 300,
      });
      const verified = await signer.verifyAccessOrSession(token);
      expect(verified.aud).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_API);
      expect(verified.sub).toBe('op_test');
      expect(verified.payload['scope']).toBe('passports:read');
    });

    it('verifyAccessOrSession routes stack:mcp tokens correctly', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_MCP,
        clientId: 'oclient_test',
        scope: 'agents:read',
        jti: 'oat_jti_5',
        ttlSeconds: 300,
      });
      const verified = await signer.verifyAccessOrSession(token);
      expect(verified.aud).toBe(OAUTH_ACCESS_TOKEN_AUDIENCE_MCP);
    });

    it('verifyAccessOrSession also accepts legacy session JWTs (stack:dashboard)', async () => {
      const sessionToken = await signer.signSession('op_test', 'a@b.com', 'business', 3600);
      const verified = await signer.verifyAccessOrSession(sessionToken);
      expect(verified.aud).toBe(SESSION_JWT_AUDIENCE);
      expect(verified.sub).toBe('op_test');
      expect(verified.payload['email']).toBe('a@b.com');
      expect(verified.payload['tier']).toBe('business');
    });

    it('verifyAccessOrSession rejects passport JWTs (wrong audience)', async () => {
      // Passport JWTs have aud=stack:passport which is NOT in the array.
      // verifyAccessOrSession should refuse them so an issued passport
      // can't be replayed against the API auth path.
      const passport = await signer.sign('jti_test', {
        operator_id: 'op_test',
        agent_id: 'agt_test',
        agent_name: 'test',
        services: [],
        identity_claims: [],
        delegation_depth: 0,
        session_id: 'ses_test',
      } as never, 300);
      await expect(signer.verifyAccessOrSession(passport.token)).rejects.toThrow();
    });

    it('verify reports a tampered, foreign, wrong-audience or malformed token as PASSPORT_INVALID, never as a revocation or a server error', async () => {
      const passport = await signer.sign('jti_dead', {
        operator_id: 'op_test', agent_id: 'agt_test', agent_name: 'test', services: [], identity_claims: [],
        delegation_depth: 0, session_id: 'ses_test',
      } as never, 300);
      const [header, payload, signature] = passport.token.split('.');
      const other = new PassportSigner();
      await other.init();
      const foreign = await other.sign('jti_foreign', {
        operator_id: 'op_test', agent_id: 'agt_test', agent_name: 'test', services: [], identity_claims: [],
        delegation_depth: 0, session_id: 'ses_test',
      } as never, 300);
      const session = await signer.signSession('op_test', 'a@b.com', 'business', 3600);
      // The first character of a signature carries six whole bits, so a different first character is always a different signature
      // (replacing the last two characters left a signature that already ended in them untouched, one run in 4096).
      const changed = `${signature![0] === 'A' ? 'B' : 'A'}${signature!.slice(1)}`;
      for (const token of [`${header}.${payload}.${changed}`, foreign.token, session, 'not.a.token', '']) {
        await expect(signer.verify(token)).rejects.toMatchObject({ code: 'PASSPORT_INVALID' });
      }
    });

    it('verifyAccessOrSession rejects expired tokens (beyond clock tolerance)', async () => {
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        clientId: 'oclient_test',
        scope: 'passports:read',
        jti: 'oat_jti_6',
        ttlSeconds: -60, // expired past the 30s clock tolerance
      });
      await expect(signer.verifyAccessOrSession(token)).rejects.toThrow();
    });

 it('verifyAccessOrSession tolerates small clock skew (30s clockTolerance)', async () => {
      // A token expired-by-10s (or minted fractionally "in the future" by
      // a skewed client clock) must still verify — zero tolerance turned
      // a 0.34s client-server skew into a 34% transient 401 rate.
      const token = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        clientId: 'oclient_test',
        scope: 'passports:read',
        jti: 'oat_jti_skew',
        ttlSeconds: -10,
      });
      await expect(signer.verifyAccessOrSession(token)).resolves.toBeTruthy();
    });
  });

  describe('signOAuthConsentToken / verifyOAuthConsentToken', () => {
    it('round-trips the consent claims', async () => {
      const token = await signer.signOAuthConsentToken('op_test', {
        client_id: 'oclient_x',
        redirect_uri: 'http://localhost:8080/cb',
        scope: 'passports:read',
        resource: 'https://api.getstack.run',
        code_challenge: 'abc123',
        code_challenge_method: 'S256',
        state: 'random-state',
        nonce: 'random-nonce',
      });
      const { sub, claims } = await signer.verifyOAuthConsentToken(token);
      expect(sub).toBe('op_test');
      expect(claims.client_id).toBe('oclient_x');
      expect(claims.redirect_uri).toBe('http://localhost:8080/cb');
      expect(claims.scope).toBe('passports:read');
      expect(claims.resource).toBe('https://api.getstack.run');
      expect(claims.code_challenge).toBe('abc123');
      expect(claims.code_challenge_method).toBe('S256');
      expect(claims.state).toBe('random-state');
      expect(claims.nonce).toBe('random-nonce');
      expect(claims.member_id).toBeUndefined();
    });

    it('preserves member_id when provided', async () => {
      const token = await signer.signOAuthConsentToken('op_parent', {
        client_id: 'oclient_x',
        redirect_uri: 'http://localhost:8080/cb',
        scope: 'passports:read',
        resource: 'https://api.getstack.run',
        code_challenge: 'abc',
        code_challenge_method: 'S256',
        state: 'state',
        member_id: 'mem_alice',
      });
      const { sub, claims } = await signer.verifyOAuthConsentToken(token);
      expect(sub).toBe('op_parent');
      expect(claims.member_id).toBe('mem_alice');
    });

    it('stays valid for the 15 minutes a magic-link sign-in can take, and is refused after that', async () => {
      vi.useFakeTimers();
      try {
        vi.setSystemTime(new Date('2026-11-10T10:00:00Z'));
        const token = await signer.signOAuthConsentToken('pending', {
          client_id: 'oclient_x',
          redirect_uri: 'http://localhost:8080/cb',
          scope: 'passports:read',
          resource: 'https://api.getstack.run',
          code_challenge: 'abc',
          code_challenge_method: 'S256',
          state: 'state',
        });
        vi.setSystemTime(new Date('2026-11-10T10:14:00Z'));
        await expect(signer.verifyOAuthConsentToken(token)).resolves.toBeTruthy();
        // Past the 15 minutes and the signer's 30 second clock tolerance.
        vi.setSystemTime(new Date('2026-11-10T10:15:31Z'));
        await expect(signer.verifyOAuthConsentToken(token)).rejects.toThrow();
      } finally {
        vi.useRealTimers();
      }
    });

    it('rejects a consent token verified against the wrong audience', async () => {
      const consentToken = await signer.signOAuthConsentToken('op_test', {
        client_id: 'oclient_x',
        redirect_uri: 'http://localhost:8080/cb',
        scope: 'passports:read',
        resource: 'https://api.getstack.run',
        code_challenge: 'abc',
        code_challenge_method: 'S256',
        state: 'state',
      });
      // Calling verifyAccessOrSession on a consent token must NOT succeed —
      // its aud is stack:oauth-consent, not in the access/session allowlist.
      // Critical invariant: a consent JWT cannot be replayed as an access
      // token, since both share the same signing key.
      await expect(signer.verifyAccessOrSession(consentToken)).rejects.toThrow();
    });
  });

 describe('agent JWT', () => {
    it('peekAgentJwt extracts iss + sub without verifying', async () => {
      const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience(AGENT_JWT_AUDIENCE)
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .setJti('aj_test')
        .sign(privateKey);

      const peeked = signer.peekAgentJwt(token);
      expect(peeked.iss).toBe(AGENT_JWT_ISSUER);
      expect(peeked.sub).toBe('agt_test');
      expect(peeked.jti).toBe('aj_test');
    });

    it('verifyAgentJwt accepts a valid agent-signed token', async () => {
      const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const pubJwk = await exportJWK(publicKey);
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience(AGENT_JWT_AUDIENCE)
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .setJti('aj_test_2')
        .sign(privateKey);

      const result = await signer.verifyAgentJwt(token, pubJwk);
      expect(result.sub).toBe('agt_test');
      expect(result.jti).toBe('aj_test_2');
    });

    it('verifyAgentJwt rejects a wrong-key signature', async () => {
      const a = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const b = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const wrongPubJwk = await exportJWK(b.publicKey);
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience(AGENT_JWT_AUDIENCE)
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .setJti('aj_test_3')
        .sign(a.privateKey);

      await expect(signer.verifyAgentJwt(token, wrongPubJwk)).rejects.toThrow();
    });

    it('verifyAgentJwt rejects wrong-audience tokens (refuses to be a passport-replay sink)', async () => {
      const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const pubJwk = await exportJWK(publicKey);
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience('stack:api') // wrong — should be stack:agent
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .setJti('aj_test_4')
        .sign(privateKey);
      await expect(signer.verifyAgentJwt(token, pubJwk)).rejects.toThrow();
    });

    it('verifyAgentJwt rejects long-TTL tokens (>120s ceiling)', async () => {
      const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const pubJwk = await exportJWK(publicKey);
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience(AGENT_JWT_AUDIENCE)
        .setIssuedAt(now)
        .setExpirationTime(now + 3600) // 1h — way over 120s
        .setJti('aj_test_5')
        .sign(privateKey);
      await expect(signer.verifyAgentJwt(token, pubJwk)).rejects.toThrow(/TTL exceeds max/);
    });

    it('verifyAgentJwt rejects expired tokens', async () => {
      const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const pubJwk = await exportJWK(publicKey);
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience(AGENT_JWT_AUDIENCE)
        .setIssuedAt(now - 120)
        .setExpirationTime(now - 60)
        .setJti('aj_test_6')
        .sign(privateKey);
      await expect(signer.verifyAgentJwt(token, pubJwk)).rejects.toThrow();
    });

    it('verifyAccessOrSession refuses agent tokens (cannot be replayed as access tokens)', async () => {
      const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
      const now = Math.floor(Date.now() / 1000);
      // Sign an "agent" token with a random keypair. Even with the
      // correct iss, the signature won't verify against STACK's signing
      // key — but more importantly, the audience (stack:agent) is not
      // in verifyAccessOrSession's allowlist. Either way must throw.
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(AGENT_JWT_ISSUER)
        .setSubject('agt_test')
        .setAudience(AGENT_JWT_AUDIENCE)
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .setJti('aj_cross')
        .sign(privateKey);
      await expect(signer.verifyAccessOrSession(token)).rejects.toThrow();
    });
  });

  describe('issuer guard', () => {
    it('signs the legacy issuer and accepts the metadata issuer during the issuer migration', async () => {
      expect(OAUTH_ISSUER).toBe(PASSPORT_ISSUER);
      expect(OAUTH_METADATA_ISSUER).toBe('https://api.getstack.run');

      const session = await signer.signSession('op_test', 'a@b.com', 'business', 60);
      const access = await signer.signAccessToken({
        operatorId: 'op_test',
        audience: OAUTH_ACCESS_TOKEN_AUDIENCE_API,
        clientId: 'oclient',
        scope: 'passports:read',
        jti: 'oat_iss_test',
        ttlSeconds: 60,
      });
      await expect(signer.verifyAccessOrSession(session)).resolves.toBeDefined();
      await expect(signer.verifyAccessOrSession(access)).resolves.toBeDefined();

      const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
      const privateJwk = await exportJWK(pair.privateKey);
      const publicJwk = await exportJWK(pair.publicKey);
      const transitionSigner = new PassportSigner();
      await transitionSigner.initWithKeys(privateJwk, publicJwk);
      const now = Math.floor(Date.now() / 1000);
      const transitionToken = await new SignJWT({ token_use: 'access', scope: 'agents:read' })
        .setProtectedHeader({ alg: 'EdDSA' })
        .setIssuer(OAUTH_METADATA_ISSUER)
        .setSubject('op_legacy')
        .setAudience(OAUTH_ACCESS_TOKEN_AUDIENCE_API)
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .sign(pair.privateKey);
      await expect(transitionSigner.verifyAccessOrSession(transitionToken)).resolves.toMatchObject({
        sub: 'op_legacy',
      });
    });
  });
});

describe('PassportSigner.verify, a token that is not a Passport', () => {
  it('is PASSPORT_INVALID, not a revocation and never an unclassified error', async () => {
    const signer = new PassportSigner();
    await signer.init();
    const session = await signer.signSession('op_test', 'a@example.test', 'free', 60);
    // Unreadable, tampered, and a real token of this deployment with another audience.
    for (const token of ['not.a.jwt', 'abc', `${session.slice(0, -4)}AAAA`, session]) {
      await expect(signer.verify(token), token.slice(0, 12)).rejects.toMatchObject({ code: 'PASSPORT_INVALID', statusCode: 401 });
    }
  });
});
