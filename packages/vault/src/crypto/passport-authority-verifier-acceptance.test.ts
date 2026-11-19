import {
  PASSPORT_ISSUER,
  PASSPORT_JWT_AUDIENCE,
  PassportExpiredError,
  PassportRevokedError,
  type AuthorityReference,
} from '@stack/shared';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { PassportService } from '../services/passport-service.js';
import { passportTestWiring } from '../services/passport-service.test-support.js';
import { PassportSigner, type PassportPayload } from './passport-signer.js';

const authorityRefs: AuthorityReference[] = [{
  binding_id: 'abn_verifier_acceptance',
  binding_version: 3,
  binding_claim_id: 'pc_verifier_acceptance',
  binding_digest: `sha256:${'b'.repeat(64)}`,
  receiver_id: 'rcv_verifier_acceptance',
  receiver_profile_version_id: 'apv_verifier_acceptance',
  expires_at: Math.floor(Date.now() / 1000) + 600,
}];

const baseClaims: PassportPayload = {
  operator_id: 'op_verifier_acceptance',
  agent_id: 'agt_verifier_acceptance',
  agent_name: 'Verifier acceptance agent',
  services: [],
  identity_claims: [],
  delegation_depth: 0,
  session_id: 'ses_verifier_acceptance',
};

async function setup(revoked = false) {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const signer = new PassportSigner();
  await signer.initWithKeys(await exportJWK(pair.privateKey), await exportJWK(pair.publicKey));
  const verifyPassportRefs = vi.fn(async () => undefined);
  const wiring = passportTestWiring({ authorityLookup: { verifyPassportRefs } as never });
  const service = new PassportService(
    { isRevoked: vi.fn(async () => revoked) } as never,
    { findById: vi.fn(async () => ({ id: baseClaims.agent_id, operator_id: baseClaims.operator_id, status: 'active' })) } as never,
    { findConnectionById: vi.fn(async () => null) } as never,
    signer,
    { get: vi.fn(async () => null) } as never,
    { findById: vi.fn(async () => ({ id: baseClaims.operator_id, status: 'active' })) } as never,
    '',
    {} as never,
    wiring.dependencies,
  );
  return { signer, service, privateKey: pair.privateKey, verifyPassportRefs };
}

async function forgedToken(input: {
  privateKey: CryptoKey;
  issuer?: string;
  audience?: string;
  subject?: string;
  expiresAt?: number;
}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ stk: { ...baseClaims, authority_refs: authorityRefs } })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuer(input.issuer ?? PASSPORT_ISSUER)
    .setAudience(input.audience ?? PASSPORT_JWT_AUDIENCE)
    .setSubject(input.subject ?? baseClaims.agent_id)
    .setIssuedAt(now - 120)
    .setExpirationTime(input.expiresAt ?? now + 300)
    .setJti('ppt_forged_acceptance')
    .sign(input.privateKey);
}

describe('canonical authority-bearing Passport verifier acceptance', () => {
  it('verifies both current and authority-bearing Passports through the same online verifier', async () => {
    const { signer, service, verifyPassportRefs } = await setup();
    const current = await signer.sign('ppt_current_acceptance', baseClaims, 300);
    const authority = await signer.sign('ppt_authority_acceptance', { ...baseClaims, authority_refs: authorityRefs }, 300);

    await expect(service.verify(current.token)).resolves.toMatchObject({ jti: 'ppt_current_acceptance' });
    await expect(service.verify(authority.token)).resolves.toMatchObject({
      jti: 'ppt_authority_acceptance',
      stk: { authority_refs: authorityRefs },
    });
    expect(verifyPassportRefs).toHaveBeenCalledOnce();
    expect(verifyPassportRefs).toHaveBeenCalledWith({
      operatorId: baseClaims.operator_id,
      agentId: baseClaims.agent_id,
      refs: authorityRefs,
    });
  });

  it.each([
    ['issuer', { issuer: 'https://attacker.invalid' }],
    ['audience', { audience: 'stack:some-other-audience' }],
    ['subject', { subject: 'agt_substituted' }],
  ] as const)('rejects a Passport with the wrong %s', async (_label, override) => {
    const { service, privateKey } = await setup();
    await expect(service.verify(await forgedToken({ privateKey, ...override }))).rejects.toThrow();
  });

  it('rejects a Passport signed by a different deployment key', async () => {
    const { service } = await setup();
    const attacker = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    await expect(service.verify(await forgedToken({ privateKey: attacker.privateKey }))).rejects.toThrow();
  });

  it('rejects expiry beyond the allowed clock tolerance', async () => {
    const { service, privateKey } = await setup();
    const expired = await forgedToken({
      privateKey,
      expiresAt: Math.floor(Date.now() / 1000) - 60,
    });
    await expect(service.verify(expired)).rejects.toBeInstanceOf(PassportExpiredError);
  });

  it('rejects an otherwise valid authority-bearing Passport after online revocation', async () => {
    const { signer, service } = await setup(true);
    const authority = await signer.sign('ppt_revoked_acceptance', { ...baseClaims, authority_refs: authorityRefs }, 300);
    await expect(service.verify(authority.token)).rejects.toBeInstanceOf(PassportRevokedError);
  });
});
