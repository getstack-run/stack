import { describe, expect, it } from 'vitest';
import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import { PASSPORT_ISSUER, PASSPORT_JWT_AUDIENCE } from '@stack/shared';
import { PassportSigner } from './passport-signer.js';

const stk = {
  operator_id: 'op_test',
  agent_id: 'agt_bound',
  agent_name: 'bound agent',
  services: [],
  identity_claims: [],
  authority_refs: [{
    binding_id: 'abn_test',
    binding_version: 1,
    binding_claim_id: 'pc_test',
    binding_digest: `sha256:${'a'.repeat(64)}`,
    receiver_id: 'rcv_test',
    receiver_profile_version_id: 'apv_test',
    expires_at: Math.floor(Date.now() / 1000) + 300,
  }],
  delegation_depth: 0,
  session_id: 'ses_test',
};

async function setup() {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const signer = new PassportSigner();
  await signer.initWithKeys(await exportJWK(pair.privateKey), await exportJWK(pair.publicKey));
  return { signer, privateKey: pair.privateKey };
}

function receiverPresentation(now: number) {
  const digest = `sha256:${'c'.repeat(64)}`;
  return {
    iss: 'https://getstack.run' as const,
    aud: 'https://receiver.example',
    jti: 'pjt_test',
    iat: now,
    exp: now + 60,
    authority_use_id: 'aus_test',
    agent_id: 'agt_bound',
    agent_key_thumbprint: digest,
    binding_ref: stk.authority_refs[0],
    principal_ref: 'prn_test',
    mission_id: 'ms_test',
    action_uri: 'urn:stack:test:submit',
    resource_hash: digest,
    request_hash: digest,
    receiver_id: 'rcv_test',
    receiver_profile_version_id: 'apv_test',
    domain_profile_version_id: 'apv_domain',
    proof_profile_version_ids: ['apv_proof'],
    live_check_time: now,
    evidence_refs: [{
      proof_id: 'prf_test',
      proof_version: 1,
      role: 'principal_identity' as const,
      authoriser_principal_id: null,
      group_key_hash: digest,
      profile_version_id: 'apv_proof',
      issuer_identifier: 'issuer.example',
      schema_uri: 'urn:example:identity',
      schema_version: '1',
      assurance_uri: 'urn:example:high',
      evidence_digest: digest,
      evidence_modes: ['exact_private' as const],
      status: 'valid' as const,
    }],
    approval_claim_refs: [],
    approval_requirements: [],
    proof_strength: 'native_issuer_evidence' as const,
    nonce: 'abcdefghijklmnopqrstuv',
    disclosed_facts: [{
      fact_id: 'private.fact',
      mode: 'exact_private' as const,
      proof_id: 'prf_test',
      value: 'receiver-only',
      assertion_source: 'stack_derived' as const,
      proof_strength: 'native_stack_attestation' as const,
      provenance: { profile_version_id: 'apv_proof' },
    }],
  };
}

describe('PassportSigner authority claim validation', () => {
  it('accepts an opaque authority reference and returns no proof or PII payload', async () => {
    const { signer } = await setup();
    const signed = await signer.sign('ppt_test', stk, 300);

    await expect(signer.verify(signed.token)).resolves.toMatchObject({
      sub: 'agt_bound',
      stk: { authority_refs: stk.authority_refs },
    });
    const decoded = JSON.stringify(decodeJwt(signed.token));
    expect(decoded).not.toContain('personal_number');
    expect(decoded).not.toContain('native_evidence');
  });

  it('rejects a signed token whose JWT subject differs from stk.agent_id', async () => {
    const { signer, privateKey } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({ stk })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer(PASSPORT_ISSUER)
      .setAudience(PASSPORT_JWT_AUDIENCE)
      .setSubject('agt_other')
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .setJti('ppt_subject_mismatch')
      .sign(privateKey);

    await expect(signer.verify(forged)).rejects.toThrow(/subject does not match/);
  });

  it('refuses to mint a Passport with a malformed authority digest', async () => {
    const { signer } = await setup();
    const malformed = {
      ...stk,
      authority_refs: [{ ...stk.authority_refs[0], binding_digest: 'not-a-digest' }],
    };

    await expect(signer.sign('ppt_bad_ref', malformed as never, 300)).rejects.toThrow(/sha256/);
  });

  it('keeps the subject binding check on the expired-token refresh path', async () => {
    const { signer, privateKey } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({ stk })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer(PASSPORT_ISSUER)
      .setAudience(PASSPORT_JWT_AUDIENCE)
      .setSubject('agt_other')
      .setIssuedAt(now - 120)
      .setExpirationTime(now - 60)
      .setJti('ppt_expired_subject_mismatch')
      .sign(privateKey);

    await expect(signer.verify(forged, { ignoreExpiration: true }))
      .rejects.toThrow(/subject does not match/);
  });

  it('signs the private receiver presentation with the canonical deployment key', async () => {
    const { signer } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const payload = receiverPresentation(now);
    const token = await signer.signAuthorityPresentation(payload);
    const header = decodeProtectedHeader(token);
    expect(header).toMatchObject({ alg: 'EdDSA', typ: 'JWT' });
    expect(header.kid).toBeTruthy();

    const publicKey = await importJWK(await signer.getPublicJwk(), 'EdDSA');
    const verified = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      issuer: payload.iss,
      audience: payload.aud,
    });
    expect(verified.payload.disclosed_facts).toEqual(payload.disclosed_facts);
  });

  it('refuses to sign a presentation with a substituted issuer or excessive lifetime', async () => {
    const { signer } = await setup();
    const now = Math.floor(Date.now() / 1000);
    const base = receiverPresentation(now);

    await expect(signer.signAuthorityPresentation({ ...base, iss: 'https://attacker.example' }))
      .rejects.toThrow();
    await expect(signer.signAuthorityPresentation({ ...base, exp: now + 121 }))
      .rejects.toThrow(/120 seconds/);
  });

  it('refuses to sign a receiver presentation missing an exact authority binding', async () => {
    const { signer } = await setup();
    const { binding_ref: _missing, ...incomplete } = receiverPresentation(Math.floor(Date.now() / 1000));

    await expect(signer.signAuthorityPresentation(incomplete))
      .rejects.toThrow();
  });
});
