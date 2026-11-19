import { beforeAll, describe, expect, it, vi } from 'vitest';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { ForbiddenError, type FleetPolicyInput } from '@stack/shared';
import { verifyFleetWorkload, type FleetWorkloadVerifier } from './fleet-workload.js';

let keys: Awaited<ReturnType<typeof generateKeyPair>>;
beforeAll(async () => { keys = await generateKeyPair('EdDSA', { extractable: true }); });
const issuer = 'https://identity.example.test';
const subject = 'worker:payments';
const audience = 'stack:fleet:payments';

function setup(kind: 'spiffe' | 'wimse' = 'wimse') {
  const expectedSubject = kind === 'spiffe' ? 'spiffe://fleet.example.test/worker/payments' : subject;
  const policy = { operatorId: 'op_owner', active: true, definition: {
    workload_trust: [{ kind, issuer, audience, subjects: [expectedSubject] }],
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  } as FleetPolicyInput };
  const configs = [{ id: 'cfg_owner', operator_id: 'op_owner', active: true, audience: audience as string | null }];
  const verifier: FleetWorkloadVerifier = {
    policy: async () => policy,
    configs: async () => configs,
    accept: vi.fn(async (_kind, token) => {
      const { payload } = await jwtVerify(token, keys.publicKey, { issuer, audience });
      return { subject: payload.sub!, issuer: payload.iss!, audience: payload.aud as string, notAfter: payload.exp! };
    }),
  };
  const token = (claims: Record<string, unknown> = {}, signingKey = keys.privateKey) => new SignJWT({
    iss: issuer, aud: audience, sub: expectedSubject, exp: Math.floor(Date.now() / 1000) + 300, ...claims,
  }).setProtectedHeader({ alg: 'EdDSA' }).sign(signingKey);
  return { policy, configs, verifier, token, expectedSubject };
}

describe('fleet workload trust and proof binding', () => {
  it.each(['wimse', 'spiffe'] as const)('accepts %s only through the owned pinned issuer configuration', async kind => {
    const { verifier, token, expectedSubject } = setup(kind);
    const result = await verifyFleetWorkload(verifier, 'flp_test', await token());
    expect(result).toMatchObject({ operatorId: 'op_owner', kind, configId: 'cfg_owner', subject: expectedSubject, issuer, audience });
    expect(result.tokenDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(verifier.accept).toHaveBeenCalledWith(kind, expect.any(String), 'cfg_owner');
  });

  it.each([{ iss: 'https://foreign.example.test' }, { sub: 'worker:foreign' }, { aud: 'another-service' }, { aud: [audience] }])('denies unapproved identity %j before cryptographic dispatch', async claims => {
    const { verifier, token } = setup();
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token(claims))).rejects.toBeInstanceOf(ForbiddenError);
    expect(verifier.accept).not.toHaveBeenCalled();
  });

  it('cannot choose a foreign tenant issuer configuration', async () => {
    const { verifier, configs, token } = setup();
    configs[0]!.operator_id = 'op_other';
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token())).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('requires audience pinning in the stored issuer configuration', async () => {
    const { verifier, configs, token } = setup();
    configs[0]!.audience = null;
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token())).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('rejects ambiguous issuer configurations and duplicate policy trust rules', async () => {
    const { verifier, configs, policy, token } = setup();
    configs.push({ ...configs[0]!, id: 'cfg_duplicate' });
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token())).rejects.toBeInstanceOf(ForbiddenError);
    configs.pop();
    policy.definition.workload_trust.push(policy.definition.workload_trust[0]!);
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token())).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('denies invalid signatures even when every decoded claim matches policy', async () => {
    const { verifier, token } = setup();
    const wrong = await generateKeyPair('EdDSA');
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token({}, wrong.privateKey))).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('denies expired identity and disabled policy', async () => {
    const { verifier, policy, token } = setup();
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token({ exp: 1 }))).rejects.toBeInstanceOf(ForbiddenError);
    policy.active = false;
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token())).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('carries verified confirmation-key binding for enrollment proof enforcement', async () => {
    const { verifier, token } = setup();
    const jwk = await exportJWK(keys.publicKey);
    const thumbprint = await calculateJwkThumbprint(jwk);
    const result = await verifyFleetWorkload(verifier, 'flp_test', await token({ cnf: { jwk, jkt: thumbprint } }));
    expect(result.confirmationThumbprint).toBe(thumbprint);
  });

  it.each([{ unsupported: true }, {}, { jkt: 'bad' }])('does not silently treat unsupported cnf %j as bearer authority', async cnf => {
    const { verifier, token } = setup();
    await expect(verifyFleetWorkload(verifier, 'flp_test', await token({ cnf }))).rejects.toBeInstanceOf(ForbiddenError);
  });
});
