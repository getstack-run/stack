import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  LICENCE_FEATURES,
  STACK_LICENCE_PUBLIC_KEYS,
  licenceGrants,
  verifyLicence,
  type LicenceClaims,
} from './index.js';

const SPKI_PREFIX_LENGTH = 12;

function newIssuer(kid = 'test-key-1') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(SPKI_PREFIX_LENGTH).toString('base64url');
  const issue = (overrides: Partial<Record<keyof LicenceClaims, unknown>> = {}, payloadOverride?: string) => {
    const claims = {
      v: 1,
      kid,
      customer: 'Example AB',
      issued_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2027-01-01T00:00:00.000Z',
      features: ['sso', 'siem'],
      ...overrides,
    };
    const payload = payloadOverride ?? Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
    const signature = sign(null, Buffer.from(`stack-licence-v1\n${payload}`, 'utf8'), privateKey);
    return `STACKLIC1.${payload}.${signature.toString('base64url')}`;
  };
  return { trustedKeys: { [kid]: raw }, issue };
}

const NOW = new Date('2026-10-21T12:00:00.000Z');

describe('verifyLicence', () => {
  it('accepts a key signed by a trusted licence key and reads what it grants', () => {
    const { issue, trustedKeys } = newIssuer();
    const state = verifyLicence(issue(), { now: NOW, trustedKeys });
    expect(state.status).toBe('valid');
    if (state.status !== 'valid') return;
    expect(state.claims.customer).toBe('Example AB');
    expect(licenceGrants(state, 'sso', NOW)).toBe(true);
    expect(licenceGrants(state, 'siem', NOW)).toBe(true);
    expect(licenceGrants(state, 'partners', NOW)).toBe(false);
  });

  it('reports no key as none, so the engine runs with enterprise features off', () => {
    expect(verifyLicence(undefined)).toEqual({ status: 'none' });
    expect(verifyLicence('')).toEqual({ status: 'none' });
    expect(verifyLicence('   \n')).toEqual({ status: 'none' });
    expect(licenceGrants({ status: 'none' }, 'sso')).toBe(false);
  });

  it('reads an expired key as expired and grants nothing', () => {
    const { issue, trustedKeys } = newIssuer();
    const state = verifyLicence(issue({ expires_at: '2026-06-01T00:00:00.000Z' }), { now: NOW, trustedKeys });
    expect(state.status).toBe('expired');
    expect(licenceGrants(state, 'sso', NOW)).toBe(false);
  });

  it('stops granting at the expiry instant even if it was valid when checked', () => {
    const { issue, trustedKeys } = newIssuer();
    const state = verifyLicence(issue(), { now: NOW, trustedKeys });
    expect(licenceGrants(state, 'sso', new Date('2026-12-31T23:59:59.000Z'))).toBe(true);
    expect(licenceGrants(state, 'sso', new Date('2027-01-01T00:00:00.000Z'))).toBe(false);
  });

  it('refuses a payload edited after signing, such as a longer expiry or more features', () => {
    const { issue, trustedKeys } = newIssuer();
    const [prefix, , signature] = issue().split('.');
    const forged = Buffer.from(
      JSON.stringify({
        v: 1,
        kid: 'test-key-1',
        customer: 'Example AB',
        issued_at: '2026-01-01T00:00:00.000Z',
        expires_at: '2099-01-01T00:00:00.000Z',
        features: [...LICENCE_FEATURES],
      }),
    ).toString('base64url');
    expect(verifyLicence(`${prefix}.${forged}.${signature}`, { now: NOW, trustedKeys })).toEqual({
      status: 'invalid',
      reason: 'bad_signature',
    });
  });

  it('refuses a key signed by another party that borrows a trusted kid', () => {
    const real = newIssuer();
    const impostor = newIssuer();
    expect(verifyLicence(impostor.issue(), { now: NOW, trustedKeys: real.trustedKeys })).toEqual({
      status: 'invalid',
      reason: 'bad_signature',
    });
  });

  it('refuses a kid it does not trust, including every kid when the built-in set is used', () => {
    const { issue } = newIssuer('someone-else');
    expect(verifyLicence(issue(), { now: NOW })).toEqual({ status: 'invalid', reason: 'unknown_key' });
    expect(Object.keys(STACK_LICENCE_PUBLIC_KEYS).length).toBeGreaterThan(0);
  });

  it('refuses malformed and differently-versioned keys without throwing', () => {
    const { trustedKeys } = newIssuer();
    for (const key of ['nope', 'STACKLIC1.only-two', 'STACKLIC1.a.b.c', 'STACKLIC1.@@@.###', 'STACKLIC1..']) {
      expect(verifyLicence(key, { now: NOW, trustedKeys }).status).toBe('invalid');
    }
    expect(verifyLicence('STACKLIC2.aaaa.bbbb', { now: NOW, trustedKeys })).toEqual({
      status: 'invalid',
      reason: 'unsupported_version',
    });
  });

  it('refuses signed claims it cannot read, and a key issued far in the future', () => {
    const { issue, trustedKeys } = newIssuer();
    expect(verifyLicence(issue({ customer: '' }), { now: NOW, trustedKeys })).toEqual({ status: 'invalid', reason: 'bad_claims' });
    expect(verifyLicence(issue({ expires_at: 'tomorrow-ish' }), { now: NOW, trustedKeys })).toEqual({ status: 'invalid', reason: 'bad_claims' });
    expect(verifyLicence(issue({ features: [1] }), { now: NOW, trustedKeys })).toEqual({ status: 'invalid', reason: 'bad_claims' });
    expect(verifyLicence(issue({ issued_at: '2027-06-01T00:00:00.000Z' }), { now: NOW, trustedKeys })).toEqual({
      status: 'invalid',
      reason: 'not_yet_valid',
    });
  });

  it('reads the STACK account a key was issued to, and refuses a malformed one', () => {
    const { issue, trustedKeys } = newIssuer();
    const issued = verifyLicence(issue({ operator_id: 'op_abc123-XYZ' }), { now: NOW, trustedKeys });
    expect(issued.status === 'valid' && issued.claims.operator_id).toBe('op_abc123-XYZ');
    const plain = verifyLicence(issue(), { now: NOW, trustedKeys });
    expect(plain.status === 'valid' && 'operator_id' in plain.claims).toBe(false);
    for (const bad of ['', 'abc', 'op_', 'op_has space', 42, null]) {
      expect(verifyLicence(issue({ operator_id: bad }), { now: NOW, trustedKeys })).toEqual({ status: 'invalid', reason: 'bad_claims' });
    }
  });

  it('reads the id a key carries, so it can be revoked, and refuses a malformed one', () => {
    const { issue, trustedKeys } = newIssuer();
    const id = 'lk_2b7d9f0a4c1e8356';
    const issued = verifyLicence(issue({ jti: id }), { now: NOW, trustedKeys });
    expect(issued.status === 'valid' && issued.claims.jti).toBe(id);
    // A key without one is still a valid licence for its features; the network is what refuses it.
    const plain = verifyLicence(issue(), { now: NOW, trustedKeys });
    expect(plain.status).toBe('valid');
    expect(plain.status === 'valid' && 'jti' in plain.claims).toBe(false);
    for (const bad of ['', 'short', 'has space in it, long enough', 'x'.repeat(65), 42, null]) {
      expect(verifyLicence(issue({ jti: bad }), { now: NOW, trustedKeys })).toEqual({ status: 'invalid', reason: 'bad_claims' });
    }
  });

  it('keeps the features it knows and ignores ones a newer key grants', () => {
    const { issue, trustedKeys } = newIssuer();
    const state = verifyLicence(issue({ features: ['sso', 'quantum-mode', 'sso'] }), { now: NOW, trustedKeys });
    expect(state.status).toBe('valid');
    if (state.status === 'valid') expect(state.claims.features).toEqual(['sso']);
  });
});
