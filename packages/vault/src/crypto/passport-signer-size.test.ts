import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import { InvalidRequestError, PASSPORT_TOKEN_MAX_CHARS } from '@stack/shared';
import { PassportSigner } from './passport-signer.js';

// A Passport is sent in a request header, and STACK's servers read request headers up to 64 KB. STACK refuses, in
// plain words, to sign one longer than 48,000 characters, which would not arrive.

async function signer() {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const s = new PassportSigner();
  await s.initWithKeys(await exportJWK(pair.privateKey), await exportJWK(pair.publicKey));
  return s;
}

const scope = (constraints: unknown[]) => ({
  service_id: 'svc_slack', service_name: 'slack', scopes: ['*'], credential_ref: 'c', connection_id: 'scon_slack', constraints,
});

const claims = (services: unknown[]) => ({
  operator_id: 'op_test', agent_id: 'agt_one', agent_name: 'one', services, identity_claims: [], delegation_depth: 0, session_id: 'ses_test',
});

describe('the size of a signed Passport', () => {
  it('signs an ordinary one', async () => {
    const signed = await (await signer()).sign('ppt_small', claims([scope([{ path: 'method', op: 'eq', value: 'GET' }])]) as never, 300);
    expect(signed.token.length).toBeLessThan(PASSPORT_TOKEN_MAX_CHARS);
  });

  it('signs one past the old 12,000 characters', async () => {
    const values = Array.from({ length: 64 }, (_, i) => `value-${i}-${'x'.repeat(40)}`);
    const wide = Array.from({ length: 6 }, (_, i) => ({ path: `body.p${i}`, op: 'in', value: values }));
    const signed = await (await signer()).sign('ppt_wide', claims([scope(wide)]) as never, 300);
    expect(signed.token.length).toBeGreaterThan(12_000);
    expect(signed.token.length).toBeLessThan(PASSPORT_TOKEN_MAX_CHARS);
  });

  it('refuses plainly one that is too long for a header', async () => {
    const big = Array.from({ length: 256 }, (_, i) => `value-${i}-${'x'.repeat(40)}`);
    const heavy = Array.from({ length: 12 }, (_, i) => ({ path: `body.p${i}`, op: 'in', value: big }));
    const attempt = (await signer()).sign('ppt_big', claims([scope(heavy)]) as never, 300);
    await expect(attempt).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(attempt).rejects.toThrow(/characters, more than the 48000 one can be\. Give it fewer constraints or shorter ones\./);
  });
});
