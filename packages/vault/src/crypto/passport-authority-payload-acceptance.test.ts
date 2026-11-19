import { decodeJwt, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { PassportSigner } from './passport-signer.js';

const SENSITIVE_CANARIES = [
  'RAW-IDENTITY-ALICE-EXAMPLE',
  'RAW-CAPACITY-DIRECTOR-EXAMPLE',
  'RAW-MANDATE-PAY-INVOICE-EXAMPLE',
  'sk_live_receiver_credential_example',
  '190001019999',
  'TAX-SECTOR-FILING-FACT-EXAMPLE',
] as const;

async function signer() {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const result = new PassportSigner();
  await result.initWithKeys(await exportJWK(pair.privateKey), await exportJWK(pair.publicKey));
  return result;
}

describe('authority Passport payload acceptance', () => {
  it('captures only opaque authority references and non-secret routing metadata', async () => {
    const passportSigner = await signer();
    const now = Math.floor(Date.now() / 1000);
    const signed = await passportSigner.sign('ppt_authority_payload_acceptance', {
      operator_id: 'op_acceptance',
      agent_id: 'agt_acceptance',
      agent_name: 'Acceptance agent',
      services: [],
      identity_claims: [],
      delegation_depth: 0,
      session_id: 'ses_acceptance',
      authority_refs: [{
        binding_id: 'abn_acceptance',
        binding_version: 7,
        binding_claim_id: 'pc_acceptance',
        binding_digest: `sha256:${'a'.repeat(64)}`,
        receiver_id: 'rcv_acceptance',
        receiver_profile_version_id: 'apv_receiver_acceptance',
        expires_at: now + 300,
      }],
      // These model an unsafe caller trying to smuggle source payloads into
      // the Passport. PassportClaimsSchema is the real mint-time allowlist.
      raw_identity: SENSITIVE_CANARIES[0],
      raw_capacity: SENSITIVE_CANARIES[1],
      raw_mandate: SENSITIVE_CANARIES[2],
      credential: SENSITIVE_CANARIES[3],
      personal_number: SENSITIVE_CANARIES[4],
      tax_filing_fact: SENSITIVE_CANARIES[5],
    } as never, 300);

    const decoded = decodeJwt(signed.token);
    const encodedPayload = JSON.stringify(decoded);
    for (const canary of SENSITIVE_CANARIES) expect(encodedPayload).not.toContain(canary);
    expect(decoded).toMatchObject({
      sub: 'agt_acceptance',
      stk: {
        operator_id: 'op_acceptance',
        agent_id: 'agt_acceptance',
        authority_refs: [{
          binding_id: 'abn_acceptance',
          binding_version: 7,
          binding_claim_id: 'pc_acceptance',
          receiver_id: 'rcv_acceptance',
          receiver_profile_version_id: 'apv_receiver_acceptance',
        }],
      },
    });
    expect(Object.keys(decoded.stk as Record<string, unknown>)).not.toEqual(
      expect.arrayContaining(['raw_identity', 'raw_capacity', 'raw_mandate', 'credential', 'personal_number', 'tax_filing_fact']),
    );
  });
});
