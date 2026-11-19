import { describe, expect, it } from 'vitest';
import { PassportSigner } from '../../crypto/passport-signer.js';
import { StackIdentityAuthorityAdapter } from './stack-identity-authority.js';

function profile(kind: 'identity' | 'capacity' | 'signature', subjectBinding: Record<string, unknown>) {
  return {
    id: `apv_${kind}`,
    operator_id: 'op_acme',
    proof_kind: kind,
    schema_uri: `urn:test:${kind}`,
    schema_version: '1',
    adapter_key: 'stack_identity_authority',
    adapter_version: 1,
    accepted_native_formats: ['application/stack-authority-capacity+jwt'],
    status: 'active' as const,
    content_hash: 'sha256:'.padEnd(71, '0'),
    config_json: { validation: { subject_binding: subjectBinding } },
  };
}

describe('StackIdentityAuthorityAdapter', () => {
  it('binds the exact signed identity claim to the approving person', async () => {
    const signer = new PassportSigner();
    await signer.init();
    const bindingJws = await signer.signAuthorityCeremony('prn_person', {
      ceremony_type: 'identity_claim_authority_binding',
      operator_id: 'op_acme',
      identity_claim_id: 'idc_stripe',
      signed_claim_id: 'pc_identity',
      provider_key: 'stripe_identity',
    });
    const adapter = new StackIdentityAuthorityAdapter(signer);
    await expect(adapter.bindLegacyIdentitySubject({
      operatorId: 'op_acme',
      identityClaimId: 'idc_stripe',
      signedClaimId: 'pc_identity',
      subjectPrincipalId: 'prn_person',
      profile: profile('identity', { method: 'stack_identity_claim_ceremony', binding_jws: bindingJws }),
    } as never)).resolves.toBe(true);
    await expect(adapter.bindLegacyIdentitySubject({
      operatorId: 'op_acme',
      identityClaimId: 'idc_other',
      signedClaimId: 'pc_identity',
      subjectPrincipalId: 'prn_person',
      profile: profile('identity', { method: 'stack_identity_claim_ceremony', binding_jws: bindingJws }),
    } as never)).resolves.toBe(false);
  });

  it('records customer-asserted capacity without describing it as provider-verified', async () => {
    const signer = new PassportSigner();
    await signer.init();
    const adapter = new StackIdentityAuthorityAdapter(signer);
    const evidence = await signer.signAuthorityCeremony('prn_person', {
      ceremony_type: 'customer_asserted_capacity',
      operator_id: 'op_acme',
      represented_principal_id: 'prn_org',
      role_name: 'Finance approver',
      assertion_hash: 'sha256:'.padEnd(71, '1'),
    });
    const verified = await adapter.verify({
      nativeEvidence: evidence,
      nativeFormat: 'application/stack-authority-capacity+jwt',
      expectedIssuer: 'stack:authority-ceremony',
      expectedSubjectPrincipalId: 'prn_person',
      expectedRepresentedPrincipalId: 'prn_org',
      profile: profile('capacity', { method: 'stack_signed_ceremony' }),
    } as never);
    expect(verified.assuranceUri).toBe('urn:stack:assurance:customer-asserted-capacity');
    expect(verified.normalizedFacts).toMatchObject({
      capacity: { role_asserted: true, role_name: 'Finance approver', assertion_source: 'customer_account_admin' },
    });
  });
});
