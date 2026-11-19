import { describe, expect, it, vi } from 'vitest';
import { PassportSigner } from '../../crypto/passport-signer.js';
import { EnterpriseOidcAuthorityAdapter } from './enterprise-oidc-authority.js';
import { AuthorityApprovalCeremonyRejectedError } from '../../services/authority-service.js';

const issuer = 'https://login.example.test/tenant/v2.0';

function profile(kind: 'identity' | 'capacity' | 'signature', subjectBinding: Record<string, unknown>) {
  return {
    id: `apv_${kind}`,
    operator_id: 'op_acme',
    proof_kind: kind,
    schema_uri: `urn:test:${kind}`,
    schema_version: '1',
    adapter_key: 'enterprise_oidc_authority',
    adapter_version: 1,
    accepted_native_formats: ['application/stack-authority-oidc+jwt'],
    status: 'active' as const,
    content_hash: 'sha256:'.padEnd(71, '0'),
    config_json: {
      proof_kind: kind,
      validation: { subject_binding: subjectBinding },
      freshness: { maximum_age_seconds: 3600, live_status_required: true },
    },
  };
}

describe('EnterpriseOidcAuthorityAdapter', () => {
  it('accepts a configured app role and binds it to the represented organisation', async () => {
    const signer = new PassportSigner();
    await signer.init();
    const oidc = {
      verifyAuthorityEvidence: vi.fn(async () => ({
        payload: { iss: issuer, sub: 'user-1', iat: Math.floor(Date.now() / 1000), roles: ['finance-approver'] },
        signature_algorithm: 'RS256',
        issuer_key_thumbprint: 'thumbprint',
        expires_at: new Date(Date.now() + 30 * 60_000),
      })),
    };
    const adapter = new EnterpriseOidcAuthorityAdapter(oidc, signer);
    const evidence = await signer.signAuthorityCeremony('prn_person', {
      ceremony_type: 'oidc_authority_evidence',
      operator_id: 'op_acme',
      represented_principal_id: 'prn_org',
      oidc_config_id: 'oidc_1',
      oidc_id_token: 'native-id-token',
      oidc_nonce: 'nonce',
      oidc_subject_hash: await import('@stack/shared').then(({ sha256 }) => sha256(`${issuer}\u0000user-1`)),
      role_name: 'Finance approver',
    });
    const verified = await adapter.verify({
      nativeEvidence: evidence,
      nativeFormat: 'application/stack-authority-oidc+jwt',
      expectedIssuer: issuer,
      expectedSubjectPrincipalId: 'prn_person',
      expectedRepresentedPrincipalId: 'prn_org',
      profile: profile('capacity', {
        oidc_config_id: 'oidc_1',
        claim_path: 'roles',
        claim_value_hash: await import('@stack/shared').then(({ sha256 }) => sha256('finance-approver')),
        role_name_hash: await import('@stack/shared').then(({ sha256 }) => sha256('Finance approver')),
      }),
    });
    expect(verified.representedPrincipalId).toBe('prn_org');
    expect(verified.normalizedFacts).toMatchObject({ capacity: { role_verified: true, role_name: 'Finance approver' } });
  });

  it('fails closed when the configured role is absent', async () => {
    const { sha256 } = await import('@stack/shared');
    const signer = new PassportSigner();
    await signer.init();
    const adapter = new EnterpriseOidcAuthorityAdapter({
      verifyAuthorityEvidence: async () => ({
        payload: { iss: issuer, sub: 'user-1', roles: ['support'] },
        signature_algorithm: 'RS256', issuer_key_thumbprint: 'thumb',
        expires_at: new Date(Date.now() + 60_000),
      }),
    }, signer);
    const evidence = await signer.signAuthorityCeremony('prn_person', {
      ceremony_type: 'oidc_authority_evidence', operator_id: 'op_acme',
      represented_principal_id: 'prn_org', oidc_config_id: 'oidc_1',
      oidc_id_token: 'token', oidc_nonce: 'nonce',
      oidc_subject_hash: sha256(`${issuer}\u0000user-1`), role_name: 'Finance approver',
    });
    await expect(adapter.verify({
      nativeEvidence: evidence, nativeFormat: 'application/stack-authority-oidc+jwt',
      expectedIssuer: issuer, expectedSubjectPrincipalId: 'prn_person',
      expectedRepresentedPrincipalId: 'prn_org',
      profile: profile('capacity', { oidc_config_id: 'oidc_1', claim_path: 'roles',
        claim_value_hash: sha256('finance-approver'), role_name_hash: sha256('Finance approver') }),
    })).rejects.toThrow('configured organisational role');
  });

  it('accepts only the exact approval request, actor and proof references', async () => {
    const { canonicalize, sha256 } = await import('@stack/shared');
    const signer = new PassportSigner();
    await signer.init();
    const adapter = new EnterpriseOidcAuthorityAdapter({ verifyAuthorityEvidence: vi.fn() }, signer);
    const author = { kind: 'operator_owner' as const, operator_id: 'op_acme' };
    const token = await signer.signAuthorityCeremony('prn_person', {
      ceremony_type: 'authority_approval_decision', operator_id: 'op_acme',
      request_id: 'apr_one', request_hash: 'sha256:'.padEnd(71, '1'), decision: 'approve',
      authenticated_author_hash: sha256(canonicalize(author)),
      identity_proof_id: 'prf_identity', identity_proof_version: 1,
      capacity_proof_id: 'prf_capacity', capacity_proof_version: 1,
      decision_proof_id: 'prf_decision', decision_proof_version: 1,
    });
    const shared = {
      requestId: 'apr_one', requestHash: 'sha256:'.padEnd(71, '1'), decision: 'approve' as const,
      signedDecision: token, authenticatedAuthor: author, authoriserPrincipalId: 'prn_person',
      identityProof: { id: 'prf_identity', version: 1 },
      capacityProof: { id: 'prf_capacity', version: 1 }, profile: profile('identity', {}),
    };
    await expect(adapter.verifyApprovalDecision(shared as never)).resolves.toEqual({
      decisionProofId: 'prf_decision', decisionProofVersion: 1,
    });
    await expect(adapter.verifyApprovalDecision({
      ...shared, requestHash: 'sha256:'.padEnd(71, '2'),
    } as never))
      .rejects.toBeInstanceOf(AuthorityApprovalCeremonyRejectedError);
  });
});
