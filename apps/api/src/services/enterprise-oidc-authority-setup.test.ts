import { describe, expect, it, vi } from 'vitest';
import {
  completeEnterpriseOidcAuthoritySetup,
  completeStripeIdentityAuthoritySetup,
} from './enterprise-oidc-authority-setup.js';

function fixture() {
  let profileSequence = 0;
  let proofSequence = 0;
  const createProfileVersion = vi.fn(async (..._args: unknown[]) => ({ id: `apv_${++profileSequence}` }));
  const activateProfileVersion = vi.fn(async (...args: unknown[]) => ({ id: String(args[2]) }));
  const importProof = vi.fn(async (..._args: unknown[]) => ({ id: `prf_${++proofSequence}`, version: 1 }));
  const createBinding = vi.fn(async (..._args: unknown[]) => ({ id: 'abn_setup', version: 1, status: 'pending' }));
  const decideApproval = vi.fn(async (..._args: unknown[]) => ({ id: 'apd_setup', status: 'approved' }));
  const services = {
    operator: { getById: vi.fn(async () => ({ id: 'op_one', status: 'active', tier: 'enterprise' })) },
    agent: { getById: vi.fn(async () => ({ id: 'agt_finance', status: 'active', pubkey: { kty: 'OKP' } })) },
    serviceConnection: { getConnectionScoped: vi.fn(async () => ({
      id: 'scon_stripe', status: 'active', proxy_enabled: true, provider: 'stripe', member_id: null,
    })) },
    mission: { findById: vi.fn() },
    signer: { signAuthorityCeremony: vi.fn(async () => 'stack.signed.ceremony') },
    authority: {
      createPrincipal: vi.fn()
        .mockResolvedValueOnce({ id: 'prn_person' })
        .mockResolvedValueOnce({ id: 'prn_org' }),
      createProfileVersion,
      activateProfileVersion,
      importProof,
      createLegacyIdentityProofFacade: vi.fn(async () => ({ id: 'prf_identity_facade', version: 1 })),
      listReceivers: vi.fn(async () => []),
      createReceiver: vi.fn(async () => ({
        id: 'rcv_stripe', mode: 'proxy_bridge', status: 'pending',
        canonical_identifier: 'stack:service-connection:scon_stripe',
        current_profile_version_id: null,
      })),
      resolveAgentKeyThumbprint: vi.fn(async () => 'sha256:agent-key'),
      createBinding,
      createApprovalRequests: vi.fn(async () => [{
        id: 'apr_setup', status: 'pending', request_hash: `sha256:${'a'.repeat(64)}`,
      }]),
      decideApproval,
      activateBinding: vi.fn(async (..._args: unknown[]) => ({
        id: 'abn_setup', version: 1, status: 'active',
        expires_at: new Date(Date.now() + 20 * 60_000).toISOString(),
      })),
    },
  };
  return { services, createProfileVersion, importProof, createBinding, decideApproval };
}

describe('Enterprise OIDC Authority setup orchestration', () => {
  it('creates one active Authority from verified person, company role, exact job and connected system', async () => {
    const { services, createProfileVersion, createBinding, decideApproval } = fixture();
    const browserSession = { email: 'synthetic@test.invalid', ownerSessionRevision: 'verified-revision', expiresAt: Math.floor(Date.now() / 1000) + 60 };
    const result = await completeEnterpriseOidcAuthoritySetup({
      services: services as never,
      operatorId: 'op_one',
      workflowId: 'workflow_one',
      browserSession,
      author: { kind: 'operator_owner', operator_id: 'op_one' },
      request: {
        organisation_name: 'Example AB',
        role_name: 'Finance approver', role_claim_path: 'roles', role_claim_value: 'finance',
        agent_id: 'agt_finance', service_connection_id: 'scon_stripe', provider: 'stripe',
        purpose: 'Refund duplicate charges', http_method: 'POST', resource_path: '/v1/refunds',
        constraints: [{ path: 'body.amount', op: 'lte', value: 100 }],
        expires_at: new Date(Date.now() + 20 * 60_000),
      },
      evidence: {
        operator_id: 'op_one', config_id: 'oidc_one', id_token: 'provider.id.token', nonce: 'n'.repeat(43),
        payload: { iss: 'https://id.example.test', sub: 'person-one', roles: ['finance'] },
        signature_algorithm: 'RS256', issuer_key_thumbprint: 'sha256:idp-key',
        expires_at: new Date(Date.now() + 30 * 60_000),
      },
    });

    expect(result).toMatchObject({ binding_id: 'abn_setup', binding_status: 'active' });
    const profileInputs = createProfileVersion.mock.calls.map(
      (call) => call[1] as Record<string, any>,
    );
    const receiverProfile = profileInputs.find(
      (profile) => profile.profile_kind === 'receiver',
    );
    expect(receiverProfile?.config_json).toMatchObject({
      receiver_id: 'rcv_stripe', service_connection_id: 'scon_stripe',
      protocol: { key: 'stack.proxy_bridge', version: '1' },
    });
    expect(receiverProfile?.config_json).not.toHaveProperty('delivery');
    const domainProfile = profileInputs.find(
      (profile) => profile.profile_kind === 'domain',
    );
    expect(domainProfile?.config_json.actions[0].normalized_request_schema.properties).toMatchObject({
      method: { const: 'POST' },
      url: { properties: { pathname: { const: '/v1/refunds' } } },
    });
    const bindingInput = createBinding.mock.calls[0]?.[1] as Record<string, any>;
    expect(bindingInput.scope.actions[0].constraints).toEqual([
      { path: 'body.amount', op: 'lte', value: 100 },
    ]);
    expect(bindingInput.proofs.map((proof: { role: string }) => proof.role)).toEqual([
      'principal_identity', 'authoriser_identity', 'authoriser_capacity', 'mandate',
    ]);
    expect(decideApproval).toHaveBeenCalledOnce();
    expect(decideApproval.mock.calls[0]?.[5]).toBe(browserSession);
    expect(services.authority.activateBinding.mock.calls[0]?.[4]).toBe(browserSession);
  });

  it('refuses a setup whose requested lifetime outlasts the fresh IdP evidence', async () => {
    const { services, createProfileVersion } = fixture();
    await expect(completeEnterpriseOidcAuthoritySetup({
      services: services as never,
      operatorId: 'op_one', workflowId: 'workflow_expired',
      author: { kind: 'operator_owner', operator_id: 'op_one' },
      request: {
        organisation_name: 'Example AB', role_name: 'CFO',
        role_claim_path: 'roles', role_claim_value: 'cfo', agent_id: 'agt_finance',
        service_connection_id: 'scon_stripe', provider: 'stripe', purpose: 'Approve one payment',
        http_method: 'POST', resource_path: '/v1/payments', constraints: [],
        expires_at: new Date(Date.now() + 30 * 60_000),
      },
      evidence: {
        operator_id: 'op_one', config_id: 'oidc_one', id_token: 'provider.id.token', nonce: 'n'.repeat(43),
        payload: { iss: 'https://id.example.test', sub: 'person-one', roles: ['cfo'] },
        signature_algorithm: 'RS256', issuer_key_thumbprint: 'sha256:idp-key',
        expires_at: new Date(Date.now() + 20 * 60_000),
      },
    })).rejects.toThrow('lasts longer than the verified identity-provider session');
    expect(createProfileVersion).not.toHaveBeenCalled();
  });

  it('uses Stripe to verify the person and records the company role as customer-asserted', async () => {
    const { services, createProfileVersion, createBinding } = fixture();
    const browserSession = { email: 'member@test.invalid', memberId: 'mem_synthetic', expiresAt: Math.floor(Date.now() / 1000) + 60 };
    services.operator.getById.mockResolvedValue({ id: 'op_one', status: 'active', tier: 'free' });
    const result = await completeStripeIdentityAuthoritySetup({
      services: services as never,
      operatorId: 'op_one',
      workflowId: 'workflow_stripe',
      browserSession,
      author: { kind: 'operator_owner', operator_id: 'op_one' },
      request: {
        organisation_name: 'Example AB', role_name: 'Account owner',
        role_claim_path: 'roles', role_claim_value: 'owner', agent_id: 'agt_finance',
        service_connection_id: 'scon_stripe', provider: 'stripe', purpose: 'Refund duplicate charges',
        http_method: 'POST', resource_path: '/v1/refunds', constraints: [],
        expires_at: new Date(Date.now() + 20 * 60_000),
      },
      identityClaim: {
        id: 'idc_stripe', provider_key: 'stripe_identity', layer: 'identity',
        assurance_level: 'high', verified_at: new Date(),
        expires_at: new Date(Date.now() + 60 * 60_000), claim_id: 'pc_stripe_identity',
      },
    });

    expect(result).toMatchObject({ binding_id: 'abn_setup', binding_status: 'active' });
    expect(services.authority.decideApproval.mock.calls[0]?.[5]).toBe(browserSession);
    expect(services.authority.activateBinding.mock.calls[0]?.[4]).toBe(browserSession);
    expect(services.authority.createLegacyIdentityProofFacade).toHaveBeenCalledWith('op_one', {
      identity_claim_id: 'idc_stripe', subject_principal_id: 'prn_person', profile_version_id: expect.any(String),
    }, 'workflow_stripe:proof:identity');
    const profileInputs = createProfileVersion.mock.calls.map((call) => call[1] as Record<string, any>);
    const capacityProfile = profileInputs.find((profile) => profile.schema_uri === 'urn:stack:authority:customer-asserted-capacity');
    expect(capacityProfile).toMatchObject({
      adapter_key: 'stack_identity_authority',
      config_json: { assurance_mapping: {
        customer_asserted_capacity: 'urn:stack:assurance:customer-asserted-capacity',
      } },
    });
    const bindingInput = createBinding.mock.calls[0]?.[1] as Record<string, any>;
    expect(bindingInput.proofs.map((proof: { role: string }) => proof.role)).toContain('authoriser_capacity');
  });
});
