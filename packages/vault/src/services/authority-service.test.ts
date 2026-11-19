import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { AuthorityReceiverPresentationPayload, canonicalize, sha256 as rawSha256 } from '@stack/shared';
import {
  AuthorityApprovalCeremonyRejectedError,
  AuthorityService,
  authorityAgentKeyThumbprint,
  PinnedAuthorityApprovalDecisionVerifier,
  StackDirectPostJwtV1Protocol,
  STACK_DIRECT_POST_DELIVERY_MODE,
  STACK_DIRECT_POST_PROTOCOL_KEY,
  STACK_DIRECT_POST_PROTOCOL_VERSION,
  STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
  STACK_PROXY_BRIDGE_PROTOCOL_KEY,
  STACK_PROXY_BRIDGE_PROTOCOL_VERSION,
  type AuthorityBindingRecord,
  type AuthorityDbTransaction,
  type AuthorityProofRecord,
  type AuthorityProofProfileVersionRecord,
  type AuthorityPresentationRecord,
  type AuthorityRepositoryPort,
  type AuthorityReceiverRecord,
  type AuthorityServiceDeps,
  type AuthorityUseRecord,
} from './authority-service.js';
import { verifyPresentationAgentProof } from './authority/agent-proof.js';
import { assertDisclosurePolicySatisfiesReceiver } from './authority/binding-policy.js';
import { deduplicateProofRows } from './authority/disclosure.js';
import { createAuthorityModules } from './authority/modules.js';

const digest =`sha256:${'a'.repeat(64)}`;
const now = new Date('2026-08-21T10:00:00.000Z');
const wireDigest = (value: string) => `sha256:${rawSha256(value)}`;

function proofProfile(overrides: Partial<AuthorityProofProfileVersionRecord> = {}): AuthorityProofProfileVersionRecord {
  return {
    id: 'apv_profile', operator_id: 'op_test', proof_kind: 'identity', schema_uri: 'urn:test:id',
    schema_version: '1', adapter_key: 'test', adapter_version: 1, accepted_native_formats: ['test+jws'],
    status: 'active', content_hash: digest,
    config_json: {
      validation: { accepted_issuer_ids: ['issuer:good'], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: ['identity.id'] },
      freshness: { maximum_age_seconds: 3600, live_status_required: false },
    },
    ...overrides,
  };
}

function activeProof(overrides: Partial<AuthorityProofRecord> = {}): AuthorityProofRecord {
  return {
    id: 'prf_test', version: 1, operator_id: 'op_test', subject_principal_id: 'prn_subject',
    represented_principal_id: null, profile_version_id: 'apv_profile', proof_kind: 'identity',
    source_kind: 'external_native', legacy_identity_claim_id: null, issuer_identifier: 'issuer:good',
    issuer_key_thumbprint: digest, original_relying_party_identifier: null, schema_uri: 'urn:test:id',
    schema_version: '1', native_format: 'test+jws', native_evidence_encrypted: 'encrypted-native',
    normalized_facts_encrypted: 'encrypted-facts', native_evidence_hash: digest,
    normalized_facts_hash: digest, verification_method: 'jws', verifier_identifier: 'test',
    verifier_version: '1', assurance_uri: 'urn:test:assurance:high',
    verified_at: new Date(now.getTime() - 1_000), valid_from: new Date(now.getTime() - 1_000),
    expires_at: new Date(now.getTime() + 60_000), status: 'active',
    status_fresh_until: null, last_status_result: 'valid', last_status_checked_at: null,
    claim_id: 'pc_proof', created_at: now, revoked_at: null, revoked_reason: null,
    erased_at: null, tombstone_hash: null, tombstone_claim_id: null, supersedes_version: null,
    ...overrides,
  };
}

function serviceDeps(overrides: Partial<AuthorityServiceDeps>): AuthorityServiceDeps {
  const defaultKms = {
    encrypt: vi.fn(async (plaintext: string) => ({
      ciphertext: `test:${Buffer.from(plaintext, 'utf8').toString('base64url')}`,
      keyRef: 'test-key',
    })),
    decrypt: vi.fn(async (ciphertext: string) => Buffer.from(
      ciphertext.replace(/^test:/, ''), 'base64url',
    ).toString('utf8')),
  };
  return {
    repo: {} as AuthorityServiceDeps['repo'],
    kms: defaultKms,
    claimIssuer: {} as AuthorityServiceDeps['claimIssuer'],
    presentationProtocols: [new StackDirectPostJwtV1Protocol(
      { keyId: 'stack-test', algorithm: 'EdDSA', sign: vi.fn() },
      { deliver: vi.fn() },
    )],
    receiverRequestAudience: 'stack:test',
    passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
    now: () => now,
    ...overrides,
    legacyIdentityResolver: overrides.legacyIdentityResolver ?? { resolveFacts: vi.fn() },
  };
}

function service(overrides: Partial<AuthorityServiceDeps>): AuthorityService {
  return new AuthorityService(serviceDeps(overrides));
}

/** The modules behind the facade, for tests of internal guards. */
function modules(overrides: Partial<AuthorityServiceDeps>) {
  return createAuthorityModules(serviceDeps(overrides));
}

describe('AuthorityService security boundaries', () => {
  it.each(['skill', 'agent', 'dropoff'])('registers an owned internal %s receiver without external keys or a service connection', async kind => {
    let receiver: AuthorityReceiverRecord | null = null;
    let profile: Record<string, unknown> | null = null;
    const identifier = `stack:${kind}:target_1`;
    const owned = vi.fn(async (_operator: string, value: string) => value === identifier);
    const repo = {
      idempotent: async (_ledger: unknown, mutation: (value: unknown) => Promise<unknown>) => mutation(repo),
      isOwnedInternalReceiver: owned,
      findManagedReceiverByCanonicalId: vi.fn(async () => null),
      insertReceiver: vi.fn(async (row: AuthorityReceiverRecord) => { receiver = row; return row; }),
      findReceiver: vi.fn(async () => receiver),
      insertProfileVersion: vi.fn(async (row: Record<string, unknown>) => { profile = { ...row, id: 'apv_internal' }; return profile; }),
      findProfileVersion: vi.fn(async () => profile),
      activateProfileVersion: vi.fn(async () => ({ ...profile, status: 'active' })),
    };
    const sut = service({ repo: repo as unknown as AuthorityRepositoryPort });
    const created = await sut.createReceiver('op_test', { mode: 'internal', canonical_identifier: identifier, display_name: 'Internal' }, 'internal-one');
    expect(created.verified_at).toBe(now.toISOString());
    const input = { profile_kind: 'receiver' as const, profile_key: 'internal', version: 1, schema_uri: 'urn:stack:internal', schema_version: '1', adapter_key: 'stack.internal_runtime', adapter_version: 1, receiver_id: created.id,
      config_json: { receiver_id: created.id, protocol: { key: 'stack.internal_runtime' as const, version: '1' as const }, audience: 'stack:test', canonical_identifier: identifier, approval_policy: { version: '1', groups: [] }, live_status_required: true as const } };
    await sut.createProfileVersion('op_test', input, 'profile-one');
    await expect(sut.activateProfileVersion('op_test', 'receiver', 'apv_internal', 'activate')).resolves.toMatchObject({ status: 'active' });
    await expect(sut.createProfileVersion('op_test', { ...input, config_json: { ...input.config_json, canonical_identifier: 'stack:agent:foreign' } }, 'bad-profile')).rejects.toThrow();
    await expect(sut.createReceiver('op_test', { mode: 'internal', canonical_identifier: 'stack:agent:foreign', display_name: 'Foreign' }, 'foreign')).rejects.toThrow();
    owned.mockResolvedValue(false);
    await expect(sut.activateProfileVersion('op_test', 'receiver', 'apv_internal', 'activate-after-revoke')).rejects.toThrow();
  });
  it('pages agent authority and exposes only exact binding proof references and safe metadata', async () => {
    const binding = {
      id: 'abn_one', version: 2, operator_id: 'op_test', agent_id: 'agt_one',
      principal_id: 'apr_one', receiver_id: 'arc_one', status: 'revoked',
      valid_from: now, expires_at: now, created_at: now,
      activated_at: null, revoked_at: now, mission_ids: ['msn_historical'],
      purpose_encrypted: 'NEVER EXPOSE',
    } as unknown as AuthorityBindingRecord;
    const listAgentBindings = vi.fn(async () => ({
      bindings: [binding], has_more: true, principals: [], receivers: [], proofs: [activeProof({ id: 'prf_identity' })],
      links: [
        { binding_id: 'abn_one', binding_version: 1, proof_id: 'old-version', proof_version: 1 },
        { binding_id: 'abn_other', binding_version: 2, proof_id: 'other-binding', proof_version: 1 },
        { binding_id: 'abn_one', binding_version: 2, proof_id: 'prf_identity', proof_version: 1,
          role: 'identity', group_key: 'identity', weight: 1, required: true, ordinal: 0 },
      ],
    }));
    const sut = service({ repo: { listAgentBindings } as unknown as AuthorityRepositoryPort });
    const result = await sut.listAgentBindings('op_test', 'agt_one', 3, 10);
    expect(listAgentBindings).toHaveBeenCalledWith('op_test', 'agt_one', 3, 10, undefined);
    expect(result).toMatchObject({ page: 3, limit: 10, has_more: true });
    expect(result.items[0]!.status).toBe('revoked');
    expect(result.items[0]!.mission_ids).toEqual(['msn_historical']);
    expect(result.items[0]!.proof_refs).toHaveLength(1);
    expect(result.items[0]!.proof_refs[0]!.proof_id).toBe('prf_identity');
    expect(JSON.stringify(result)).not.toMatch(/encrypted|NEVER EXPOSE/);
    expect(result.proofs[0]!.proof_kind).toBe('identity');
  });

  it('rejects unbounded agent authority pagination before reading', async () => {
    const listAgentBindings = vi.fn();
    const sut = service({ repo: { listAgentBindings } as unknown as AuthorityRepositoryPort });
    for (const [page, limit] of [[0, 20], [1, 51], [1.5, 20], [100_001, 20]]) {
      await expect(sut.listAgentBindings('op_test', 'agt_one', page!, limit!)).rejects.toThrow('invalid authority page');
    }
    expect(listAgentBindings).not.toHaveBeenCalled();
  });

  it('projects use and presentation history without disclosing native payloads', async () => {
    const listAgentAuthorityUses = vi.fn(async () => ({
      uses: [{ id: 'ause_one', binding_id: 'abn_one', binding_version: 2, agent_id: 'agt_one',
        status: 'denied', denial_code: 'scope_denied', created_at: now,
        normalized_request: { private: 'not for browser' } }],
      presentations: [{ id: 'aprs_one', authority_use_id: 'ause_one', status: 'expired',
        proof_refs: [{ id: 'prf_exact', version: 3 }], expires_at: now,
        native_evidence: 'not for browser', disclosure_manifest: [] }],
      has_more: false,
    }));
    const sut = service({ repo: { listAgentAuthorityUses } as unknown as AuthorityRepositoryPort });
    const result = await sut.listAgentAuthorityUses('op_test', 'agt_one', 1, 20, { id: 'abn_one', version: 2 });
    expect(listAgentAuthorityUses).toHaveBeenCalledWith('op_test', 'agt_one', 1, 20, { id: 'abn_one', version: 2 });
    expect(result.items[0]!.denial_code).toBe('scope_denied');
    expect(result.presentations[0]!.proof_refs).toEqual([{ proof_id: 'prf_exact', proof_version: 3 }]);
    expect(JSON.stringify(result)).not.toMatch(/native_evidence|normalized_request|not for browser/);
  });

  it('activates a proxy receiver only for an owned connection and an exact bridge profile', async () => {
    let receiver: AuthorityReceiverRecord | null = null;
    let profile: Record<string, unknown> | null = null;
    const repo = {
      idempotent: async (_ledger: unknown, mutation: (value: unknown) => Promise<unknown>) => mutation(repo),
      isOwnedActiveServiceConnection: vi.fn(async (_operatorId: string, connectionId: string) => connectionId === 'scon_stripe'),
      findManagedReceiverByCanonicalId: vi.fn(async () => null),
      insertReceiver: vi.fn(async (row: AuthorityReceiverRecord) => {
        receiver = row;
        return row;
      }),
      findReceiver: vi.fn(async () => receiver),
      insertProfileVersion: vi.fn(async (row: Record<string, unknown>) => {
        profile = { ...row, id: 'apv_proxy' };
        return profile;
      }),
      findProfileVersion: vi.fn(async () => profile),
      activateProfileVersion: vi.fn(async () => ({ ...profile, status: 'active' })),
    } as unknown as AuthorityRepositoryPort;
    const sut = service({ repo });

    const created = await sut.createReceiver('op_test', {
      mode: 'proxy_bridge',
      canonical_identifier: 'stack:service-connection:scon_stripe',
      display_name: 'Stripe',
      proxy_service_connection_id: 'scon_stripe',
    }, 'receiver-one');
    expect(created.verified_at).toBe(now.toISOString());
    expect(created.status).toBe('pending');

    const config = {
      receiver_id: created.id,
      protocol: {
        key: STACK_PROXY_BRIDGE_PROTOCOL_KEY,
        version: STACK_PROXY_BRIDGE_PROTOCOL_VERSION,
      } as const,
      audience: 'stack:service-connection:scon_stripe',
      service_connection_id: 'scon_stripe',
      approval_policy: { version: '1', groups: [] },
      live_status_required: true as const,
    };
    await sut.createProfileVersion('op_test', {
      profile_kind: 'receiver',
      profile_key: 'stripe-proxy',
      version: 1,
      schema_uri: 'urn:stack:authority:receiver:proxy-bridge',
      schema_version: '1',
      adapter_key: STACK_PROXY_BRIDGE_PROTOCOL_KEY,
      adapter_version: 1,
      receiver_id: created.id,
      config_json: config,
    }, 'profile-one');
    await expect(sut.activateProfileVersion('op_test', 'receiver', 'apv_proxy', 'activate-one'))
      .resolves.toMatchObject({ status: 'active' });

    await expect(sut.createProfileVersion('op_test', {
      profile_kind: 'receiver', profile_key: 'bad-proxy', version: 1,
      schema_uri: 'urn:stack:authority:receiver:proxy-bridge', schema_version: '1',
      adapter_key: STACK_PROXY_BRIDGE_PROTOCOL_KEY, adapter_version: 1,
      receiver_id: created.id,
      config_json: { ...config, delivery: { endpoint: 'https://invented.example' } },
    } as never, 'profile-bad')).rejects.toThrow('receiver profile is incompatible with stack.proxy_bridge/v1');
  });

  it.each([
    ['protocol key', { protocol: { key: 'other.protocol', version: STACK_DIRECT_POST_PROTOCOL_VERSION } }],
    ['protocol version', { protocol: { key: STACK_DIRECT_POST_PROTOCOL_KEY, version: '2' } }],
    ['request auth method', { request_authentication: { method: 'bearer', signing_key_ids: ['key-1'], allowed_algs: ['EdDSA'] } }],
    ['delivery mode', { delivery: { mode: 'plaintext', allowed_key_management_algs: ['ECDH-ES+A256KW'], allowed_content_encryption_algs: ['A256GCM'] } }],
    ['request algorithm', { request_authentication: { method: STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
      signing_key_ids: ['key-1'], allowed_algs: ['RS256'] } }],
    ['receipt algorithm', { receipt: { signing_key_ids: ['receipt-key'], allowed_algs: ['RS256'] } }],
    ['key-management algorithm', { delivery: { mode: STACK_DIRECT_POST_DELIVERY_MODE,
      allowed_key_management_algs: ['RSA-OAEP'], allowed_content_encryption_algs: ['A256GCM'] } }],
    ['content-encryption algorithm', { delivery: { mode: STACK_DIRECT_POST_DELIVERY_MODE,
      allowed_key_management_algs: ['ECDH-ES+A256KW'], allowed_content_encryption_algs: ['A128CBC-HS256'] } }],
  ])('rejects a receiver profile with mismatched %s', (_label, override) => {
    const base = {
      protocol: { key: STACK_DIRECT_POST_PROTOCOL_KEY, version: STACK_DIRECT_POST_PROTOCOL_VERSION },
      request_authentication: { method: STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
        signing_key_ids: ['key-1'], allowed_algs: ['EdDSA'] },
      approval_policy: { version: '1', groups: [] },
      delivery: { mode: STACK_DIRECT_POST_DELIVERY_MODE,
        allowed_key_management_algs: ['ECDH-ES+A256KW'], allowed_content_encryption_algs: ['A256GCM'] },
    };
    const protocol = new StackDirectPostJwtV1Protocol(
      { keyId: 'stack-test', algorithm: 'EdDSA', sign: vi.fn() }, { deliver: vi.fn() },
    );
    expect(() => protocol.validateProfile({ ...base, ...override })).toThrow('incompatible');
  });

  it.each([
    ['missing version', { groups: [] }],
    ['unknown field', { version: '1', groups: [], permissive: true }],
    ['unknown group field', { version: '1', groups: [{ phase: 'action', group_key: 'owner',
      required_weight: 1, reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: false,
      permissive: true }] }],
  ])('rejects malformed approval policy: %s', (_label, approvalPolicy) => {
    const protocol = new StackDirectPostJwtV1Protocol(
      { keyId: 'stack-test', algorithm: 'EdDSA', sign: vi.fn() }, { deliver: vi.fn() },
    );
    expect(() => protocol.validateProfile({
      protocol: { key: STACK_DIRECT_POST_PROTOCOL_KEY, version: STACK_DIRECT_POST_PROTOCOL_VERSION },
      request_authentication: { method: STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
        signing_key_ids: ['key-1'], allowed_algs: ['EdDSA'] },
      delivery: { mode: STACK_DIRECT_POST_DELIVERY_MODE,
        allowed_key_management_algs: ['ECDH-ES+A256KW'], allowed_content_encryption_algs: ['A256GCM'] },
      approval_policy: approvalPolicy,
    })).toThrow('approval policy');
  });

  it('requires receiver facts, retention limits, and principal confirmation in the binding policy', () => {
    const assertPolicy = assertDisclosurePolicySatisfiesReceiver as unknown as (
      disclosure: Record<string, unknown>, approval: Record<string, unknown>, receiver: Record<string, unknown>
    ) => void;
    const receiver = { required_facts: [{ fact_id: 'person.name', allowed_modes: ['exact_private'],
      retention_rule: { maximum_seconds: 3600 } }] };
    expect(() => assertPolicy({ rules: [], principal_confirmation_required: false,
      max_retention_seconds: 3600, live_status_required: false }, { version: '1', groups: [] }, receiver))
      .toThrow('pinned receiver facts');
    expect(() => assertPolicy({ rules: [{ fact_id: 'person.name', mode: 'exact_private', required: true }],
      principal_confirmation_required: false, max_retention_seconds: 60, live_status_required: false },
    { version: '1', groups: [] }, receiver)).toThrow('retention exceeds');
    expect(() => assertPolicy({ rules: [{ fact_id: 'person.name', mode: 'exact_private', required: true }],
      principal_confirmation_required: true, max_retention_seconds: 3600, live_status_required: false },
    { version: '1', groups: [] }, receiver)).toThrow('final presentation approval');
    expect(() => assertPolicy({ rules: [{ fact_id: 'person.name', mode: 'exact_private', required: true }],
      principal_confirmation_required: true, max_retention_seconds: 3600, live_status_required: false },
    { version: '1', groups: [{ phase: 'presentation', group_key: 'owner', required_weight: 1,
      reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: true }] }, receiver)).not.toThrow();
  });

  it('rejects a 1-of-2 approval requirement masquerading as satisfied presentation evidence', () => {
    const payload = {
      iss: 'https://getstack.run', aud: 'https://receiver.example', jti: 'pjt_test', iat: 1, exp: 120,
      authority_use_id: 'aus_test', agent_id: 'agt_test', agent_key_thumbprint: digest,
      binding_ref: { binding_id: 'abn_test', binding_version: 1, binding_claim_id: 'pc_binding',
        binding_digest: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver', expires_at: 120 },
      principal_ref: 'prn_test', mission_id: null, action_uri: 'urn:test:act', resource_hash: null,
      request_hash: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
      domain_profile_version_id: null, proof_profile_version_ids: ['apv_proof'], live_check_time: 1,
      evidence_refs: [{ proof_id: 'prf_test', proof_version: 1, role: 'mandate',
        authoriser_principal_id: 'prn_test', group_key_hash: digest, profile_version_id: 'apv_proof',
        issuer_identifier: 'issuer:test', schema_uri: 'urn:test', schema_version: '1', assurance_uri: null,
        evidence_digest: digest, evidence_modes: ['none'], status: 'active' }],
      approval_claim_refs: [{ claim_id: 'pc_decision', claim_hash: digest, phase: 'presentation' }],
      approval_requirements: [{ phase: 'presentation', group_key_hash: digest, required_weight: 2,
        collected_weight: 1, reject_mode: 'any_reject', request_hash: digest,
        approval_requirement_hash: digest, status: 'satisfied',
        decision_claim_refs: [{ claim_id: 'pc_decision', claim_hash: digest }] }],
      proof_strength: 'native_stack_attestation', nonce: 'A'.repeat(22), disclosed_facts: [],
    };
    expect(AuthorityReceiverPresentationPayload.safeParse(payload).success).toBe(false);
    payload.approval_requirements[0]!.collected_weight = 2;
    expect(AuthorityReceiverPresentationPayload.safeParse(payload).success).toBe(true);
  });

  it('rejects an adapter that verifies a different issuer than the pinned import', async () => {
    const profile: AuthorityProofProfileVersionRecord = {
      id: 'apv_profile', operator_id: 'op_test', proof_kind: 'identity', schema_uri: 'urn:test:id',
      schema_version: '1', adapter_key: 'test', adapter_version: 1, accepted_native_formats: ['test+jws'],
      status: 'active', content_hash: digest,
      config_json: { validation: { accepted_issuer_ids: ['issuer:good'], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: [] }, freshness: { maximum_age_seconds: 3600, live_status_required: false } },
    };
    const claims = { registerExternalProofVerificationClaim: vi.fn() };
    const sut = service({
      repo: {
        idempotent: async (_input: unknown, mutation: (repo: AuthorityRepositoryPort) => Promise<unknown>) => mutation({
          findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
          findProofProfileVersion: async () => profile,
          currentTransaction: () => undefined,
        } as unknown as AuthorityServiceDeps['repo']),
      } as unknown as AuthorityServiceDeps['repo'],
      adapters: [{
        key: 'test', version: 1,
        verify: async () => ({ normalizedFacts: {}, issuerIdentifier: 'issuer:evil', verificationMethod: 'jws',
          verifierIdentifier: 'test', verifierVersion: '1', verifiedAt: now, validFrom: now,
          signatureVerified: true, subjectPrincipalId: 'prn_subject' }),
      }],
      claimIssuer: claims as unknown as AuthorityServiceDeps['claimIssuer'],
    });
    await expect(sut.importProof('op_test', {
      subject_principal_id: 'prn_subject', profile_version_id: 'apv_profile', proof_kind: 'identity',
      issuer_identifier: 'issuer:good', schema_uri: 'urn:test:id', schema_version: '1', native_format: 'test+jws',
      native_evidence: 'signed',
    }, 'idem')).rejects.toThrow('issuer mismatch');
    expect(claims.registerExternalProofVerificationClaim).not.toHaveBeenCalled();
  });

  it('rejects an issuer that is not accepted by the immutable proof profile', async () => {
    const profile = proofProfile({ config_json: {
      validation: { accepted_issuer_ids: ['issuer:approved'], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: [] },
      freshness: { maximum_age_seconds: 3600, live_status_required: false },
    } });
    const claims = { registerExternalProofVerificationClaim: vi.fn() };
    const sut = service({
      repo: {
        idempotent: async (_input: unknown, mutation: (repo: AuthorityRepositoryPort) => Promise<unknown>) => mutation({
          findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
          findProofProfileVersion: async () => profile,
          currentTransaction: () => undefined,
        } as unknown as AuthorityServiceDeps['repo']),
      } as unknown as AuthorityServiceDeps['repo'],
      adapters: [{ key: 'test', version: 1, verify: async () => ({ normalizedFacts: {},
        issuerIdentifier: 'issuer:good', verificationMethod: 'jws', verifierIdentifier: 'test',
        verifierVersion: '1', verifiedAt: now, validFrom: now, signatureVerified: true,
        signatureAlgorithm: 'EdDSA', subjectPrincipalId: 'prn_subject' }) }],
      claimIssuer: claims as unknown as AuthorityServiceDeps['claimIssuer'],
    });
    await expect(sut.importProof('op_test', {
      subject_principal_id: 'prn_subject', profile_version_id: profile.id, proof_kind: 'identity',
      issuer_identifier: 'issuer:good', schema_uri: profile.schema_uri, schema_version: profile.schema_version,
      native_format: 'test+jws', native_evidence: 'signed',
    }, 'idem')).rejects.toThrow('not accepted');
    expect(claims.registerExternalProofVerificationClaim).not.toHaveBeenCalled();
  });

  it.each([
    ['unsigned evidence', { signatureVerified: false, signatureAlgorithm: undefined }, 'signature was not verified'],
    ['wrong signature algorithm', { signatureVerified: true, signatureAlgorithm: 'RS256' }, 'algorithm is not accepted'],
    ['wrong subject', { subjectPrincipalId: 'prn_attacker' }, 'subject binding mismatch'],
    ['missing required claim', { normalizedFacts: {} }, 'requested proof fact is unavailable'],
    ['stale verification', { verifiedAt: new Date(now.getTime() - 3_601_000) }, 'older than'],
    ['future validity', { validFrom: new Date(now.getTime() + 1_000) }, 'not yet valid'],
    ['expired validity', { expiresAt: new Date(now.getTime() - 1) }, 'is expired'],
  ])('rejects %s before signing or persistence', async (_label, verifiedOverride, message) => {
    const profile = proofProfile();
    const claims = { registerExternalProofVerificationClaim: vi.fn() };
    const insertProof = vi.fn();
    const sut = service({
      repo: {
        idempotent: async (_input: unknown, mutation: (repo: AuthorityRepositoryPort) => Promise<unknown>) => mutation({
          findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
          findProofProfileVersion: async () => profile,
          insertProof,
          currentTransaction: () => undefined,
        } as unknown as AuthorityServiceDeps['repo']),
      } as unknown as AuthorityServiceDeps['repo'],
      adapters: [{
        key: 'test', version: 1,
        verify: async () => ({ normalizedFacts: { identity: { id: 'subject' } }, issuerIdentifier: 'issuer:good',
          verificationMethod: 'jws', verifierIdentifier: 'test', verifierVersion: '1', verifiedAt: now,
          validFrom: now, signatureVerified: true, signatureAlgorithm: 'EdDSA',
          subjectPrincipalId: 'prn_subject', ...verifiedOverride }),
      }],
      claimIssuer: claims as unknown as AuthorityServiceDeps['claimIssuer'],
    });
    await expect(sut.importProof('op_test', {
      subject_principal_id: 'prn_subject', profile_version_id: profile.id, proof_kind: 'identity',
      issuer_identifier: 'issuer:good', schema_uri: profile.schema_uri, schema_version: profile.schema_version,
      native_format: 'test+jws', native_evidence: 'signed',
    }, 'idem')).rejects.toThrow(message);
    expect(claims.registerExternalProofVerificationClaim).not.toHaveBeenCalled();
    expect(insertProof).not.toHaveBeenCalled();
  });

  it('rejects a schema/profile mismatch before calling the proof adapter', async () => {
    const verify = vi.fn();
    const sut = service({
      repo: {
        idempotent: async (_input: unknown, mutation: (repo: AuthorityRepositoryPort) => Promise<unknown>) => mutation({
          findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
          findProofProfileVersion: async () => proofProfile(),
        } as unknown as AuthorityServiceDeps['repo']),
      } as unknown as AuthorityServiceDeps['repo'],
      adapters: [{ key: 'test', version: 1, verify }],
    });
    await expect(sut.importProof('op_test', {
      subject_principal_id: 'prn_subject', profile_version_id: 'apv_profile', proof_kind: 'identity',
      issuer_identifier: 'issuer:good', schema_uri: 'urn:test:attacker-schema', schema_version: '1',
      native_format: 'test+jws', native_evidence: 'signed',
    }, 'idem')).rejects.toThrow('immutable profile');
    expect(verify).not.toHaveBeenCalled();
  });

  it('uses a nonce-bound facts commitment so predictable personal numbers cannot be dictionary-matched', async () => {
    const facts = { person: { personal_number: '199001011234' } };
    const encryptedPlaintexts: string[] = [];
    let inserted: AuthorityProofRecord | null = null;
    const profile = proofProfile({ config_json: {
      validation: { accepted_issuer_ids: ['issuer:good'], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: ['person.personal_number'] },
      freshness: { maximum_age_seconds: 3600, live_status_required: false },
    } });
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
      findProofProfileVersion: async () => profile,
      currentTransaction: () => undefined,
      insertProof: async (row: AuthorityProofRecord) => { inserted = row; return row; },
    } as unknown as AuthorityRepositoryPort;
    const claimIssuer = {
      registerExternalProofVerificationClaim: async () => ({ claimId: 'pc_proof', claimHash: digest }),
    } as unknown as AuthorityServiceDeps['claimIssuer'];
    const sut = service({
      repo,
      kms: {
        encrypt: vi.fn(async (plaintext: string) => {
          encryptedPlaintexts.push(plaintext);
          return { ciphertext: `encrypted-${encryptedPlaintexts.length}`, keyRef: 'test-key' };
        }),
        decrypt: vi.fn(),
      },
      adapters: [{ key: 'test', version: 1, verify: async () => ({ normalizedFacts: facts,
        issuerIdentifier: 'issuer:good', verificationMethod: 'jws', verifierIdentifier: 'test',
        verifierVersion: '1', verifiedAt: now, validFrom: now, signatureVerified: true,
        signatureAlgorithm: 'EdDSA', subjectPrincipalId: 'prn_subject' }) }],
      claimIssuer,
    });
    const view = await sut.importProof('op_test', {
      subject_principal_id: 'prn_subject', profile_version_id: profile.id, proof_kind: 'identity',
      issuer_identifier: 'issuer:good', schema_uri: profile.schema_uri, schema_version: profile.schema_version,
      native_format: 'test+jws', native_evidence: 'signed',
    }, 'idem');
    const unkeyedDictionaryHash = wireDigest(canonicalize(facts));
    expect(inserted!.normalized_facts_hash).not.toBe(unkeyedDictionaryHash);
    const envelope = encryptedPlaintexts.flatMap((value) => {
      try { return [JSON.parse(value) as Record<string, unknown>]; } catch { return []; }
    }).find((value) => Object.prototype.hasOwnProperty.call(value, 'facts'))!;
    expect(envelope).toMatchObject({ facts });
    expect(String(envelope.commitment_nonce)).toMatch(/^[A-Za-z0-9_-]{22,}$/);
    expect(JSON.stringify(view)).not.toContain('199001011234');
    expect(JSON.stringify(view)).not.toContain(String(envelope.commitment_nonce));
  });

  it.each([
    ['revoked proof', { status: 'revoked' as const }, 'is revoked'],
    ['expired proof', { expires_at: new Date(now.getTime() - 1) }, 'expired'],
    ['future proof', { valid_from: new Date(now.getTime() + 1) }, 'not yet valid'],
    ['issuer-revoked proof', { last_status_result: 'revoked' as const }, 'revoked by its issuer'],
  ])('fails closed for a %s at use time', async (_label, proofOverride, message) => {
    const call = modules({}).guards;
    const repo = { findProofProfileVersion: async () => proofProfile() } as unknown as AuthorityRepositoryPort;
    await expect(call.assertProofUsable(repo, activeProof(proofOverride), now)).rejects.toThrow(message);
  });

  it('fails closed when a live-status proof is unknown or stale', async () => {
    const liveProfile = proofProfile({ config_json: {
      validation: { accepted_issuer_ids: ['issuer:good'], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: [] },
      freshness: { maximum_age_seconds: 3600, live_status_required: true },
    } });
    const call = modules({}).guards;
    const repo = { findProofProfileVersion: async () => liveProfile } as unknown as AuthorityRepositoryPort;
    await expect(call.assertProofUsable(repo, activeProof({ last_status_result: null,
      last_status_checked_at: null, status_fresh_until: null }), now)).rejects.toThrow('live status');
    await expect(call.assertProofUsable(repo, activeProof({ last_status_result: 'valid',
      last_status_checked_at: new Date(now.getTime() - 60_000), status_fresh_until: now }), now)).rejects.toThrow('live status');
  });

  it('resolves sensitive value_ref constraints in memory and fails closed on mismatch or ambiguity', async () => {
    const personalNumber = '199001011234';
    const factsEnvelope = canonicalize({ facts: { person: { personal_number: personalNumber } },
      commitment_nonce: 'AAAAAAAAAAAAAAAAAAAAAA' });
    const proof = activeProof({ normalized_facts_encrypted: 'facts', normalized_facts_hash: wireDigest(factsEnvelope) });
    const profile = proofProfile({ config_json: {
      validation: { accepted_issuer_ids: ['issuer:good'], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: [] },
      freshness: { maximum_age_seconds: 3600, live_status_required: false },
      disclosable_facts: [{ fact_id: 'person.personal_number', native_path: 'person.personal_number',
        allowed_modes: ['exact_private'] }],
    } });
    let links = [{ proof_id: proof.id, proof_version: proof.version }];
    const repo = {
      listBindingProofs: async () => links,
      findProof: async () => proof,
      findProofProfileVersion: async () => profile,
    } as unknown as AuthorityRepositoryPort;
    const { evaluation } = modules({ repo, kms: { encrypt: vi.fn(), decrypt: vi.fn(async () => factsEnvelope) } });
    const check = evaluation.constraintsPermit.bind(evaluation) as unknown as (repo: AuthorityRepositoryPort,
      binding: AuthorityBindingRecord, constraints: Array<Record<string, unknown>>,
      normalizedRequest: unknown) => Promise<boolean>;
    const binding = { id: 'abn_test', version: 1, operator_id: 'op_test' } as AuthorityBindingRecord;
    const constraints = [{ path: 'taxpayer_id', op: 'eq', value_ref: 'person.personal_number' }];
    await expect(check(repo, binding, constraints, { taxpayer_id: personalNumber })).resolves.toBe(true);
    await expect(check(repo, binding, constraints, { taxpayer_id: '199001011235' })).resolves.toBe(false);
    links = [{ proof_id: proof.id, proof_version: 1 }, { proof_id: 'prf_second', proof_version: 1 }];
    await expect(check(repo, binding, constraints, { taxpayer_id: personalNumber })).resolves.toBe(false);
    expect(JSON.stringify({ binding, constraints })).not.toContain(personalNumber);
  });

  it('enforces the mandatory identity, authoriser, and mandate roles inside the service boundary', async () => {
    const repo = {
      idempotent: async (_input: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_org', kind: 'organisation', status: 'active' }),
      resolveCurrentAgentKey: async () => ({ thumbprint: digest, active: true }),
      findReceiver: async () => ({ id: 'rcv_test', status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: 'rcv_test', status: 'active',
        config_json: { approval_policy: { version: '1', groups: [] } } }),
    } as unknown as AuthorityRepositoryPort;
    const sut = service({ repo });
    await expect(sut.createBinding('op_test', {
      principal_id: 'prn_org', agent_id: 'agt_test', receiver_id: 'rcv_test',
      receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: null, mission_ids: [],
      purpose_code: 'tax.submit', purpose_statement: null,
      scope: { actions: [], limits: {} }, approval_policy: { version: '1', groups: [] },
      disclosure_policy: { rules: [], principal_confirmation_required: false,
        max_retention_seconds: 0, live_status_required: false },
      delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
      valid_from: now, expires_at: new Date(now.getTime() + 60_000), proofs: [],
    } as never, 'idem')).rejects.toThrow('required principal_identity');
  });

  it('requires capacity evidence when a human authorises for an organisation', async () => {
    const input = {
      principal_id: 'prn_org', agent_id: 'agt_test', receiver_id: 'rcv_test',
      receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: null, mission_ids: [],
      purpose_code: 'tax.submit', purpose_statement: null,
      scope: { actions: [], limits: {} }, approval_policy: { version: '1', groups: [] },
      disclosure_policy: { rules: [], principal_confirmation_required: false,
        max_retention_seconds: 0, live_status_required: false },
      delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
      valid_from: now, expires_at: new Date(now.getTime() + 60_000),
      proofs: [
        { proof_id: 'prf_principal', proof_version: 1, role: 'principal_identity',
          authoriser_principal_id: null, group_key: null, weight: 1, required: true, ordinal: 0 },
        { proof_id: 'prf_authoriser', proof_version: 1, role: 'authoriser_identity',
          authoriser_principal_id: 'prn_human', group_key: 'owners', weight: 1, required: true, ordinal: 1 },
        { proof_id: 'prf_mandate', proof_version: 1, role: 'mandate',
          authoriser_principal_id: 'prn_human', group_key: 'owners', weight: 1, required: true, ordinal: 2 },
      ],
    };
    const termsDigest = wireDigest(canonicalize({
      principal_id: input.principal_id, authoriser_principal_ids: ['prn_human'], agent_id: input.agent_id,
      agent_key_thumbprint: digest, receiver_id: input.receiver_id,
      receiver_profile_version_id: input.receiver_profile_version_id, domain_profile_version_id: null,
      mission_ids: [], purpose_code: input.purpose_code, purpose_statement: null, scope: input.scope,
      approval_policy: input.approval_policy, disclosure_policy: input.disclosure_policy,
      delegation_policy: input.delegation_policy, valid_from: input.valid_from.toISOString(),
      expires_at: input.expires_at.toISOString(),
    }));
    const mandateEnvelope = canonicalize({
      facts: { mandate_terms_digest: termsDigest }, commitment_nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    });
    const proofs = new Map([
      ['prf_principal', activeProof({ id: 'prf_principal', subject_principal_id: 'prn_org' })],
      ['prf_authoriser', activeProof({ id: 'prf_authoriser', subject_principal_id: 'prn_human' })],
      ['prf_mandate', activeProof({ id: 'prf_mandate', proof_kind: 'mandate',
        subject_principal_id: 'prn_human', normalized_facts_encrypted: 'mandate-facts',
        normalized_facts_hash: wireDigest(mandateEnvelope) })],
    ]);
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_org', kind: 'organisation', status: 'active' }),
      resolveCurrentAgentKey: async () => ({ thumbprint: digest, active: true }),
      findReceiver: async () => ({ id: 'rcv_test', status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: 'rcv_test', status: 'active',
        config_json: { approval_policy: { version: '1', groups: [] } } }),
      findProof: async (_operatorId: string, proofId: string) => proofs.get(proofId) ?? null,
      findProofProfileVersion: async () => proofProfile(),
    } as unknown as AuthorityRepositoryPort;
    const sut = service({ repo, kms: {
      encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `encrypted:${plaintext}`, keyRef: 'test-key' })),
      decrypt: vi.fn(async (ciphertext: string) => ciphertext === 'mandate-facts'
        ? mandateEnvelope : '{}'),
    } });
    await expect(sut.createBinding('op_test', input as never, 'idem')).rejects.toThrow('capacity proof');
  });

  it('nonce-binds every encrypted binding value so personal data cannot be dictionary-matched', async () => {
    const personalNumber = '199001011234';
    const input = {
      principal_id: 'prn_subject', agent_id: 'agt_test', receiver_id: 'rcv_test',
      receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: null, mission_ids: [],
      purpose_code: 'tax.submit', purpose_statement: `File return for ${personalNumber}`,
      scope: { actions: [{ action_uri: 'urn:tax:submit', resource_refs: [],
        constraints: [{ path: 'person.personal_number', op: 'eq', value: personalNumber }] }], limits: {} },
      approval_policy: { version: '1', groups: [] },
      disclosure_policy: { rules: [], principal_confirmation_required: false,
        max_retention_seconds: 0, live_status_required: false },
      delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
      valid_from: now, expires_at: new Date(now.getTime() + 60_000),
      proofs: [
        { proof_id: 'prf_principal', proof_version: 1, role: 'principal_identity',
          authoriser_principal_id: null, group_key: null, weight: 1, required: true, ordinal: 0 },
        { proof_id: 'prf_authoriser', proof_version: 1, role: 'authoriser_identity',
          authoriser_principal_id: 'prn_subject', group_key: null, weight: 1, required: true, ordinal: 1 },
        { proof_id: 'prf_mandate', proof_version: 1, role: 'mandate',
          authoriser_principal_id: 'prn_subject', group_key: null, weight: 1, required: true, ordinal: 2 },
      ],
    };
    const termsDigest = wireDigest(canonicalize({
      principal_id: input.principal_id, authoriser_principal_ids: ['prn_subject'], agent_id: input.agent_id,
      agent_key_thumbprint: digest, receiver_id: input.receiver_id,
      receiver_profile_version_id: input.receiver_profile_version_id, domain_profile_version_id: null,
      mission_ids: [], purpose_code: input.purpose_code, purpose_statement: input.purpose_statement,
      scope: input.scope, approval_policy: input.approval_policy, disclosure_policy: input.disclosure_policy,
      delegation_policy: input.delegation_policy, valid_from: input.valid_from.toISOString(),
      expires_at: input.expires_at.toISOString(),
    }));
    const mandateEnvelope = canonicalize({
      facts: { mandate_terms_digest: termsDigest }, commitment_nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    });
    const proofs = new Map([
      ['prf_principal', activeProof({ id: 'prf_principal' })],
      ['prf_authoriser', activeProof({ id: 'prf_authoriser' })],
      ['prf_mandate', activeProof({ id: 'prf_mandate', proof_kind: 'mandate', normalized_facts_encrypted: 'mandate-facts',
        normalized_facts_hash: wireDigest(mandateEnvelope) })],
    ]);
    const encryptedValues: string[] = [];
    let storedBinding: AuthorityBindingRecord | null = null;
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_subject', kind: 'person', status: 'active' }),
      resolveCurrentAgentKey: async () => ({ thumbprint: digest, active: true, publicJwk: {} }),
      findReceiver: async () => ({ id: 'rcv_test', status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: 'rcv_test', status: 'active',
        config_json: { approval_policy: { version: '1', groups: [] } } }),
      findProof: async (_operatorId: string, proofId: string) => proofs.get(proofId) ?? null,
      findProofProfileVersion: async () => proofProfile(),
      insertBinding: async (row: AuthorityBindingRecord) => { storedBinding = row; return row; },
    } as unknown as AuthorityRepositoryPort;
    const sut = service({ repo, kms: {
      encrypt: vi.fn(async (plaintext: string) => {
        encryptedValues.push(plaintext);
        return { ciphertext: `encrypted-${encryptedValues.length}`, keyRef: 'test-key' };
      }),
      decrypt: vi.fn(async (ciphertext: string) => ciphertext === 'mandate-facts'
        ? mandateEnvelope : '{}'),
    } });
    const view = await sut.createBinding('op_test', input as never, 'idem');
    expect(storedBinding!.purpose_hash).not.toBe(wireDigest(input.purpose_statement));
    expect(storedBinding!.scope_hash).not.toBe(wireDigest(canonicalize(input.scope)));
    for (const plaintext of encryptedValues) {
      const envelope = JSON.parse(plaintext) as Record<string, unknown>;
      expect(String(envelope.commitment_nonce)).toMatch(/^[A-Za-z0-9_-]{22,}$/);
    }
    expect(JSON.stringify(view)).not.toContain(personalNumber);
    expect(JSON.stringify(view)).not.toContain('commitment_nonce');
  });

  it('returns truthful presentation provenance without inventing per-fact proof IDs', async () => {
    const row = {
      id: 'prs_test', authority_use_id: 'aus_test', status: 'delivered',
      disclosure_manifest: [
        { fact_id: 'person.identifier', mode: 'exact_private' },
        { fact_id: 'person.adult', mode: 'predicate' },
      ],
      proof_refs: [{ id: 'prf_identity', version: 2 }, { id: 'prf_mandate', version: 1 }],
      expires_at: new Date(now.getTime() + 60_000),
    } as AuthorityPresentationRecord;
    const sut = service({ repo: {
      listPresentationsForOperator: async () => [row],
    } as unknown as AuthorityRepositoryPort });
    await expect(sut.listAuthorityPresentations('op_test')).resolves.toEqual([{
      id: row.id,
      authority_use_id: row.authority_use_id,
      status: row.status,
      disclosure_manifest: row.disclosure_manifest,
      proof_refs: [
        { proof_id: 'prf_identity', proof_version: 2 },
        { proof_id: 'prf_mandate', proof_version: 1 },
      ],
      expires_at: row.expires_at.toISOString(),
    }]);
  });

  it('deduplicates one proof assigned to multiple binding roles for disclosure selection', () => {
    const proof = activeProof({ id: 'prf_shared', version: 3 });
    expect(deduplicateProofRows([proof, proof])).toEqual([proof]);
  });

  it('persists the original 201 status for create-mutation idempotency replay', async () => {
    const calls: Array<Record<string, unknown>> = [];
    const repo = {
      idempotent: async (input: Record<string, unknown>, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => {
        calls.push(input);
        return mutation(repo);
      },
      insertPrincipal: async (row: Record<string, unknown>) => row,
    } as unknown as AuthorityRepositoryPort;
    const sut = service({ repo });
    await sut.createPrincipal('op_test', { kind: 'person' }, 'idem-create');
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ operatorId: 'op_test', operation: 'principal.create',
      idempotencyKey: 'idem-create', responseStatus: 201 });
  });

  it('decrypts an ordinary idempotency retry with the persisted ledger ID in KMS AAD', async () => {
    let stored: { ledgerId: string; encrypted: string; result: unknown } | undefined;
    let inserts = 0;
    const repo = {
      idempotent: async (request: { ledgerId: string; workflowPayloadEncrypted: string;
        matchesExistingRequest(value: string, ledgerId: string): Promise<boolean> },
      mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => {
        if (stored) {
          if (!(await request.matchesExistingRequest(stored.encrypted, stored.ledgerId))) {
            throw new Error('different payload');
          }
          return stored.result;
        }
        const result = await mutation(repo);
        stored = { ledgerId: request.ledgerId, encrypted: request.workflowPayloadEncrypted, result };
        return result;
      },
      insertPrincipal: async (row: Record<string, unknown>) => { inserts += 1; return row; },
    } as unknown as AuthorityRepositoryPort;
    const kms = {
      encrypt: vi.fn(async (plaintext: string, context: Record<string, string>) => ({
        ciphertext: `${context.ledger_id}:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test',
      })),
      decrypt: vi.fn(async (ciphertext: string, context: Record<string, string>) => {
        const [ledgerId, encoded] = ciphertext.split(':');
        if (ledgerId !== context.ledger_id) throw new Error('AAD mismatch');
        return Buffer.from(encoded!, 'base64url').toString('utf8');
      }),
    };
    const sut = service({ repo, kms });
    const first = await sut.createPrincipal('op_test', { kind: 'person' }, 'idem-ledger');
    await expect(sut.createPrincipal('op_test', { kind: 'person' }, 'idem-ledger')).resolves.toEqual(first);
    expect(inserts).toBe(1);
    expect(kms.decrypt).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ ledger_id: stored!.ledgerId }));
    await expect(sut.createPrincipal('op_test', { kind: 'organisation' }, 'idem-ledger'))
      .rejects.toThrow('different payload');
  });

  it('replays one secret-bound runtime result commitment and rejects a different exact result', async () => {
    let stored: { ledgerId: string; encrypted: string; result: unknown } | undefined;
    const repo = {
      idempotent: async (request: { ledgerId: string; workflowPayloadEncrypted: string;
        matchesExistingRequest(value: string, ledgerId: string): Promise<boolean> },
      mutation: () => Promise<unknown>) => {
        if (stored) {
          if (!(await request.matchesExistingRequest(stored.encrypted, stored.ledgerId))) {
            throw new Error('different payload');
          }
          return stored.result;
        }
        const result = await mutation();
        stored = { ledgerId: request.ledgerId, encrypted: request.workflowPayloadEncrypted, result };
        return result;
      },
    } as unknown as AuthorityRepositoryPort;
    const { runtimeUse } = modules({ repo });
    const commit = runtimeUse.commitRuntimeResult.bind(runtimeUse);
    const exact = { personal_number: '199001011234' };
    const first = await commit('op_test', 'aus_test', 'succeeded', exact);
    await expect(commit('op_test', 'aus_test', 'succeeded', exact)).resolves.toBe(first);
    expect(first).not.toBe(wireDigest(canonicalize({ outcome: 'succeeded', exact_result: exact })));
    expect(JSON.stringify(stored)).not.toContain('199001011234');
    await expect(commit('op_test', 'aus_test', 'succeeded', { personal_number: '199001011235' }))
      .rejects.toThrow('different payload');
  });

  it('replays an approval decision exactly once and rejects same-key different payload', async () => {
    let storedEncrypted: string | undefined;
    let storedResult: unknown;
    const repo = {
      idempotent: async (request: { workflowPayloadEncrypted: string;
        matchesExistingRequest(value: string): Promise<boolean> },
      mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => {
        if (storedEncrypted) {
          if (!(await request.matchesExistingRequest(storedEncrypted))) throw new Error('different payload');
          return storedResult;
        }
        storedEncrypted = request.workflowPayloadEncrypted;
        storedResult = await mutation(repo);
        return storedResult;
      },
      currentTransaction: () => undefined,
      validateApprovalDecision: async () => ({ request_id: 'apr_test', binding_id: 'abn_test', binding_version: 1,
        authority_use_id: null, authoriser_principal_id: 'prn_subject', identity_proof_id: 'prf_identity',
        identity_proof_version: 1, capacity_proof_id: null, capacity_proof_version: null,
        decision_proof_id: 'prf_decision', decision_proof_version: 1, decision: 'approve', weight: 1,
        request_hash: digest, phase: 'action', group_key_hash: digest, approval_requirement_hash: digest,
        expires_at: new Date(now.getTime() + 60_000) }),
      decideApproval: async () => ({ id: 'apd_test', decision: 'approve' }),
    } as unknown as AuthorityRepositoryPort;
    const verifier = vi.fn(async () => ({ authoriserPrincipalId: 'prn_subject', identityProofId: 'prf_identity',
      identityProofVersion: 1, decisionProofId: 'prf_decision', decisionProofVersion: 1 }));
    const sut = service({ repo, approvalDecisionVerifier: { verify: verifier }, claimIssuer: {
      registerApprovalClaim: async () => ({ claimId: 'pc_approval', claimHash: digest }),
    } as unknown as AuthorityServiceDeps['claimIssuer'] });
    const input = { request_id: 'apr_test', decision: 'approve' as const, request_hash: digest,
      signed_decision: 'signed-one' };
    const actor = { kind: 'operator_owner' as const, operator_id: 'op_test' };
    const first = await sut.decideApproval('op_test', 'apr_test', actor, input, 'idem-approval');
    await expect(sut.decideApproval('op_test', 'apr_test', actor, input, 'idem-approval')).resolves.toEqual(first);
    expect(verifier).toHaveBeenCalledTimes(1);
    await expect(sut.decideApproval('op_test', 'apr_test', actor,
      { ...input, signed_decision: 'signed-two' }, 'idem-approval')).rejects.toThrow('different payload');
    expect(verifier).toHaveBeenCalledTimes(1);
  });

  it('treats only an explicit ceremony rejection as a candidate miss', async () => {
    const profile = proofProfile();
    const repo = {
      listApprovalVerifierCandidates: async () => [
        { authoriserPrincipalId: 'prn_first',
          identityProof: activeProof({ id: 'prf_first', subject_principal_id: 'prn_first' }),
          profile, requestHash: digest },
        { authoriserPrincipalId: 'prn_second',
          identityProof: activeProof({ id: 'prf_second', subject_principal_id: 'prn_second' }),
          profile, requestHash: digest },
      ],
    } as unknown as AuthorityRepositoryPort;
    const adapter = {
      key: 'test', version: 1,
      verifyApprovalDecision: vi.fn(async (input: { authoriserPrincipalId: string }) => {
        if (input.authoriserPrincipalId === 'prn_first') {
          throw new AuthorityApprovalCeremonyRejectedError();
        }
        return { decisionProofId: 'prf_decision', decisionProofVersion: 1 };
      }),
    };
    const verifier = new PinnedAuthorityApprovalDecisionVerifier(repo, [adapter as never]);

    await expect(verifier.verify({
      operatorId: 'op_test', requestId: 'apr_test', requestHash: digest,
      decision: 'approve', signedDecision: 'signed',
      authenticatedAuthor: { kind: 'operator_owner', operator_id: 'op_test' },
    })).resolves.toMatchObject({ authoriserPrincipalId: 'prn_second' });
  });

  it('fails unavailable on an unexpected approval-adapter fault', async () => {
    const repo = {
      listApprovalVerifierCandidates: async () => [{
        authoriserPrincipalId: 'prn_subject', identityProof: activeProof(),
        profile: proofProfile(), requestHash: digest,
      }],
    } as unknown as AuthorityRepositoryPort;
    const adapter = {
      key: 'test', version: 1,
      verifyApprovalDecision: vi.fn(async () => { throw new TypeError('adapter transport failed'); }),
    };
    const verifier = new PinnedAuthorityApprovalDecisionVerifier(repo, [adapter as never]);

    await expect(verifier.verify({
      operatorId: 'op_test', requestId: 'apr_test', requestHash: digest,
      decision: 'approve', signedDecision: 'signed',
      authenticatedAuthor: { kind: 'operator_owner', operator_id: 'op_test' },
    })).rejects.toMatchObject({ statusCode: 503, code: 'SERVICE_UNAVAILABLE' });
  });

  it('does not relabel an unexpected approval verifier fault as invalid authorisation', async () => {
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
    } as unknown as AuthorityRepositoryPort;
    const sut = service({
      repo,
      approvalDecisionVerifier: { verify: vi.fn(async () => { throw new TypeError('dependency fault'); }) },
    });

    await expect(sut.decideApproval(
      'op_test',
      'apr_test',
      { kind: 'operator_owner', operator_id: 'op_test' },
      { request_id: 'apr_test', decision: 'approve', request_hash: digest, signed_decision: 'signed' },
      'idem-approval-fault',
    )).rejects.toMatchObject({ statusCode: 503, code: 'SERVICE_UNAVAILABLE' });
  });

  it('denies no-further-delegation for both human and agent callers', async () => {
    const parent = { id: 'abn_parent', version: 1, operator_id: 'op_test', agent_id: 'agt_parent',
      allow_further_delegation: false } as AuthorityBindingRecord;
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findBinding: async () => parent,
      isPassportAuthorizedForBinding: async () => true,
    } as unknown as AuthorityRepositoryPort;
    const input = { child_agent_id: 'agt_child' } as never;
    for (const actor of [
      { kind: 'operator_owner' as const, operator_id: 'op_test' },
      { kind: 'agent' as const, agent_id: 'agt_parent', passport_jti: 'jti_parent' },
    ]) {
      await expect(service({ repo }).delegateBinding('op_test', parent.id, input, actor, `idem-${actor.kind}`))
        .rejects.toThrow('forbids further delegation');
    }
  });

  it('denies agent delegation when its Passport does not carry the exact parent binding', async () => {
    const parent = { id: 'abn_parent', version: 2, operator_id: 'op_test', agent_id: 'agt_parent',
      allow_further_delegation: true } as AuthorityBindingRecord;
    const passportCheck = vi.fn(async () => false);
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findBinding: async () => parent,
      isPassportAuthorizedForBinding: passportCheck,
    } as unknown as AuthorityRepositoryPort;
    await expect(service({ repo }).delegateBinding('op_test', parent.id, { child_agent_id: 'agt_child' } as never,
      { kind: 'agent', agent_id: 'agt_parent', passport_jti: 'jti_without_parent' }, 'idem-agent'))
      .rejects.toThrow('does not carry the exact parent');
    expect(passportCheck).toHaveBeenCalledWith(expect.objectContaining({ bindingId: parent.id,
      bindingVersion: parent.version, passportJti: 'jti_without_parent' }));
  });

  it('resumes one durable waiting authority use after approval with the same request ID', async () => {
    const requestId = 'R'.repeat(32);
    const normalizedRequest = { amount: 10 };
    const requestHash = wireDigest(canonicalize({ receiver_request_id: requestId, normalized_request: normalizedRequest }));
    const scopeEnvelope = canonicalize({ value: { actions: [{ action_uri: 'urn:test:act', resource_refs: [],
      constraints: [] }], limits: {} }, commitment_nonce: 'AAAAAAAAAAAAAAAAAAAAAA' });
    const approvalEnvelope = canonicalize({ value: { version: '1', groups: [{ phase: 'action', group_key: 'owner',
      required_weight: 1, reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: false }] },
      commitment_nonce: 'BBBBBBBBBBBBBBBBBBBBBB' });
    const disclosureEnvelope = canonicalize({ value: { rules: [], principal_confirmation_required: false,
      max_retention_seconds: null, live_status_required: false }, commitment_nonce: 'CCCCCCCCCCCCCCCCCCCCCC' });
    const binding = {
      id: 'abn_wait', version: 1, operator_id: 'op_test', principal_id: 'prn_subject', agent_id: 'agt_test',
      agent_key_thumbprint: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
      domain_profile_version_id: null, mission_ids: [], parent_binding_id: null, parent_binding_version: null,
      lineage_root_id: 'abn_wait', lineage_root_version: 1, delegation_depth: 0, purpose_code: 'test',
      purpose_statement_encrypted: null, purpose_hash: digest, scope_encrypted: 'scope', scope_hash: wireDigest(scopeEnvelope),
      approval_policy_encrypted: 'approval', approval_policy_hash: wireDigest(approvalEnvelope),
      disclosure_policy_encrypted: 'disclosure', disclosure_policy_hash: wireDigest(disclosureEnvelope),
      delegation_policy: {}, delegation_policy_hash: digest, allow_further_delegation: false,
      max_delegation_depth: 0, proof_set_hash: digest, valid_from: new Date(now.getTime() - 1000),
      expires_at: new Date(now.getTime() + 60_000), status: 'active', claim_id: 'pc_binding', claim_hash: digest,
      created_at: now, activated_at: now, revoked_at: null, revoked_reason: null,
      erased_at: null, tombstone_hash: null, tombstone_claim_id: null,
    } as unknown as AuthorityBindingRecord;
    let use: AuthorityUseRecord | null = null;
    let approvalSatisfied = false;
    const repo = {
      atomic: async (mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      currentTransaction: () => undefined,
      findBinding: async () => binding,
      findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
      resolveCurrentAgentKey: async () => ({ thumbprint: digest, active: true, publicJwk: {} }),
      findReceiver: async () => ({ id: 'rcv_test', status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: 'rcv_test', status: 'active',
        config_json: { approval_policy: { version: '1', groups: [] } } }),
      listBindingProofs: async () => [],
      findAuthorityUseByRuntimeRequest: async () => use,
      insertAuthorityUse: async (row: Record<string, unknown>) => {
        use = { ...row, intent_claim_id: null, outcome_claim_id: null, dispatched_at: null,
          completed_at: null, result_hash: null } as unknown as AuthorityUseRecord;
        return use;
      },
      ensureApprovalRequest: async () => undefined,
      hasUnsatisfiedApprovals: async () => !approvalSatisfied,
      consumeSatisfiedApprovals: async () => undefined,
      authorizeWaitingAuthorityUse: async () => {
        use = { ...use!, status: 'authorized', denial_code: null, authorized_at: now };
        return use;
      },
    } as unknown as AuthorityRepositoryPort;
    const sut = service({ repo, kms: {
      encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: plaintext, keyRef: 'test' })),
      decrypt: vi.fn(async (ciphertext: string) => ({ scope: scopeEnvelope, approval: approvalEnvelope,
        disclosure: disclosureEnvelope }[ciphertext] ?? ciphertext)),
    }, claimIssuer: {
      registerAuthorityUseClaim: async () => ({ claimId: 'pc_use', claimHash: digest }),
    } as unknown as AuthorityServiceDeps['claimIssuer'] });
    const evaluation = { bindingId: binding.id, bindingVersion: 1, passportJti: 'jti_test', agentId: 'agt_test',
      agentKeyThumbprint: digest, receiverId: 'rcv_test', receiverRequestId: requestId,
      actionUri: 'urn:test:act', requestHash, normalizedRequest, verificationMode: 'proxy_mediated' as const };
    await expect(sut.evaluateAuthority('op_test', evaluation)).resolves.toMatchObject({ allowed: false,
      authorityUseId: expect.any(String), denialCode: 'APPROVAL_REQUIRED' });
    const waitingId = use!.id;
    approvalSatisfied = true;
    await expect(sut.evaluateAuthority('op_test', evaluation)).resolves.toMatchObject({ allowed: true,
      authorityUseId: waitingId, executionState: 'authorized' });
    expect(use).toMatchObject({ id: waitingId, status: 'authorized', receiver_request_id: requestId });

    // A stable operation retry authenticates against the same exact use but
    // receives its lifecycle state; it must not create or authorize a second
    // use after dispatch.
    use = { ...use!, status: 'dispatched', dispatched_at: now };
    await expect(sut.evaluateAuthority('op_test', evaluation)).resolves.toMatchObject({
      allowed: true,
      authorityUseId: waitingId,
      executionState: 'dispatched',
    });
  });

  it('returns dependency failure instead of hiding a runtime authority repository outage as no-match', async () => {
    const receiverRequestId = 'R'.repeat(32);
    const normalizedRequest = { amount: 10 };
    const binding = {
      id: 'abn_test', version: 1, operator_id: 'op_test', agent_id: 'agt_test',
      agent_key_thumbprint: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
      claim_id: 'pc_binding', expires_at: new Date(now.getTime() + 60_000), mission_ids: [],
    } as unknown as AuthorityBindingRecord;
    const ref = { binding_id: binding.id, binding_version: 1, binding_claim_id: 'pc_binding',
      binding_digest: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
      expires_at: Math.floor(binding.expires_at.getTime() / 1000) };
    const sut = service({ repo: {
      listPassportRefs: async () => [ref],
      resolveCurrentAgentKey: async () => ({ active: true, thumbprint: digest, publicJwk: {} }),
      resolveRuntimeReceivers: async () => [{ id: 'rcv_test' }],
      findBinding: async () => binding,
      listBindingProofs: async () => { throw new Error('database offline'); },
    } as unknown as AuthorityRepositoryPort });
    await expect(sut.evaluateRuntimeAuthority({ operatorId: 'op_test', passportJti: 'jti_test',
      agentId: 'agt_test', authenticatedAgentId: 'agt_test', boundary: { kind: 'skill', skillId: 'sk_test' },
      receiverRequestId, normalizedRequest,
      requestHash: wireDigest(canonicalize({ receiver_request_id: receiverRequestId,
        normalized_request: normalizedRequest })), verificationMode: 'proxy_mediated' }))
      .rejects.toThrow('dependency is unavailable');
  });

  it('reads the request_hash of a status check as it reads the one of a presentation request: over the receiver request id and the normalized request', async () => {
    const normalized = { resource_type: 'tax_return', resource_ref: 'tax-return:2026' };
    const receiverRequestId = 'status-request-id-0000001';
    const binding = {
      id: 'abn_status', version: 1, operator_id: 'op_test', agent_id: 'agt_test', agent_key_thumbprint: digest,
      receiver_id: 'rcv_test', claim_id: 'pc_status', mission_ids: [],
    } as unknown as AuthorityBindingRecord;
    const { receipts, guards } = modules({ repo: {
      findReceiverById: async () => ({ id: 'rcv_test', managed_by_operator_id: 'op_test' }),
      findBinding: async () => binding,
    } as unknown as AuthorityRepositoryPort });
    vi.spyOn(guards, 'assertBindingUsable').mockResolvedValue(undefined);
    const input = (requestHash: string) => ({
      binding_id: 'abn_status', binding_claim_id: 'pc_status', agent_id: 'agt_test', agent_key_thumbprint: digest,
      action_uri: 'urn:test:action', receiver_request_id: receiverRequestId, resource_ref: 'tax-return:2026',
      request_hash: requestHash, normalized_request: normalized,
    });
    const shared = wireDigest(canonicalize({ receiver_request_id: receiverRequestId, normalized_request: normalized }));
    const withoutId = wireDigest(canonicalize(normalized));
    const auth = { receiverId: 'rcv_test', keyId: 'key-1', jti: 'jti-status', expiresAt: now, payload: {} };
    // The hash over the normalized request alone is refused; the hash both messages share gets past the check to the next one.
    await expect(receipts.statusCheck(auth, input(withoutId))).rejects.toThrow('status request hash mismatch');
    const past = await receipts.statusCheck(auth, input(shared)).then(() => null, (error: unknown) => error);
    expect(String(past)).not.toContain('status request hash mismatch');
  });

  it('rejects a canonical HTTPS origin used as receiver iss/sub instead of rcv_*', async () => {
    const { privateKey } = await generateKeyPair('Ed25519');
    const token = await new SignJWT({ htm: 'POST', htu: '/v1/authority/status-checks', body_hash: digest })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'key-1' })
      .setIssuer('https://receiver.example').setSubject('https://receiver.example').setAudience('stack:test')
      .setJti('jti-1').setIssuedAt(Math.floor(now.getTime() / 1000)).setExpirationTime(Math.floor(now.getTime() / 1000) + 30)
      .sign(privateKey);
    const findReceiver = vi.fn();
    const sut = service({ repo: { findReceiverById: findReceiver } as unknown as AuthorityServiceDeps['repo'] });
    await expect(sut.authenticateReceiverRequest({ compactJws: token, method: 'POST',
      normalizedPath: '/v1/authority/status-checks', bodyHash: digest })).rejects.toThrow('protocol or routing');
    expect(findReceiver).not.toHaveBeenCalled();
  });

  it('accepts only an active native receiver ID with its pinned request key', async () => {
    const { privateKey, publicKey } = await generateKeyPair('Ed25519');
    const publicJwk = await exportJWK(publicKey);
    const receiver: AuthorityReceiverRecord = {
      id: 'rcv_test', managed_by_operator_id: 'op_test', mode: 'native', status: 'active',
      current_profile_version_id: 'apv_receiver', canonical_identifier: 'https://receiver.example',
    };
    const token = await new SignJWT({ htm: 'POST', htu: '/v1/authority/status-checks', body_hash: digest })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'key-1' }).setIssuer(receiver.id).setSubject(receiver.id)
      .setAudience('stack:test/v1/authority/status-checks').setJti('jti-1').setIssuedAt(Math.floor(now.getTime() / 1000))
      .setExpirationTime(Math.floor(now.getTime() / 1000) + 30).sign(privateKey);
    const sut = service({ repo: {
      findReceiverById: async () => receiver,
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: receiver.id, status: 'active', content_hash: digest,
        audience: 'stack:test', delivery_endpoint: 'https://receiver.example/callback',
        config_json: {
          protocol: { key: STACK_DIRECT_POST_PROTOCOL_KEY, version: STACK_DIRECT_POST_PROTOCOL_VERSION },
          request_authentication: { method: STACK_DIRECT_POST_REQUEST_AUTH_METHOD,
            signing_key_ids: ['key-1'], allowed_algs: ['EdDSA'], maximum_age_seconds: 60 },
          approval_policy: { version: '1', groups: [] },
          delivery: { mode: STACK_DIRECT_POST_DELIVERY_MODE,
            allowed_key_management_algs: ['ECDH-ES+A256KW'], allowed_content_encryption_algs: ['A256GCM'] },
        } }),
      findReceiverKey: async () => ({ id: 'rky_test', receiver_id: receiver.id, key_id: 'key-1', use: 'request_signing',
        algorithm: 'EdDSA', public_jwk: publicJwk, thumbprint: digest, status: 'active', valid_from: new Date(now.getTime() - 1000),
        valid_until: null }),
      consumeReceiverJti: async () => true,
    } as unknown as AuthorityServiceDeps['repo'] });
    await expect(sut.authenticateReceiverRequest({ compactJws: token, method: 'POST',
      normalizedPath: '/v1/authority/status-checks', bodyHash: digest })).resolves.toMatchObject({ receiverId: receiver.id });
    const futureToken = await new SignJWT({ htm: 'POST', htu: '/v1/authority/status-checks', body_hash: digest })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'key-1' }).setIssuer(receiver.id).setSubject(receiver.id)
      .setAudience('stack:test/v1/authority/status-checks').setJti('jti-future').setIssuedAt(Math.floor(now.getTime() / 1000) + 6)
      .setExpirationTime(Math.floor(now.getTime() / 1000) + 30).sign(privateKey);
    await expect(sut.authenticateReceiverRequest({ compactJws: futureToken, method: 'POST',
      normalizedPath: '/v1/authority/status-checks', bodyHash: digest })).rejects.toThrow('lifetime is invalid');
    const wrongAudience = await new SignJWT({ htm: 'POST', htu: '/v1/authority/status-checks', body_hash: digest })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'key-1' }).setIssuer(receiver.id).setSubject(receiver.id)
      .setAudience('stack:test').setJti('jti-wrong-aud').setIssuedAt(Math.floor(now.getTime() / 1000))
      .setExpirationTime(Math.floor(now.getTime() / 1000) + 30).sign(privateKey);
    await expect(sut.authenticateReceiverRequest({ compactJws: wrongAudience, method: 'POST',
      normalizedPath: '/v1/authority/status-checks', bodyHash: digest })).rejects.toThrow();
  });

  it('rejects malformed, foreign, future, and replayed agent proofs', async () => {
    const { privateKey, publicKey } = await generateKeyPair('Ed25519');
    const { privateKey: foreignPrivateKey } = await generateKeyPair('Ed25519');
    const publicJwk = await exportJWK(publicKey);
    const thumbprint = authorityAgentKeyThumbprint(publicJwk as { kty: string; crv: string; x: string });
    const binding = {
      id: 'abn_test', version: 1, operator_id: 'op_test', agent_id: 'agt_test',
      agent_key_thumbprint: thumbprint,
    } as AuthorityBindingRecord;
    const authorityRef = {
      binding_id: binding.id, binding_version: 1, binding_claim_id: 'pc_binding', binding_digest: digest,
      principal_ref: 'prn_subject', receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
    };
    const issuedAt = Math.floor(now.getTime() / 1000);
    const baseInput = {
      signed_request: 'a.b.c', agent_proof: '', passport: 'passport-token', authority_ref: authorityRef,
      receiver_profile_version_id: 'apv_receiver', receiver_request_id: 'A'.repeat(32), mission_id: null,
      action_uri: 'urn:test:act', resource_hash: null, request_hash: digest, normalized_request: {},
      requested_facts: [{ fact_id: 'person.id', mode: 'status_only' as const }], nonce: 'N'.repeat(22),
      issued_at: issuedAt, expires_at: issuedAt + 30,
    };
    const boundPayload = (overrides: Record<string, unknown> = {}) => ({
      receiver_request_id: baseInput.receiver_request_id, authority_ref: authorityRef,
      passport_hash: wireDigest(baseInput.passport), mission_id: null, action_uri: baseInput.action_uri,
      resource_hash: null, request_hash: digest, nonce: baseInput.nonce, ...overrides,
    });
    const sign = async (key: typeof privateKey, issuer = binding.agent_id, iat = issuedAt, jti = 'agent-jti') =>
      new SignJWT(boundPayload()).setProtectedHeader({ alg: 'EdDSA', kid: thumbprint })
        .setIssuer(issuer).setSubject(issuer).setAudience('rcv_test').setJti(jti)
        .setIssuedAt(iat).setExpirationTime(iat + 30).sign(key);
    const consume = vi.fn(async () => true);
    const repo = { consumeAuthorityJti: consume } as unknown as AuthorityRepositoryPort;
    const verifier = { verifyPresentationAgentProof: (input: {
      binding: AuthorityBindingRecord; currentAgentKey: { thumbprint: string; active: boolean; publicJwk: typeof publicJwk };
      receiverId: string; input: typeof baseInput; requestMaximumAge: number; now: Date;
    }) => verifyPresentationAgentProof(repo, input as unknown as Parameters<typeof verifyPresentationAgentProof>[1]) };
    const key = { thumbprint, active: true, publicJwk };
    const valid = await sign(privateKey);
    await expect(verifier.verifyPresentationAgentProof({ binding, currentAgentKey: key, receiverId: 'rcv_test',
      input: { ...baseInput, agent_proof: valid }, requestMaximumAge: 60, now })).resolves.toBeUndefined();
    consume.mockResolvedValueOnce(false);
    await expect(verifier.verifyPresentationAgentProof({ binding, currentAgentKey: key, receiverId: 'rcv_test',
      input: { ...baseInput, agent_proof: valid }, requestMaximumAge: 60, now })).rejects.toThrow('replay');
    const foreign = await sign(foreignPrivateKey, 'agt_attacker');
    await expect(verifier.verifyPresentationAgentProof({ binding, currentAgentKey: key, receiverId: 'rcv_test',
      input: { ...baseInput, agent_proof: foreign }, requestMaximumAge: 60, now })).rejects.toThrow();
    const future = await sign(privateKey, binding.agent_id, issuedAt + 6, 'future-jti');
    await expect(verifier.verifyPresentationAgentProof({ binding, currentAgentKey: key, receiverId: 'rcv_test',
      input: { ...baseInput, agent_proof: future, issued_at: issuedAt + 6, expires_at: issuedAt + 36 },
      requestMaximumAge: 60, now })).rejects.toThrow('lifetime is invalid');
    await expect(verifier.verifyPresentationAgentProof({ binding, currentAgentKey: key, receiverId: 'rcv_test',
      input: { ...baseInput, agent_proof: 'a.b.c' }, requestMaximumAge: 60, now })).rejects.toThrow();
  });

  it('registers the terminal authority_use claim and durable terminal row in one transaction', async () => {
    const binding: AuthorityBindingRecord = {
      id: 'abn_test', version: 1, operator_id: 'op_test', principal_id: 'prn_subject', agent_id: 'agt_test',
      agent_key_thumbprint: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
      domain_profile_version_id: 'apv_domain', mission_ids: [], parent_binding_id: null, parent_binding_version: null,
      lineage_root_id: 'abn_test', lineage_root_version: 1, delegation_depth: 0, purpose_code: 'test',
      purpose_statement_encrypted: null, purpose_hash: digest, scope_encrypted: 'scope', scope_hash: digest,
      approval_policy_encrypted: 'approval', approval_policy_hash: digest, disclosure_policy_encrypted: 'disclosure',
      disclosure_policy_hash: digest, delegation_policy: {}, delegation_policy_hash: digest, proof_set_hash: digest,
      allow_further_delegation: false, max_delegation_depth: 0, valid_from: now,
      expires_at: new Date(now.getTime() + 60_000), status: 'active', claim_id: 'pc_binding', claim_hash: digest,
      created_at: now, activated_at: now, revoked_at: null, revoked_reason: null,
      erased_at: null, tombstone_hash: null, tombstone_claim_id: null,
    };
    const use = {
      id: 'aus_test', operator_id: 'op_test', binding_id: binding.id, binding_version: 1,
      status: 'dispatched', result_hash: null, intent_claim_id: null, outcome_claim_id: null,
    } as AuthorityUseRecord;
    const signedUses: AuthorityUseRecord[] = [];
    const tx = {} as AuthorityDbTransaction;
    const repo = {
      idempotent: async (_request: unknown, mutation: () => Promise<unknown>) => mutation(),
      atomic: async (mutation: (repo: AuthorityServiceDeps['repo']) => Promise<unknown>) => mutation(repo),
      currentTransaction: () => tx,
      findAuthorityUseForOperator: async () => use,
      findBinding: async () => binding,
      listBindingProofs: async () => [],
      completeAuthorityUse: async (input: { outcome: 'succeeded' | 'failed'; resultHash: string; now: Date }) => ({
        ...use, status: input.outcome, result_hash: input.resultHash, completed_at: input.now,
      }),
    } as unknown as AuthorityServiceDeps['repo'];
    const sut = service({ repo, claimIssuer: {
      registerAuthorityUseClaim: async (
        { use: claimUse, bindingDigest }: { use: AuthorityUseRecord; bindingDigest: string },
        transaction?: AuthorityDbTransaction,
      ) => {
        expect(transaction).toBe(tx);
        expect(bindingDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
        signedUses.push(claimUse as AuthorityUseRecord);
        return { claimId: 'pc_terminal', claimHash: digest };
      },
    } as unknown as AuthorityServiceDeps['claimIssuer'] });
    await sut.completeRuntimeAuthorityUse({ operatorId: 'op_test', useId: use.id, outcome: 'succeeded',
      exactResult: { personal_number: '199001011234' } });
    expect(signedUses).toHaveLength(1);
    expect(signedUses[0]).toMatchObject({ id: use.id, status: 'succeeded',
      result_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/), completed_at: now });
    expect(signedUses[0]!.result_hash).not.toBe(wireDigest(canonicalize({ personal_number: '199001011234' })));
  });
});
