import { AuthorityReceiverPresentationPayload, canonicalize, sha256 as rawSha256 } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import {
  AuthorityService,
  type AuthorityPresentationRecord,
  type AuthorityProofAdapter,
  type AuthorityProofProfileVersionRecord,
  type AuthorityProofRecord,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
} from './authority-service.js';

const now = new Date('2026-08-21T10:00:00.000Z');
const hash = (value: string) => `sha256:${rawSha256(value)}`;
const fixedDigest = hash('provenance-fixture');

function profile(id: string, format: string, issuer: string): AuthorityProofProfileVersionRecord {
  return {
    id, operator_id: 'op_test', proof_kind: 'identity', schema_uri: `urn:test:${id}`,
    schema_version: '1', adapter_key: `adapter_${id}`, adapter_version: 1,
    accepted_native_formats: [format], status: 'active', content_hash: fixedDigest,
    config_json: { validation: { accepted_issuer_ids: [issuer], accepted_signature_algs: ['EdDSA'],
      signature_required: true, required_claim_paths: ['subject.id'] },
    assurance_mapping: { high: 'urn:test:high' },
    freshness: { maximum_age_seconds: 3_600, live_status_required: false } },
  };
}

function service(repo: AuthorityRepositoryPort, adapters: AuthorityProofAdapter[] = [],
  claimIssuer: AuthorityServiceDeps['claimIssuer'] = {} as AuthorityServiceDeps['claimIssuer']) {
  return new AuthorityService({
    repo,
    kms: {
      encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test' })),
      decrypt: vi.fn(async (ciphertext: string) => Buffer.from(ciphertext.replace(/^test:/, ''), 'base64url').toString()),
    },
    adapters, claimIssuer, receiverRequestAudience: 'stack:test',
    passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
    legacyIdentityResolver: { resolveFacts: vi.fn() }, now: () => now,
  });
}

function presentationBase(): Record<string, any> {
  return {
    iss: 'https://getstack.run', aud: 'https://receiver.example', jti: 'pjt_provenance',
    iat: 1_800_000_000, exp: 1_800_000_060, authority_use_id: 'aus_provenance',
    agent_id: 'agt_executor', agent_key_thumbprint: fixedDigest,
    binding_ref: { binding_id: 'abn_provenance', binding_version: 1, binding_claim_id: 'pc_binding',
      binding_digest: fixedDigest, receiver_id: 'rcv_receiver', receiver_profile_version_id: 'apv_receiver',
      expires_at: 1_800_000_060 },
    principal_ref: 'prn_subject', mission_id: 'ms_work', action_uri: 'urn:test:submit',
    resource_hash: fixedDigest, request_hash: fixedDigest, receiver_id: 'rcv_receiver',
    receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: 'apv_domain',
    proof_profile_version_ids: ['apv_identity'], live_check_time: 1_800_000_000,
    evidence_refs: [{ proof_id: 'prf_identity', proof_version: 1, role: 'principal_identity',
      authoriser_principal_id: null, group_key_hash: fixedDigest, profile_version_id: 'apv_identity',
      issuer_identifier: 'issuer:native', schema_uri: 'urn:test:identity', schema_version: '1',
      assurance_uri: 'urn:test:high', evidence_digest: fixedDigest, evidence_modes: ['issuer_evidence'], status: 'valid' }],
    approval_claim_refs: [], approval_requirements: [], proof_strength: 'native_issuer_evidence',
    nonce: 'A'.repeat(22), disclosed_facts: [],
  };
}

describe('authority provenance acceptance matrix', () => {
  it('preserves two native proof formats, issuers, and verifier provenance through verification and persistence', async () => {
    const fixtures = [
      { id: 'apv_cose', format: 'application/cose', issuer: 'issuer:registry', evidence: 'd28443a10127a0' },
      { id: 'apv_sdjwt', format: 'application/sd-jwt', issuer: 'issuer:wallet', evidence: 'eyJhbGciOiJFZERTQSJ9.test' },
    ];
    const profiles = new Map(fixtures.map((item) => [item.id, profile(item.id, item.format, item.issuer)]));
    const inserted: AuthorityProofRecord[] = [];
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
      findProofProfileVersion: async (_operatorId: string, id: string) => profiles.get(id) ?? null,
      currentTransaction: () => undefined,
      insertProof: async (row: AuthorityProofRecord) => { inserted.push(row); return row; },
    } as unknown as AuthorityRepositoryPort;
    const adapters: AuthorityProofAdapter[] = fixtures.map((item) => ({
      key: `adapter_${item.id}`, version: 1,
      verify: async () => ({ normalizedFacts: { subject: { id: 'opaque-subject' } },
        issuerIdentifier: item.issuer, issuerKeyThumbprint: hash(`${item.issuer}:key`),
        verificationMethod: `${item.format}:signature`, verifierIdentifier: `adapter_${item.id}`,
        verifierVersion: '1', assuranceUri: 'urn:test:high', verifiedAt: now, validFrom: now,
        signatureVerified: true, signatureAlgorithm: 'EdDSA', subjectPrincipalId: 'prn_subject' }),
    }));
    const sut = service(repo, adapters, {
      registerExternalProofVerificationClaim: async ({ proof }) => ({ claimId: `pc_${proof.native_format.replace(/\W/g, '_')}`,
        claimHash: hash(canonicalize({ issuer: proof.issuer_identifier, format: proof.native_format })) }),
    } as AuthorityServiceDeps['claimIssuer']);

    for (const item of fixtures) {
      await sut.importProof('op_test', { subject_principal_id: 'prn_subject', profile_version_id: item.id,
        proof_kind: 'identity', issuer_identifier: item.issuer, schema_uri: `urn:test:${item.id}`,
        schema_version: '1', native_format: item.format, native_evidence: item.evidence }, `idem-${item.id}`);
    }
    expect(inserted.map((row) => ({ format: row.native_format, issuer: row.issuer_identifier,
      source: row.source_kind, verifier: row.verifier_identifier, method: row.verification_method }))).toEqual([
      { format: 'application/cose', issuer: 'issuer:registry', source: 'external_native',
        verifier: 'adapter_apv_cose', method: 'application/cose:signature' },
      { format: 'application/sd-jwt', issuer: 'issuer:wallet', source: 'external_native',
        verifier: 'adapter_apv_sdjwt', method: 'application/sd-jwt:signature' },
    ]);
    for (const [index, row] of inserted.entries()) {
      const plaintext = Buffer.from(row.native_evidence_encrypted!.replace(/^test:/, ''), 'base64url').toString();
      const decoded = JSON.parse(plaintext) as Record<string, unknown>;
      expect(decoded.evidence).toBe(fixtures[index]!.evidence);
      expect(String(decoded.commitment_nonce)).toMatch(/^[A-Za-z0-9_-]{22,}$/);
    }
  });

  it('accepts issuer-verifiable evidence only with issuer-native provenance', () => {
    const payload = presentationBase();
    payload.disclosed_facts = [{ fact_id: 'identity.credential', mode: 'issuer_evidence',
      proof_id: 'prf_identity', assertion_source: 'issuer_native', proof_strength: 'native_issuer_evidence',
      value: { compact_credential: 'opaque' }, evidence_digest: fixedDigest,
      provenance: { adapter_key: 'native', adapter_version: 1, method: 'issuer-signature' } }];
    expect(AuthorityReceiverPresentationPayload.safeParse(payload).success).toBe(true);
    expect(AuthorityReceiverPresentationPayload.safeParse({ ...payload,
      disclosed_facts: payload.disclosed_facts.map((fact: Record<string, unknown>) => ({ ...fact, assertion_source: 'stack_derived' })) }).success).toBe(false);
    expect(AuthorityReceiverPresentationPayload.safeParse({ ...payload,
      disclosed_facts: payload.disclosed_facts.map((fact: Record<string, unknown>) => ({ ...fact, proof_strength: 'native_stack_attestation' })) }).success).toBe(false);
  });

  it('labels exact private values and predicates as STACK or adapter derivations, never issuer-native evidence', () => {
    const exact = { ...presentationBase(), proof_strength: 'native_stack_attestation',
      evidence_refs: [{ ...presentationBase().evidence_refs[0], evidence_modes: ['exact_private'] }],
      disclosed_facts: [{ fact_id: 'identity.number', mode: 'exact_private', proof_id: 'prf_identity',
        assertion_source: 'stack_derived', proof_strength: 'native_stack_attestation', value: 'private-value',
        provenance: { profile_version_id: 'apv_identity' } }] };
    const predicate = { ...presentationBase(), proof_strength: 'native_stack_attestation',
      evidence_refs: [{ ...presentationBase().evidence_refs[0], evidence_modes: ['predicate'] }],
      disclosed_facts: [{ fact_id: 'identity.adult', mode: 'predicate', proof_id: 'prf_identity',
        assertion_source: 'adapter_derived', proof_strength: 'native_stack_attestation', value: true,
        evidence_digest: fixedDigest, provenance: { adapter_key: 'native', adapter_version: 1, method: 'predicate' } }] };
    expect(AuthorityReceiverPresentationPayload.safeParse(exact).success).toBe(true);
    expect(AuthorityReceiverPresentationPayload.safeParse(predicate).success).toBe(true);
    expect(AuthorityReceiverPresentationPayload.safeParse({ ...exact,
      disclosed_facts: exact.disclosed_facts.map((fact) => ({ ...fact, assertion_source: 'issuer_native' })) }).success).toBe(false);
    expect(AuthorityReceiverPresentationPayload.safeParse({ ...predicate,
      disclosed_facts: predicate.disclosed_facts.map((fact) => ({ ...fact, proof_strength: 'native_issuer_evidence' })) }).success).toBe(false);
  });

  it.each([
    ['STACK issued the external identity', { stack_issued_external_identity: true }],
    ['the identity provider issued the mandate', { identity_provider_issued_mandate: true }],
    ['the principal personally signed the agent action', { principal_signed_agent_action: true }],
  ])('rejects a presentation that semantically claims %s', (_label, forbiddenClaim) => {
    expect(AuthorityReceiverPresentationPayload.safeParse({ ...presentationBase(), ...forbiddenClaim }).success).toBe(false);
  });

  it('keeps operator-facing presentation views to opaque proof references and truthful delivery state', async () => {
    const row = { id: 'prs_safe', authority_use_id: 'aus_safe', status: 'accepted',
      disclosure_manifest: [{ fact_id: 'identity.number', mode: 'exact_private' }],
      proof_refs: [{ id: 'prf_identity', version: 3 }], expires_at: new Date(now.getTime() + 60_000),
      issuer_identifier: 'issuer:native', assertion_source: 'issuer_native', principal_signed_agent_action: true,
    } as unknown as AuthorityPresentationRecord;
    const sut = service({ listPresentationsForOperator: async () => [row] } as unknown as AuthorityRepositoryPort);
    const [view] = await sut.listAuthorityPresentations('op_test');
    expect(view).toEqual({ id: 'prs_safe', authority_use_id: 'aus_safe', status: 'accepted',
      disclosure_manifest: [{ fact_id: 'identity.number', mode: 'exact_private' }],
      proof_refs: [{ proof_id: 'prf_identity', proof_version: 3 }], expires_at: row.expires_at.toISOString() });
    expect(view).not.toHaveProperty('issuer_identifier');
    expect(view).not.toHaveProperty('assertion_source');
    expect(view).not.toHaveProperty('principal_signed_agent_action');
  });
});
