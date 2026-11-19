import { canonicalize, sha256 as rawSha256, type CreateAuthorityBindingInput } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import {
  AuthorityService,
  type AuthorityBindingProofRecord,
  type AuthorityBindingRecord,
  type AuthorityProofAdapter,
  type AuthorityProofProfileVersionRecord,
  type AuthorityProofRecord,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
} from './authority-service.js';

const now = new Date('2026-08-21T10:00:00.000Z');
const digest = (value: string) => `sha256:${rawSha256(value)}`;
const opaqueDigest = digest('acceptance-fixture');

function profile(kind: AuthorityProofRecord['proof_kind'], format = `application/${kind}+test`): AuthorityProofProfileVersionRecord {
  return {
    id: `apv_${kind}`, operator_id: 'op_test', proof_kind: kind,
    schema_uri: `urn:test:${kind}`, schema_version: '1', adapter_key: `adapter_${kind}`,
    adapter_version: 1, accepted_native_formats: [format], status: 'active', content_hash: opaqueDigest,
    config_json: {
      validation: { accepted_issuer_ids: [`issuer:${kind}`], accepted_signature_algs: ['EdDSA'],
        signature_required: true, required_claim_paths: [] },
      assurance_mapping: { basic: `urn:test:assurance:${kind}:basic` },
      freshness: { maximum_age_seconds: 3_600, live_status_required: false },
    },
  };
}

function proof(kind: AuthorityProofRecord['proof_kind'], overrides: Partial<AuthorityProofRecord> = {}): AuthorityProofRecord {
  return {
    id: `prf_${kind}`, version: 1, operator_id: 'op_test', subject_principal_id: 'prn_org',
    represented_principal_id: null, profile_version_id: `apv_${kind}`, proof_kind: kind,
    source_kind: 'external_native', legacy_identity_claim_id: null, issuer_identifier: `issuer:${kind}`,
    issuer_key_thumbprint: opaqueDigest, original_relying_party_identifier: null,
    schema_uri: `urn:test:${kind}`, schema_version: '1', native_format: `application/${kind}+test`,
    native_evidence_encrypted: `native:${kind}`, normalized_facts_encrypted: null,
    native_evidence_hash: digest(`native:${kind}`), normalized_facts_hash: null,
    verification_method: 'fixture-signature', verifier_identifier: `adapter_${kind}`,
    verifier_version: '1', assurance_uri: `urn:test:assurance:${kind}:basic`,
    verified_at: new Date(now.getTime() - 1_000), valid_from: new Date(now.getTime() - 1_000),
    expires_at: new Date(now.getTime() + 60_000), status: 'active', status_fresh_until: null,
    last_status_result: 'valid', last_status_checked_at: null, claim_id: `pc_${kind}`,
    created_at: now, revoked_at: null, revoked_reason: null, erased_at: null,
    tombstone_hash: null, tombstone_claim_id: null, supersedes_version: null,
    ...overrides,
  };
}

function kms() {
  return {
    encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test' })),
    decrypt: vi.fn(async (ciphertext: string) => Buffer.from(ciphertext.replace(/^test:/, ''), 'base64url').toString()),
  };
}

function service(repo: AuthorityRepositoryPort, overrides: Partial<AuthorityServiceDeps> = {}) {
  return new AuthorityService({
    repo, kms: kms(), adapters: [], claimIssuer: {} as AuthorityServiceDeps['claimIssuer'],
    receiverRequestAudience: 'stack:test', passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
    legacyIdentityResolver: { resolveFacts: vi.fn() }, now: () => now, ...overrides,
  });
}

function bindingFixture() {
  const input: CreateAuthorityBindingInput = {
    principal_id: 'prn_org', agent_id: 'agt_executor', receiver_id: 'rcv_tax',
    receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: 'apv_domain',
    mission_ids: ['ms_return'], purpose_code: 'tax.submit', purpose_statement: 'Submit the annual return',
    scope: { actions: [{ action_uri: 'urn:test:tax:submit', resource_refs: ['return:2026'], constraints: [] }], limits: {} },
    approval_policy: { version: '1', groups: [] },
    disclosure_policy: { rules: [], principal_confirmation_required: false,
      max_retention_seconds: 0, live_status_required: false },
    delegation_policy: { allow_further_delegation: true, max_delegation_depth: 2 },
    valid_from: now, expires_at: new Date(now.getTime() + 60_000),
    proofs: [
      { proof_id: 'prf_identity_principal', proof_version: 1, role: 'principal_identity', group_key: 'base', weight: 1, required: true, ordinal: 0 },
      { proof_id: 'prf_identity_authoriser', proof_version: 1, role: 'authoriser_identity', authoriser_principal_id: 'prn_director', group_key: 'base', weight: 1, required: true, ordinal: 1 },
      { proof_id: 'prf_capacity', proof_version: 1, role: 'authoriser_capacity', authoriser_principal_id: 'prn_director', group_key: 'base', weight: 1, required: true, ordinal: 2 },
      { proof_id: 'prf_mandate', proof_version: 1, role: 'mandate', group_key: 'base', weight: 1, required: true, ordinal: 3 },
      { proof_id: 'prf_consent', proof_version: 1, role: 'consent', group_key: 'base', weight: 1, required: true, ordinal: 4 },
      { proof_id: 'prf_signature', proof_version: 1, role: 'mandate', group_key: 'base', weight: 1, required: true, ordinal: 5 },
      { proof_id: 'prf_domain', proof_version: 1, role: 'domain', group_key: 'base', weight: 1, required: true, ordinal: 6 },
    ],
  };
  const authoriserIds = ['prn_director'];
  const mandateTerms = digest(canonicalize({
    principal_id: input.principal_id, authoriser_principal_ids: authoriserIds,
    agent_id: input.agent_id, agent_key_thumbprint: opaqueDigest, receiver_id: input.receiver_id,
    receiver_profile_version_id: input.receiver_profile_version_id,
    domain_profile_version_id: input.domain_profile_version_id, mission_ids: input.mission_ids,
    purpose_code: input.purpose_code, purpose_statement: input.purpose_statement ?? null,
    scope: input.scope, approval_policy: input.approval_policy, disclosure_policy: input.disclosure_policy,
    delegation_policy: input.delegation_policy, valid_from: input.valid_from.toISOString(),
    expires_at: input.expires_at.toISOString(),
  }));
  const termsEnvelope = canonicalize({ facts: { mandate_terms_digest: mandateTerms }, commitment_nonce: 'A'.repeat(22) });
  const proofs = new Map<string, AuthorityProofRecord>([
    ['prf_identity_principal', proof('identity', { id: 'prf_identity_principal', subject_principal_id: 'prn_org' })],
    ['prf_identity_authoriser', proof('identity', { id: 'prf_identity_authoriser', subject_principal_id: 'prn_director' })],
    ['prf_capacity', proof('capacity', { subject_principal_id: 'prn_director', represented_principal_id: 'prn_org' })],
    ['prf_mandate', proof('mandate', { subject_principal_id: 'prn_director' })],
    ['prf_consent', proof('consent', { subject_principal_id: 'prn_director' })],
    ['prf_signature', proof('signature', { subject_principal_id: 'prn_director' })],
    ['prf_domain', proof('domain', { subject_principal_id: 'prn_org' })],
  ]);
  for (const id of ['prf_mandate', 'prf_consent', 'prf_signature']) {
    const row = proofs.get(id)!;
    row.normalized_facts_encrypted = `test:${Buffer.from(termsEnvelope).toString('base64url')}`;
    row.normalized_facts_hash = digest(termsEnvelope);
  }
  return { input, proofs };
}

function compositionRepo(proofs: Map<string, AuthorityProofRecord>, insertBinding: (
  row: AuthorityBindingRecord, links: AuthorityBindingProofRecord[],
) => Promise<AuthorityBindingRecord> = async (row) => row): AuthorityRepositoryPort {
  const repo = {
    idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
    findPrincipal: async () => ({ id: 'prn_org', kind: 'organisation', status: 'active' }),
    resolveCurrentAgentKey: async () => ({ thumbprint: opaqueDigest, active: true, publicJwk: {} }),
    findReceiver: async () => ({ id: 'rcv_tax', status: 'active', current_profile_version_id: 'apv_receiver' }),
    findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: 'rcv_tax', status: 'active',
      config_json: { approval_policy: { version: '1', groups: [] } } }),
    isMissionActive: async () => true,
    findProof: async (_operatorId: string, id: string) => proofs.get(id) ?? null,
    findProofProfileVersion: async (_operatorId: string, id: string) => profile(id.replace(/^apv_/, '')),
    listProofSources: async () => [], insertBinding,
  } as unknown as AuthorityRepositoryPort;
  return repo;
}

describe('authority evidence acceptance matrix', () => {
  it('imports identity, capacity, mandate, consent, signature, and domain evidence as separate typed native proofs', async () => {
    const kinds = ['identity', 'capacity', 'mandate', 'consent', 'signature', 'domain'] as const;
    const inserted: AuthorityProofRecord[] = [];
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
      findProofProfileVersion: async (_operatorId: string, id: string) => profile(id.replace(/^apv_/, '')),
      currentTransaction: () => undefined,
      insertProof: async (row: AuthorityProofRecord) => { inserted.push(row); return row; },
    } as unknown as AuthorityRepositoryPort;
    const adapters: AuthorityProofAdapter[] = kinds.map((kind) => ({
      key: `adapter_${kind}`, version: 1,
      verify: async () => ({ normalizedFacts: {}, issuerIdentifier: `issuer:${kind}`,
        verificationMethod: 'fixture-signature', verifierIdentifier: `adapter_${kind}`, verifierVersion: '1',
        assuranceUri: `urn:test:assurance:${kind}:basic`, verifiedAt: now, validFrom: now,
        signatureVerified: true, signatureAlgorithm: 'EdDSA', subjectPrincipalId: 'prn_subject',
        ...(kind === 'capacity' ? { representedPrincipalId: 'prn_org' } : {}),
        ...(['mandate', 'consent', 'signature'].includes(kind) ? { mandateTermsDigest: opaqueDigest } : {}) }),
    }));
    const sut = service(repo, { adapters, claimIssuer: {
      registerExternalProofVerificationClaim: async ({ proof: row }) => ({ claimId: `pc_${row.proof_kind}`, claimHash: opaqueDigest }),
    } as AuthorityServiceDeps['claimIssuer'] });

    for (const kind of kinds) {
      await sut.importProof('op_test', {
        subject_principal_id: 'prn_subject', ...(kind === 'capacity' ? { represented_principal_id: 'prn_org' } : {}),
        profile_version_id: `apv_${kind}`, proof_kind: kind, issuer_identifier: `issuer:${kind}`,
        schema_uri: `urn:test:${kind}`, schema_version: '1', native_format: `application/${kind}+test`,
        native_evidence: `signed-${kind}`,
      }, `idem-${kind}`);
    }
    expect(inserted.map((row) => [row.proof_kind, row.native_format, row.source_kind])).toEqual(
      kinds.map((kind) => [kind, `application/${kind}+test`, 'external_native']),
    );
    expect(new Set(inserted.map((row) => row.profile_version_id)).size).toBe(kinds.length);
  });

  it('composes all six evidence kinds without collapsing their proof records or provenance', async () => {
    const { input, proofs } = bindingFixture();
    let storedLinks: AuthorityBindingProofRecord[] = [];
    const insertBinding = vi.fn(async (row: AuthorityBindingRecord, links: AuthorityBindingProofRecord[]) => {
      storedLinks = links; return row;
    });
    const view = await service(compositionRepo(proofs, insertBinding)).createBinding('op_test', input, 'idem-compose');
    expect(view).toMatchObject({ principal_id: 'prn_org', agent_id: 'agt_executor', receiver_id: 'rcv_tax' });
    expect(storedLinks).toHaveLength(7);
    expect(storedLinks.map((link) => proofs.get(link.proof_id)!.proof_kind)).toEqual([
      'identity', 'identity', 'capacity', 'mandate', 'consent', 'signature', 'domain',
    ]);
    expect(new Set(storedLinks.map((link) => link.proof_id)).size).toBe(7);
  });

  it.each([
    ['principal_identity', 'domain', 'prf_identity_principal'],
    ['authoriser_identity', 'capacity', 'prf_identity_authoriser'],
    ['authoriser_capacity', 'identity', 'prf_capacity'],
    ['mandate', 'identity', 'prf_mandate'],
    ['domain', 'identity', 'prf_domain'],
  ] as const)('rejects %s assignment backed by %s evidence', async (_role, falseKind, proofId) => {
    const { input, proofs } = bindingFixture();
    const original = proofs.get(proofId)!;
    proofs.set(proofId, { ...original, proof_kind: falseKind, profile_version_id: `apv_${falseKind}`,
      represented_principal_id: proofId === 'prf_capacity' ? 'prn_org' : original.represented_principal_id });
    await expect(service(compositionRepo(proofs)).createBinding('op_test', input, `idem-mismatch-${proofId}`))
      .rejects.toThrow(/assignment.*incompatible|proof kind|evidence kind/i);
  });

  it('rejects an adapter assurance URI that the immutable profile never mapped', async () => {
    const inserted = vi.fn(async (row: AuthorityProofRecord) => row);
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_subject', status: 'active' }),
      findProofProfileVersion: async () => profile('identity'), currentTransaction: () => undefined, insertProof: inserted,
    } as unknown as AuthorityRepositoryPort;
    const sut = service(repo, {
      adapters: [{ key: 'adapter_identity', version: 1, verify: async () => ({ normalizedFacts: {},
        issuerIdentifier: 'issuer:identity', verificationMethod: 'fixture-signature',
        verifierIdentifier: 'adapter_identity', verifierVersion: '1', assuranceUri: 'urn:attacker:self-asserted:root',
        verifiedAt: now, validFrom: now, signatureVerified: true, signatureAlgorithm: 'EdDSA',
        subjectPrincipalId: 'prn_subject' }) }],
      claimIssuer: { registerExternalProofVerificationClaim: vi.fn(async () => ({
        claimId: 'pc_unmapped', claimHash: opaqueDigest,
      })) } as unknown as AuthorityServiceDeps['claimIssuer'],
    });
    await expect(sut.importProof('op_test', {
      subject_principal_id: 'prn_subject', profile_version_id: 'apv_identity', proof_kind: 'identity',
      issuer_identifier: 'issuer:identity', schema_uri: 'urn:test:identity', schema_version: '1',
      native_format: 'application/identity+test', native_evidence: 'signed',
    }, 'idem-assurance')).rejects.toThrow(/assurance/i);
    expect(inserted).not.toHaveBeenCalled();
  });
});
