import { canonicalize, sha256 as rawSha256, type DelegateAuthorityBindingInput } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import {
  AuthorityService,
  type AuthorityBindingProofRecord,
  type AuthorityBindingRecord,
  type AuthorityPresentationProtocol,
  type AuthorityPresentationRecord,
  type AuthorityProofProfileVersionRecord,
  type AuthorityProofRecord,
  type AuthorityReceiverKeyRecord,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
  type AuthorityUseRecord,
  type ReceiverTransactionReceiptRecord,
} from './authority-service.js';

const now = new Date('2026-08-21T10:00:00.000Z');
const wireDigest = (value: string) => `sha256:${rawSha256(value)}`;
const fixedDigest = wireDigest('authority-lineage');
const nonce = 'A'.repeat(22);

function envelope(value: unknown) {
  const plaintext = canonicalize({ value, commitment_nonce: nonce });
  return { ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, hash: wireDigest(plaintext) };
}

function kms() {
  return {
    encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test' })),
    decrypt: vi.fn(async (ciphertext: string) => Buffer.from(ciphertext.replace(/^test:/, ''), 'base64url').toString()),
  };
}

const scope = {
  actions: [{ action_uri: 'urn:test:payment:submit', resource_refs: ['acct:one', 'acct:two'],
    constraints: [{ path: 'amount', op: 'lte' as const, value: 1_000 }] }],
  limits: { currency: 'EUR' },
};
const approval = { version: '1', groups: [{ phase: 'action', group_key: 'directors', required_weight: 2,
  reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: false }] };
const disclosure = { rules: [{ fact_id: 'organisation.registration', mode: 'status_only' as const, required: true }],
  principal_confirmation_required: false, max_retention_seconds: 0, live_status_required: false };
const scopeEnvelope = envelope(scope);
const approvalEnvelope = envelope(approval);
const disclosureEnvelope = envelope(disclosure);
const purposeEnvelope = envelope('Pay the approved supplier invoice');

function binding(overrides: Partial<AuthorityBindingRecord> = {}): AuthorityBindingRecord {
  return {
    id: 'abn_parent', version: 1, operator_id: 'op_test', principal_id: 'prn_company',
    agent_id: 'agt_parent', agent_key_thumbprint: 'sha256:parent-key', receiver_id: 'rcv_bank',
    receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: 'apv_payments',
    mission_ids: ['ms_invoice'], parent_binding_id: null, parent_binding_version: null,
    lineage_root_id: 'abn_parent', lineage_root_version: 1, delegation_depth: 0,
    purpose_code: 'supplier.pay', purpose_statement_encrypted: purposeEnvelope.ciphertext,
    purpose_hash: purposeEnvelope.hash, scope_encrypted: scopeEnvelope.ciphertext, scope_hash: scopeEnvelope.hash,
    approval_policy_encrypted: approvalEnvelope.ciphertext, approval_policy_hash: approvalEnvelope.hash,
    disclosure_policy_encrypted: disclosureEnvelope.ciphertext, disclosure_policy_hash: disclosureEnvelope.hash,
    delegation_policy: { allow_further_delegation: true, max_delegation_depth: 3 },
    delegation_policy_hash: fixedDigest, allow_further_delegation: true, max_delegation_depth: 3,
    proof_set_hash: wireDigest('proof-set'), valid_from: new Date(now.getTime() - 60_000),
    expires_at: new Date(now.getTime() + 3_600_000), status: 'active', claim_id: 'pc_binding_parent',
    claim_hash: wireDigest('binding-claim'), created_at: now, activated_at: now,
    revoked_at: null, revoked_reason: null, erased_at: null, tombstone_hash: null, tombstone_claim_id: null,
    ...overrides,
  };
}

function proof(id: string, kind: string, subject: string, represented: string | null = null): AuthorityProofRecord {
  return {
    id, version: 1, operator_id: 'op_test', subject_principal_id: subject,
    represented_principal_id: represented, profile_version_id: `apv_${kind}`, proof_kind: kind,
    source_kind: 'external_native', legacy_identity_claim_id: null, issuer_identifier: `issuer:${kind}`,
    issuer_key_thumbprint: fixedDigest, original_relying_party_identifier: null,
    schema_uri: `urn:test:${kind}`, schema_version: '1', native_format: `${kind}+test`,
    native_evidence_encrypted: `native:${id}`, normalized_facts_encrypted: null,
    native_evidence_hash: wireDigest(id), normalized_facts_hash: null, verification_method: 'native',
    verifier_identifier: 'fixture', verifier_version: '1', assurance_uri: null,
    verified_at: now, valid_from: new Date(now.getTime() - 60_000),
    expires_at: new Date(now.getTime() + 3_600_000), status: 'active', status_fresh_until: null,
    last_status_result: 'valid', last_status_checked_at: null, claim_id: `pc_${id}`, created_at: now,
    revoked_at: null, revoked_reason: null, erased_at: null, tombstone_hash: null,
    tombstone_claim_id: null, supersedes_version: null,
  };
}

const proofs = new Map([
  ['prf_identity', proof('prf_identity', 'identity', 'prn_director')],
  ['prf_capacity', proof('prf_capacity', 'capacity', 'prn_director', 'prn_company')],
  ['prf_mandate', proof('prf_mandate', 'mandate', 'prn_director')],
]);
const links: AuthorityBindingProofRecord[] = [
  { binding_id: 'abn_parent', binding_version: 1, proof_id: 'prf_identity', proof_version: 1,
    role: 'authoriser_identity', authoriser_principal_id: 'prn_director', group_key: 'directors', weight: 1, required: true, ordinal: 0 },
  { binding_id: 'abn_parent', binding_version: 1, proof_id: 'prf_capacity', proof_version: 1,
    role: 'authoriser_capacity', authoriser_principal_id: 'prn_director', group_key: 'directors', weight: 1, required: true, ordinal: 1 },
  { binding_id: 'abn_parent', binding_version: 1, proof_id: 'prf_mandate', proof_version: 1,
    role: 'mandate', authoriser_principal_id: null, group_key: 'directors', weight: 1, required: true, ordinal: 2 },
];

function profile(id: string): AuthorityProofProfileVersionRecord {
  return { id, operator_id: 'op_test', proof_kind: id.replace('apv_', ''), schema_uri: `urn:test:${id}`,
    schema_version: '1', adapter_key: 'fixture', adapter_version: 1, accepted_native_formats: ['test'],
    status: 'active', content_hash: fixedDigest,
    config_json: { freshness: { maximum_age_seconds: 7_200, live_status_required: false } } };
}

function delegateRepo(parent: AuthorityBindingRecord, onInsert: (
  row: AuthorityBindingRecord, links: AuthorityBindingProofRecord[],
) => Promise<AuthorityBindingRecord> = async (row) => row) {
  const repo = {
    idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
    findBinding: async () => parent,
    findPrincipal: async () => ({ id: parent.principal_id, status: 'active' }),
    resolveCurrentAgentKey: async (_operatorId: string, agentId: string) => ({
      thumbprint: agentId === 'agt_child' ? 'sha256:child-key' : parent.agent_key_thumbprint,
      active: true, publicJwk: {},
    }),
    findReceiver: async () => ({ id: parent.receiver_id, status: 'active', current_profile_version_id: parent.receiver_profile_version_id }),
    findReceiverProfile: async () => ({ id: parent.receiver_profile_version_id, receiver_id: parent.receiver_id, status: 'active' }),
    isMissionActive: async () => true,
    listBindingProofs: async () => links,
    findProof: async (_operatorId: string, id: string) => proofs.get(id) ?? null,
    findProofProfileVersion: async (_operatorId: string, id: string) => profile(id),
    listProofSources: async () => [], insertBinding: onInsert,
  } as unknown as AuthorityRepositoryPort;
  return repo;
}

function delegatedInput(overrides: Partial<DelegateAuthorityBindingInput> = {}): DelegateAuthorityBindingInput {
  return {
    child_agent_id: 'agt_child', child_agent_key_thumbprint: 'sha256:child-key', mission_ids: ['ms_invoice'],
    scope: { actions: [{ action_uri: 'urn:test:payment:submit', resource_refs: ['acct:one'],
      constraints: [{ path: 'amount', op: 'lte', value: 500 }] }], limits: scope.limits },
    disclosure_policy: disclosure, allow_further_delegation: false, max_delegation_depth: 1,
    valid_from: now, expires_at: new Date(now.getTime() + 1_800_000), ...overrides,
  };
}

function service(repo: AuthorityRepositoryPort, overrides: Partial<AuthorityServiceDeps> = {}) {
  return new AuthorityService({
    repo, kms: kms(), claimIssuer: {} as AuthorityServiceDeps['claimIssuer'], presentationProtocols: [],
    receiverRequestAudience: 'stack:test', passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
    legacyIdentityResolver: { resolveFacts: vi.fn() }, now: () => now, ...overrides,
  });
}

describe('authority delegation and lineage acceptance matrix', () => {
  it('persists a narrower child while preserving principal, capacity, mandate, receiver, purpose, approval, and root lineage', async () => {
    const parent = binding();
    let child: AuthorityBindingRecord | null = null;
    let childLinks: AuthorityBindingProofRecord[] = [];
    const insert = vi.fn(async (row: AuthorityBindingRecord, rows: AuthorityBindingProofRecord[]) => {
      child = row; childLinks = rows; return row;
    });
    const attemptedSubstitutions = { ...delegatedInput(), principal_id: 'prn_attacker', receiver_id: 'rcv_attacker',
      purpose_code: 'attacker.purpose', purpose_statement: null, approval_policy: { version: '1', groups: [] } };
    await service(delegateRepo(parent, insert)).delegateBinding('op_test', parent.id,
      attemptedSubstitutions as DelegateAuthorityBindingInput,
      { kind: 'operator_owner', operator_id: 'op_test' }, 'idem-child');

    expect(child).toMatchObject({
      principal_id: parent.principal_id, receiver_id: parent.receiver_id,
      receiver_profile_version_id: parent.receiver_profile_version_id,
      domain_profile_version_id: parent.domain_profile_version_id,
      purpose_code: parent.purpose_code, purpose_hash: parent.purpose_hash,
      approval_policy_hash: parent.approval_policy_hash, parent_binding_id: parent.id,
      parent_binding_version: parent.version, lineage_root_id: parent.lineage_root_id,
      lineage_root_version: parent.lineage_root_version, delegation_depth: 1,
      agent_id: 'agt_child', agent_key_thumbprint: 'sha256:child-key', mission_ids: ['ms_invoice'],
    });
    expect(child!.approval_policy_encrypted).not.toBeNull();
    expect(child!.purpose_statement_encrypted).not.toBeNull();
    expect(childLinks.map((row) => ({ proof_id: row.proof_id, role: row.role, authoriser: row.authoriser_principal_id })))
      .toEqual(links.map((row) => ({ proof_id: row.proof_id, role: row.role, authoriser: row.authoriser_principal_id })));
    expect(childLinks.every((row) => row.binding_id === child!.id)).toBe(true);
  });

  it.each([
    ['action substitution', { scope: { actions: [{ action_uri: 'urn:test:admin:delete', resource_refs: ['acct:one'], constraints: [] }], limits: scope.limits } }],
    ['receiver resource substitution', { scope: { actions: [{ action_uri: 'urn:test:payment:submit', resource_refs: ['acct:attacker'], constraints: [{ path: 'amount', op: 'lte', value: 500 }] }], limits: scope.limits } }],
    ['higher limit', { scope: { actions: [{ action_uri: 'urn:test:payment:submit', resource_refs: ['acct:one'], constraints: [{ path: 'amount', op: 'lte', value: 2_000 }] }], limits: scope.limits } }],
    ['longer validity', { expires_at: new Date(now.getTime() + 7_200_000) }],
    ['Mission substitution', { mission_ids: ['ms_attacker'] }],
    ['further-delegation widening', { allow_further_delegation: true, max_delegation_depth: 4 }],
  ] as const)('rejects %s in a delegated child', async (_label, override) => {
    const parent = binding();
    await expect(service(delegateRepo(parent)).delegateBinding('op_test', parent.id,
      delegatedInput(override as Partial<DelegateAuthorityBindingInput>),
      { kind: 'operator_owner', operator_id: 'op_test' }, `idem-${_label}`)).rejects.toThrow(/widens|Mission/i);
  });

  it('binds principal, capacity, mandate, agent key, Mission, action, result, and receiver receipt into one terminal chain', async () => {
    const child = binding({ id: 'abn_child', parent_binding_id: 'abn_parent', parent_binding_version: 1,
      agent_id: 'agt_child', agent_key_thumbprint: 'sha256:child-key', delegation_depth: 1,
      lineage_root_id: 'abn_parent', claim_id: 'pc_binding_child' });
    const parent = binding();
    const use: AuthorityUseRecord = {
      id: 'aus_lineage', operator_id: 'op_test', binding_id: child.id, binding_version: child.version,
      passport_jti: 'jti_child', mission_id: 'ms_invoice', agent_id: child.agent_id,
      agent_key_thumbprint: child.agent_key_thumbprint, receiver_id: child.receiver_id,
      receiver_profile_version_id: child.receiver_profile_version_id,
      domain_profile_version_id: child.domain_profile_version_id, receiver_request_id: 'R'.repeat(32),
      action_uri: 'urn:test:payment:submit', resource_hash: wireDigest('acct:one'), request_hash: wireDigest('request'),
      effective_scope_hash: child.scope_hash, proof_set_hash: child.proof_set_hash, disclosure_manifest: [],
      verification_mode: 'native_receiver', proof_strength: 'native_issuer_evidence', status: 'dispatched',
      denial_code: null, created_at: now, authorized_at: now, intent_claim_id: 'pc_intent', outcome_claim_id: null,
      dispatched_at: now, completed_at: null, result_hash: null,
    };
    const presentation: AuthorityPresentationRecord = {
      id: 'prs_lineage', operator_id: 'op_test', authority_use_id: use.id, binding_id: child.id,
      binding_version: 1, receiver_id: child.receiver_id, receiver_profile_version_id: child.receiver_profile_version_id,
      request_signing_key_id: 'rky_request', response_encryption_key_id: 'rky_encrypt', nonce_hash: fixedDigest,
      state_hash: null, signed_request_hash: fixedDigest, request_payload_encrypted: 'encrypted-request',
      requested_fact_ids: [], presentation_jti_hash: fixedDigest, payload_hash: wireDigest('presentation'),
      disclosure_manifest: [], proof_refs: [...proofs.values()].map((row) => ({ id: row.id, version: row.version })),
      signing_key_id: 'stack-key', signing_algorithm: 'EdDSA', key_management_algorithm: 'ECDH-ES+A256KW',
      content_encryption_algorithm: 'A256GCM', status: 'delivered', created_at: now,
      expires_at: new Date(now.getTime() + 60_000), prepared_at: now, delivered_at: now,
      last_error_code: null, erased_at: null, tombstone_hash: null, tombstone_claim_id: null,
    };
    const result = { transaction_id: 'bank-42', accepted: true };
    const resultHash = wireDigest(canonicalize({ value: result, commitment_nonce: nonce }));
    const receiptPayload = { iss: child.receiver_id, sub: child.receiver_id, iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 30, jti: 'receipt-jti', receiver_id: child.receiver_id,
      presentation_id: presentation.id, authority_use_id: use.id,
      presentation_payload_hash: presentation.payload_hash, request_hash: use.request_hash,
      action_uri: use.action_uri, outcome: 'accepted', result, result_commitment_nonce: nonce, result_hash: resultHash };
    const receiptKey: AuthorityReceiverKeyRecord = { id: 'rky_receipt', receiver_id: child.receiver_id,
      key_id: 'receipt-key', use: 'receipt_signing', algorithm: 'EdDSA', public_jwk: {}, thumbprint: fixedDigest,
      status: 'active', valid_from: new Date(now.getTime() - 1_000), valid_until: null };
    const protocol: AuthorityPresentationProtocol = {
      key: 'fixture.receipt', version: '1', validateProfile: () => undefined,
      peekReceiverRequest: () => ({ receiverId: child.receiver_id, keyId: 'receipt-key', algorithm: 'EdDSA' }),
      authenticateReceiverRequest: vi.fn(), verifyPresentationRequest: vi.fn(),
      verifyReceipt: async () => ({ payload: receiptPayload }), signEncryptAndDeliver: vi.fn(),
    };
    let persistedReceipt: ReceiverTransactionReceiptRecord | null = null;
    let completedUse: AuthorityUseRecord | null = null;
    const receiptClaim = vi.fn(async ({ receipt }: { receipt: ReceiverTransactionReceiptRecord }) => {
      persistedReceipt = receipt; return { claimId: 'pc_receipt', claimHash: fixedDigest };
    });
    const terminalUseClaim = vi.fn(async ({ use: terminal }: { use: AuthorityUseRecord }) => {
      completedUse = terminal; return { claimId: 'pc_terminal', claimHash: fixedDigest };
    });
    const repo = {
      atomic: async (mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      currentTransaction: () => undefined,
      findPresentation: async () => presentation,
      findReceiver: async () => ({ id: child.receiver_id, status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: child.receiver_id, status: 'active',
        config_json: { protocol: { key: 'fixture.receipt', version: '1' },
          receipt: { required: true, signing_key_ids: ['receipt-key'], allowed_algs: ['EdDSA'], maximum_age_seconds: 60 } } }),
      findReceiverKey: async () => receiptKey, findAuthorityUseById: async () => use,
      lockReceiptAuthorityGraph: async () => ({ presentation, use, binding: child }),
      findBinding: async (_operatorId: string, id: string) => id === child.id ? child : parent,
      findPrincipal: async () => ({ id: child.principal_id, status: 'active' }),
      resolveCurrentAgentKey: async (_operatorId: string, agentId: string) => ({ active: true,
        thumbprint: agentId === child.agent_id ? child.agent_key_thumbprint : parent.agent_key_thumbprint, publicJwk: {} }),
      isMissionActive: async () => true,
      listBindingProofs: async (_operatorId: string, id: string) => links.map((row) => ({ ...row, binding_id: id })),
      findProof: async (_operatorId: string, id: string) => proofs.get(id) ?? null,
      findProofProfileVersion: async (_operatorId: string, id: string) => profile(id), listProofSources: async () => [],
      isPassportAuthorizedForBinding: async () => true,
      insertReceiverReceipt: async (row: ReceiverTransactionReceiptRecord) => row,
      updatePresentation: async () => ({ ...presentation, status: 'accepted' }),
      completeAuthorityUse: async (input: { outcome: 'succeeded' | 'failed'; resultHash: string; outcomeClaimId?: string }) => ({
        ...use, status: input.outcome, result_hash: input.resultHash,
        outcome_claim_id: input.outcomeClaimId ?? null, completed_at: now,
      }),
    } as unknown as AuthorityRepositoryPort;
    const sut = service(repo, { presentationProtocols: [protocol], claimIssuer: {
      registerReceiverReceiptClaim: receiptClaim, registerAuthorityUseClaim: terminalUseClaim,
    } as unknown as AuthorityServiceDeps['claimIssuer'] });
    const view = await sut.acceptReceipt({ receiverId: child.receiver_id, keyId: 'receipt-key', jti: 'auth-jti',
      expiresAt: new Date(now.getTime() + 30_000), payload: {} }, presentation.id,
    { native_format: 'fixture+jws', signed_receipt: 'signed-receipt' });

    expect(view).toMatchObject({ authority_use_id: use.id, presentation_id: presentation.id,
      receiver_id: child.receiver_id, outcome: 'accepted', result_hash: resultHash });
    expect(persistedReceipt).toMatchObject({ authority_use_id: use.id, presentation_id: presentation.id,
      request_hash: use.request_hash, result_hash: resultHash });
    expect(completedUse).toMatchObject({ binding_id: child.id, mission_id: 'ms_invoice', agent_id: 'agt_child',
      agent_key_thumbprint: 'sha256:child-key', action_uri: use.action_uri, result_hash: resultHash,
      outcome_claim_id: 'pc_receipt' });
    expect(receiptClaim).toHaveBeenCalledWith(expect.objectContaining({ presentationPayloadHash: presentation.payload_hash,
      actionUri: use.action_uri }), undefined);
    expect(terminalUseClaim).toHaveBeenCalledWith(expect.objectContaining({
      use: expect.objectContaining({ binding_id: child.id, result_hash: resultHash }),
    }), undefined);
  });
});
