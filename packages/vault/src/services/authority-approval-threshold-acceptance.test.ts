import { canonicalize, sha256 as rawSha256 } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import { assertApprovalPolicyAssignments } from './authority/binding-policy.js';
import { createAuthorityModules } from './authority/modules.js';
import {
  AuthorityService,
  PinnedAuthorityApprovalDecisionVerifier,
  type AuthorityBindingRecord,
  type AuthorityProofAdapter,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
  type AuthorityUseRecord,
} from './authority-service.js';

const now = new Date('2026-08-21T10:00:00.000Z');
const wireDigest = (value: string) => `sha256:${rawSha256(value)}`;
const fixedDigest = wireDigest('approval-fixture');
const nonce = 'A'.repeat(22);

function envelope(value: unknown) {
  const plaintext = canonicalize({ value, commitment_nonce: nonce });
  return { ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, hash: wireDigest(plaintext) };
}

function binding(approvalPolicy: Record<string, unknown>): AuthorityBindingRecord {
  const scope = envelope({ actions: [{ action_uri: 'urn:test:payment:submit', resource_refs: ['acct:one'],
    constraints: [{ path: 'amount', op: 'lte', value: 1_000 }] }], limits: {} });
  const approval = envelope(approvalPolicy);
  const disclosure = envelope({ rules: [], principal_confirmation_required: false,
    max_retention_seconds: 0, live_status_required: false });
  return {
    id: 'abn_approval', version: 1, operator_id: 'op_test', principal_id: 'prn_company',
    agent_id: 'agt_executor', agent_key_thumbprint: 'sha256:agent-key', receiver_id: 'rcv_bank',
    receiver_profile_version_id: 'apv_receiver', domain_profile_version_id: 'apv_payment',
    mission_ids: ['ms_invoice'], parent_binding_id: null, parent_binding_version: null,
    lineage_root_id: 'abn_approval', lineage_root_version: 1, delegation_depth: 0,
    purpose_code: 'supplier.pay', purpose_statement_encrypted: null, purpose_hash: fixedDigest,
    scope_encrypted: scope.ciphertext, scope_hash: scope.hash,
    approval_policy_encrypted: approval.ciphertext, approval_policy_hash: approval.hash,
    disclosure_policy_encrypted: disclosure.ciphertext, disclosure_policy_hash: disclosure.hash,
    delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
    delegation_policy_hash: fixedDigest, allow_further_delegation: false, max_delegation_depth: 0,
    proof_set_hash: fixedDigest, valid_from: new Date(now.getTime() - 60_000),
    expires_at: new Date(now.getTime() + 3_600_000), status: 'active', claim_id: 'pc_binding',
    claim_hash: fixedDigest, created_at: now, activated_at: now, revoked_at: null,
    revoked_reason: null, erased_at: null, tombstone_hash: null, tombstone_claim_id: null,
  };
}

function serviceDeps(repo: AuthorityRepositoryPort): AuthorityServiceDeps {
  const claimIssuer = {
    registerAuthorityUseClaim: vi.fn(async () => ({ claimId: 'pc_use', claimHash: fixedDigest })),
  } as unknown as AuthorityServiceDeps['claimIssuer'];
  return {
    repo,
    kms: {
      encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test' })),
      decrypt: vi.fn(async (ciphertext: string) => Buffer.from(ciphertext.replace(/^test:/, ''), 'base64url').toString()),
    },
    claimIssuer,
    receiverRequestAudience: 'stack:test', passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
    legacyIdentityResolver: { resolveFacts: vi.fn() }, now: () => now,
  };
}

function service(repo: AuthorityRepositoryPort) {
  return new AuthorityService(serviceDeps(repo));
}

function evaluationFixture(approvalPolicy: Record<string, unknown>) {
  const activeBinding = binding(approvalPolicy);
  const uses = new Map<string, AuthorityUseRecord>();
  const satisfied = new Set<string>();
  const requests: Array<Record<string, unknown>> = [];
  const consumed: Array<Record<string, unknown>> = [];
  const repo = {
    atomic: async (mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
    currentTransaction: () => undefined,
    findBinding: async () => activeBinding,
    findPrincipal: async () => ({ id: activeBinding.principal_id, status: 'active' }),
    resolveCurrentAgentKey: async () => ({ active: true, thumbprint: activeBinding.agent_key_thumbprint, publicJwk: {} }),
    findReceiver: async () => ({ id: activeBinding.receiver_id, status: 'active',
      current_profile_version_id: activeBinding.receiver_profile_version_id }),
    findReceiverProfile: async () => ({ id: activeBinding.receiver_profile_version_id,
      receiver_id: activeBinding.receiver_id, status: 'active' }),
    isMissionActive: async () => true, listBindingProofs: async () => [],
    findAuthorityUseByRuntimeRequest: async (_operatorId: string, _receiverId: string, receiverRequestId: string) =>
      uses.get(receiverRequestId) ?? null,
    insertAuthorityUse: async (row: AuthorityUseRecord) => {
      const stored = { ...row, intent_claim_id: null, outcome_claim_id: null, dispatched_at: null,
        completed_at: null, result_hash: null } as AuthorityUseRecord;
      uses.set(row.receiver_request_id, stored); return stored;
    },
    ensureApprovalRequest: async (input: Record<string, unknown>) => { requests.push(input); },
    hasUnsatisfiedApprovals: async (_operatorId: string, _bindingId: string, _version: number, requestHash?: string) =>
      !satisfied.has(String(requestHash)),
    consumeSatisfiedApprovals: async (input: Record<string, unknown>) => { consumed.push(input); },
    authorizeWaitingAuthorityUse: async (_operatorId: string, useId: string) => {
      const entry = [...uses.entries()].find(([, value]) => value.id === useId);
      if (!entry) return null;
      const authorized = { ...entry[1], status: 'authorized' as const, denial_code: null, authorized_at: now };
      uses.set(entry[0], authorized); return authorized;
    },
  } as unknown as AuthorityRepositoryPort;
  const evaluate = (receiverRequestId: string, normalizedRequest: Record<string, unknown>, actionUri = 'urn:test:payment:submit') => {
    const requestHash = wireDigest(canonicalize({ receiver_request_id: receiverRequestId, normalized_request: normalizedRequest }));
    return { requestHash, result: service(repo).evaluateAuthority('op_test', {
      bindingId: activeBinding.id, bindingVersion: 1, passportJti: 'jti_agent', agentId: activeBinding.agent_id,
      agentKeyThumbprint: activeBinding.agent_key_thumbprint, receiverId: activeBinding.receiver_id,
      receiverRequestId, missionId: 'ms_invoice', actionUri, resourceRef: 'acct:one', requestHash,
      normalizedRequest, verificationMode: 'native_receiver',
    }) };
  };
  return { activeBinding, repo, uses, satisfied, requests, consumed, evaluate };
}

describe('authority approval and threshold acceptance matrix', () => {
  it('authorizes an autonomous exact action without manufacturing approval requests', async () => {
    const fixture = evaluationFixture({ version: '1', groups: [] });
    const attempt = fixture.evaluate('R'.repeat(32), { amount: 250 });
    fixture.satisfied.add(attempt.requestHash);
    await expect(attempt.result).resolves.toMatchObject({ allowed: true, proofStrength: 'native_stack_attestation' });
    expect(fixture.requests).toEqual([]);
    expect(fixture.consumed).toContainEqual(expect.objectContaining({ phase: 'action', requestHash: attempt.requestHash }));
  });

  it('waits for the two-authoriser threshold and consumes approval only for the exact action request hash', async () => {
    const fixture = evaluationFixture({ version: '1', groups: [{ phase: 'action', group_key: 'directors',
      required_weight: 2, reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: false }] });
    const first = fixture.evaluate('A'.repeat(32), { amount: 250 });
    await expect(first.result).resolves.toMatchObject({ allowed: false, denialCode: 'APPROVAL_REQUIRED' });
    expect(fixture.requests).toContainEqual(expect.objectContaining({ phase: 'action', groupKey: 'directors',
      requiredWeight: 2, requestHash: first.requestHash }));
    expect(fixture.consumed).toEqual([]);

    fixture.satisfied.add(first.requestHash);
    await expect(fixture.evaluate('A'.repeat(32), { amount: 250 }).result).resolves.toMatchObject({ allowed: true });
    expect(fixture.consumed).toContainEqual(expect.objectContaining({ phase: 'action', requestHash: first.requestHash }));

    const changed = fixture.evaluate('B'.repeat(32), { amount: 251 });
    await expect(changed.result).resolves.toMatchObject({ allowed: false, denialCode: 'APPROVAL_REQUIRED' });
    expect(changed.requestHash).not.toBe(first.requestHash);
    expect(fixture.consumed).not.toContainEqual(expect.objectContaining({ requestHash: changed.requestHash }));
  });

  it('requires two distinct named authorisers and does not count duplicate proof rows twice', () => {
    const assertAssignments = assertApprovalPolicyAssignments as unknown as (
      policy: Record<string, unknown>, assignments: Array<Record<string, unknown>>,
    ) => void;
    const policy = { version: '1', groups: [{ phase: 'activation', group_key: 'directors',
      required_weight: 2, reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: false }] };
    const oneDirectorTwice = [
      { role: 'authoriser_identity', authoriser_principal_id: 'prn_alice', group_key: 'directors', weight: 1 },
      { role: 'authoriser_capacity', authoriser_principal_id: 'prn_alice', group_key: 'directors', weight: 1 },
    ];
    expect(() => assertAssignments(policy, oneDirectorTwice)).toThrow('threshold');
    expect(() => assertAssignments(policy, [...oneDirectorTwice,
      { role: 'authoriser_identity', authoriser_principal_id: 'prn_bob', group_key: 'directors', weight: 1 },
    ])).not.toThrow();
  });

  it('creates a fresh final-step presentation requirement bound to the exact request', async () => {
    const finalPolicy = { version: '1', groups: [{ phase: 'presentation', group_key: 'principal',
      required_weight: 1, reject_mode: 'any_reject', maximum_age_seconds: 30, final_step: true }] };
    const activeBinding = binding(finalPolicy);
    const requests: Array<Record<string, unknown>> = [];
    const repoShape: Pick<AuthorityRepositoryPort, 'ensureApprovalRequest'> = {
      ensureApprovalRequest: async (input) => { requests.push(input as unknown as Record<string, unknown>); },
    };
    const repo = repoShape as AuthorityRepositoryPort;
    const { approvals } = createAuthorityModules(serviceDeps(repo));
    const ensure = approvals.ensureApprovalRequests.bind(approvals);
    const exactHash = wireDigest('exact-presentation-request');
    await ensure(repo, activeBinding, 'presentation', exactHash, 'aus_final');
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ authorityUseId: 'aus_final', phase: 'presentation',
      groupKey: 'principal', requestHash: exactHash, requiredWeight: 1 });
    expect((requests[0]!.expiresAt as Date).getTime()).toBe(now.getTime() + 30_000);
    expect(requests[0]!.challengeHash).toBe(wireDigest(canonicalize({ binding_id: activeBinding.id,
      binding_version: activeBinding.version, phase: 'presentation', group_key: 'principal', request_hash: exactHash })));
  });

  it('rejects an approval ceremony for a different exact request before calling an adapter', async () => {
    const verifyApprovalDecision = vi.fn();
    const repo = { listApprovalVerifierCandidates: async () => [{
      requestHash: wireDigest('approved-request'), authoriserPrincipalId: 'prn_alice',
      identityProof: { id: 'prf_identity', version: 1 }, profile: { adapter_key: 'fixture', adapter_version: 1 },
    }] } as unknown as AuthorityRepositoryPort;
    const verifier = new PinnedAuthorityApprovalDecisionVerifier(repo, [{ key: 'fixture', version: 1,
      verify: vi.fn(), verifyApprovalDecision } as unknown as AuthorityProofAdapter]);
    await expect(verifier.verify({ operatorId: 'op_test', requestId: 'apr_exact',
      requestHash: wireDigest('changed-request'), decision: 'approve', signedDecision: 'signed',
      authenticatedAuthor: { kind: 'operator_owner', operator_id: 'op_test' } }))
      .rejects.toThrow('invalid or ambiguous');
    expect(verifyApprovalDecision).not.toHaveBeenCalled();
  });

  it('keeps prohibited actions prohibited even when every approval is marked satisfied', async () => {
    const fixture = evaluationFixture({ version: '1', groups: [{ phase: 'action', group_key: 'directors',
      required_weight: 2, reject_mode: 'any_reject', maximum_age_seconds: 60, final_step: false }] });
    const attempt = fixture.evaluate('P'.repeat(32), { amount: 1 }, 'urn:test:admin:delete');
    fixture.satisfied.add(attempt.requestHash);
    await expect(attempt.result).rejects.toThrow('outside scope');
    expect(fixture.uses.size).toBe(0);
    expect(fixture.requests).toEqual([]);
  });
});
