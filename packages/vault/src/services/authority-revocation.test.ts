import { describe, expect, it } from 'vitest';
import { createAuthorityModules } from './authority/modules.js';
import {
  type AuthorityBindingRecord,
  type AuthorityProofRecord,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
} from './authority-service.js';

const now = new Date('2026-08-21T17:00:00.000Z');
const digest = `sha256:${'a'.repeat(64)}`;

const proof = (overrides: Partial<AuthorityProofRecord> = {}): AuthorityProofRecord => ({
  id: 'prf_derived', version: 1, operator_id: 'op_test', subject_principal_id: 'prn_test',
  represented_principal_id: null, profile_version_id: 'apv_proof', proof_kind: 'mandate',
  source_kind: 'stack_derived', legacy_identity_claim_id: null, issuer_identifier: 'issuer:test',
  issuer_key_thumbprint: digest, original_relying_party_identifier: null, schema_uri: 'urn:test',
  schema_version: '1', native_format: 'test+jws', native_evidence_encrypted: 'encrypted',
  normalized_facts_encrypted: 'facts', native_evidence_hash: digest, normalized_facts_hash: digest,
  verification_method: 'derived', verifier_identifier: 'stack', verifier_version: '1', assurance_uri: null,
  verified_at: new Date(now.getTime() - 1_000), valid_from: new Date(now.getTime() - 1_000),
  expires_at: new Date(now.getTime() + 60_000), status: 'active', status_fresh_until: null,
  last_status_result: 'valid', last_status_checked_at: null, claim_id: 'pc_proof', created_at: now,
  revoked_at: null, revoked_reason: null, erased_at: null, tombstone_hash: null,
  tombstone_claim_id: null, supersedes_version: null, ...overrides,
});

const binding: AuthorityBindingRecord = {
  id: 'abn_test', version: 1, operator_id: 'op_test', principal_id: 'prn_test', agent_id: 'agt_test',
  agent_key_thumbprint: digest, receiver_id: 'rcv_test', receiver_profile_version_id: 'apv_receiver',
  domain_profile_version_id: null, mission_ids: [], lineage_root_id: 'abn_test', lineage_root_version: 1,
  parent_binding_id: null, parent_binding_version: null, delegation_depth: 0, purpose_code: 'test',
  purpose_statement_encrypted: null, purpose_hash: digest, scope_encrypted: 'scope', scope_hash: digest,
  approval_policy_encrypted: 'approval', approval_policy_hash: digest, disclosure_policy_encrypted: 'disclosure',
  disclosure_policy_hash: digest, delegation_policy: {}, delegation_policy_hash: digest,
  allow_further_delegation: false, max_delegation_depth: 0, proof_set_hash: digest,
  valid_from: new Date(now.getTime() - 1_000), expires_at: new Date(now.getTime() + 60_000),
  status: 'active', claim_id: 'pc_binding', claim_hash: digest, created_at: now, activated_at: now,
  revoked_at: null, revoked_reason: null, erased_at: null, tombstone_hash: null, tombstone_claim_id: null,
};

function makeGuards(repo: AuthorityRepositoryPort) {
  return createAuthorityModules({
    repo, kms: {} as AuthorityServiceDeps['kms'], claimIssuer: {} as AuthorityServiceDeps['claimIssuer'],
    receiverRequestAudience: 'https://api.test',
    passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
    approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
    receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
    passportRevocationPublisher: {} as AuthorityServiceDeps['passportRevocationPublisher'],
    legacyIdentityResolver: {} as AuthorityServiceDeps['legacyIdentityResolver'], now: () => now,
  }).guards;
}

describe('authority required-link invalidation', () => {
  it('rejects an active derived proof when its required source has expired', async () => {
    const derived = proof();
    const expiredSource = proof({ id: 'prf_source', source_kind: 'external_native',
      expires_at: new Date(now.getTime() - 1) });
    const repo = {
      findPrincipal: async () => ({ status: 'active' }),
      resolveCurrentAgentKey: async () => ({ active: true, thumbprint: digest }),
      findReceiver: async () => ({ status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ status: 'active' }),
      listBindingProofs: async () => [{ proof_id: derived.id, proof_version: 1, required: true }],
      findProof: async () => derived,
      findProofProfileVersion: async () => ({ status: 'active', config_json: {
        freshness: { maximum_age_seconds: 3_600, live_status_required: false },
      } }),
      listProofSources: async (_operatorId: string, proofId: string) => proofId === derived.id ? [expiredSource] : [],
    } as unknown as AuthorityRepositoryPort;
    const guards = makeGuards(repo);
    await expect(guards.assertBindingUsable(repo, binding, now)).rejects.toThrow('required authority proof expired');
  });

  it('does not invalidate a binding when only an optional proof is expired', async () => {
    const findProof = async () => proof({ expires_at: new Date(now.getTime() - 1) });
    const repo = {
      findPrincipal: async () => ({ status: 'active' }),
      resolveCurrentAgentKey: async () => ({ active: true, thumbprint: digest }),
      findReceiver: async () => ({ status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ status: 'active' }),
      listBindingProofs: async () => [{ proof_id: 'prf_optional', proof_version: 1, required: false }],
      findProof,
    } as unknown as AuthorityRepositoryPort;
    const guards = makeGuards(repo);
    await expect(guards.assertBindingUsable(repo, binding, now)).resolves.toBeUndefined();
  });
});
