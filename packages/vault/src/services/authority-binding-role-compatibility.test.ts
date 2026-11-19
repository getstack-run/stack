import { describe, expect, it, vi } from 'vitest';
import { canonicalize, sha256 as rawSha256 } from '@stack/shared';
import {
  AuthorityService,
  type AuthorityProofRecord,
  type AuthorityRepositoryPort,
  type AuthorityServiceDeps,
} from './authority-service.js';

const now = new Date('2026-08-21T18:00:00.000Z');
const digest = `sha256:${'a'.repeat(64)}`;
const wireDigest = (value: string) => `sha256:${rawSha256(value)}`;

function proof(id: string, kind: string, subject = 'prn_human'): AuthorityProofRecord {
  return {
    id, version: 1, operator_id: 'op_test', subject_principal_id: subject,
    represented_principal_id: kind === 'capacity' ? 'prn_org' : null,
    profile_version_id: `apv_${kind}`, proof_kind: kind, source_kind: 'external_native',
    legacy_identity_claim_id: null, issuer_identifier: 'issuer:test', issuer_key_thumbprint: digest,
    original_relying_party_identifier: null, schema_uri: `urn:test:${kind}`, schema_version: '1',
    native_format: 'test+jws', native_evidence_encrypted: 'native', normalized_facts_encrypted: 'facts',
    native_evidence_hash: digest, normalized_facts_hash: digest, verification_method: 'jws',
    verifier_identifier: 'test', verifier_version: '1', assurance_uri: null,
    verified_at: now, valid_from: new Date(now.getTime() - 1_000),
    expires_at: new Date(now.getTime() + 60_000), status: 'active', status_fresh_until: null,
    last_status_result: 'valid', last_status_checked_at: now, claim_id: `pc_${id}`, created_at: now,
    revoked_at: null, revoked_reason: null, erased_at: null, tombstone_hash: null,
    tombstone_claim_id: null, supersedes_version: null,
  };
}

describe('authority proof assignment compatibility', () => {
  it.each([
    ['principal_identity', 'capacity'],
    ['authoriser_identity', 'capacity'],
    ['authoriser_capacity', 'identity'],
    ['mandate', 'identity'],
    ['consent', 'signature'],
    ['domain', 'workload'],
  ] as const)('rejects %s backed by %s evidence', async (role, incompatibleKind) => {
    const input = {
      principal_id: 'prn_org', agent_id: 'agt_test', receiver_id: 'rcv_test',
      receiver_profile_version_id: 'apv_receiver', mission_ids: [], purpose_code: 'test.authority',
      scope: { actions: [], limits: {} }, approval_policy: { version: '1', groups: [] },
      disclosure_policy: { rules: [], principal_confirmation_required: false,
        max_retention_seconds: 0, live_status_required: false },
      delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
      valid_from: now, expires_at: new Date(now.getTime() + 60_000),
      proofs: [
        { proof_id: 'prf_principal', proof_version: 1, role: 'principal_identity', group_key: 'principal', weight: 1, required: true, ordinal: 0 },
        { proof_id: 'prf_authoriser', proof_version: 1, role: 'authoriser_identity', authoriser_principal_id: 'prn_human', group_key: 'owner', weight: 1, required: true, ordinal: 1 },
        { proof_id: 'prf_capacity', proof_version: 1, role: 'authoriser_capacity', authoriser_principal_id: 'prn_human', group_key: 'owner', weight: 1, required: true, ordinal: 2 },
        { proof_id: 'prf_mandate', proof_version: 1, role: 'mandate', group_key: 'mandate', weight: 1, required: true, ordinal: 3 },
      ],
    };
    const target = input.proofs.find((assignment) => assignment.role === role);
    if (!target) input.proofs.push({
      proof_id: `prf_${role}`, proof_version: 1, role, group_key: role, weight: 1, required: false, ordinal: 4,
    } as typeof input.proofs[number]);
    const targetId = (target ?? input.proofs.at(-1))!.proof_id;
    const mandateDigest = wireDigest(canonicalize({
      principal_id: input.principal_id, authoriser_principal_ids: ['prn_human'], agent_id: input.agent_id,
      agent_key_thumbprint: digest, receiver_id: input.receiver_id,
      receiver_profile_version_id: input.receiver_profile_version_id, domain_profile_version_id: null,
      mission_ids: [], purpose_code: input.purpose_code, purpose_statement: null, scope: input.scope,
      approval_policy: input.approval_policy, disclosure_policy: input.disclosure_policy,
      delegation_policy: input.delegation_policy, valid_from: input.valid_from.toISOString(),
      expires_at: input.expires_at.toISOString(),
    }));
    const rows = new Map<string, AuthorityProofRecord>([
      ['prf_principal', proof('prf_principal', 'identity', 'prn_org')],
      ['prf_authoriser', proof('prf_authoriser', 'identity')],
      ['prf_capacity', proof('prf_capacity', 'capacity')],
      ['prf_mandate', proof('prf_mandate', 'mandate')],
      [targetId, proof(targetId, incompatibleKind, role === 'principal_identity' ? 'prn_org' : 'prn_human')],
    ]);
    const facts = canonicalize({ facts: { mandate_terms_digest: mandateDigest }, commitment_nonce: 'A'.repeat(22) });
    for (const row of rows.values()) {
      if (['mandate', 'consent', 'signature'].includes(row.proof_kind)) {
        row.normalized_facts_encrypted = 'mandate-facts';
        row.normalized_facts_hash = wireDigest(facts);
      }
    }
    const repo = {
      idempotent: async (_request: unknown, mutation: (inner: AuthorityRepositoryPort) => Promise<unknown>) => mutation(repo),
      findPrincipal: async () => ({ id: 'prn_org', kind: 'organisation', status: 'active' }),
      resolveCurrentAgentKey: async () => ({ thumbprint: digest, active: true }),
      findReceiver: async () => ({ id: 'rcv_test', status: 'active', current_profile_version_id: 'apv_receiver' }),
      findReceiverProfile: async () => ({ id: 'apv_receiver', receiver_id: 'rcv_test', status: 'active',
        config_json: { approval_policy: { version: '1', groups: [] } } }),
      findProof: async (_operatorId: string, id: string) => rows.get(id) ?? null,
      findProofProfileVersion: async (_operatorId: string, id: string) => ({
        id, proof_kind: rows.get(id.replace('apv_', 'prf_'))?.proof_kind ?? 'identity', status: 'active',
        config_json: { freshness: { maximum_age_seconds: 3_600, live_status_required: false } },
      }),
    } as unknown as AuthorityRepositoryPort;
    const service = new AuthorityService({
      repo, kms: {
        encrypt: vi.fn(async (plaintext: string) => ({ ciphertext: `encrypted:${plaintext}`, keyRef: 'test' })),
        decrypt: vi.fn(async () => facts),
      },
      claimIssuer: {} as AuthorityServiceDeps['claimIssuer'], receiverRequestAudience: 'https://api.test',
      passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
      approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
      receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
      passportRevocationPublisher: { publishAuthorityRevocations: vi.fn() },
      legacyIdentityResolver: {} as AuthorityServiceDeps['legacyIdentityResolver'], now: () => now,
    });

    await expect(service.createBinding('op_test', input as never, `idem-${role}`))
      .rejects.toThrow(`${role} proof assignment is incompatible`);
  });
});
