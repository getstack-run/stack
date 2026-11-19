import { describe, expect, it } from 'vitest';
import {
  AuthorityBindingClaim,
  AuthorityErasureTombstoneClaim,
  AuthorityApprovalClaim,
  ReceiverTransactionReceiptClaim,
  AuthorityUseClaim,
  PASSPORT_CLAIM_SCHEMAS,
} from './index.js';

const digest = `sha256:${'b'.repeat(64)}`;

describe('authority signed claims', () => {
  it('registers all approved authority claim types, including erasure tombstones', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.external_proof_verification).toBeDefined();
    expect(PASSPORT_CLAIM_SCHEMAS.authority_binding).toBe(AuthorityBindingClaim);
    expect(PASSPORT_CLAIM_SCHEMAS.authority_approval).toBeDefined();
    expect(PASSPORT_CLAIM_SCHEMAS.authority_use).toBeDefined();
    expect(PASSPORT_CLAIM_SCHEMAS.receiver_transaction_receipt).toBeDefined();
    expect(PASSPORT_CLAIM_SCHEMAS.authority_erasure_tombstone).toBe(AuthorityErasureTombstoneClaim);
  });

  it('binds an erasure tombstone to the exact artifact kind, version, and prior digests', () => {
    const claim = {
      type: 'authority_erasure_tombstone' as const,
      target_kind: 'proof' as const,
      target_id: 'prf_identity',
      target_version: 2,
      prior_artifact_digest: digest,
      prior_claim_digest: digest,
      tombstone_digest: digest,
      erased_at: 1_700_000_000,
    };
    expect(AuthorityErasureTombstoneClaim.parse(claim).target_version).toBe(2);
    expect(() => AuthorityErasureTombstoneClaim.parse({ ...claim, target_version: null })).toThrow();
    expect(() => AuthorityErasureTombstoneClaim.parse({
      ...claim,
      target_kind: 'presentation',
      target_id: 'prs_tax',
      target_version: 2,
    })).toThrow();
    expect(() => AuthorityErasureTombstoneClaim.parse({ ...claim, target_id: 'abn_wrong' })).toThrow();
    expect(() => AuthorityErasureTombstoneClaim.parse({
      ...claim,
      target_kind: 'principal',
      target_id: 'prn_person',
      target_version: null,
      legal_name: 'Alex Example',
    })).toThrow();
  });

  it('accepts an opaque PII-free authority binding commitment', () => {
    expect(AuthorityBindingClaim.parse({
      type: 'authority_binding',
      binding_id: 'abn_tax',
      binding_version: 1,
      binding_digest: digest,
      principal_id: 'prn_person',
      agent_id: 'agt_tax',
      agent_key_thumbprint: digest,
      receiver_id: 'rcv_tax',
      receiver_profile_version_id: 'apv_receiver_1',
      domain_profile_version_id: 'apv_domain_1',
      mission_ids: ['ms_tax'],
      lineage_root_id: 'abn_tax',
      lineage_root_version: 1,
      parent_binding_id: null,
      parent_binding_version: null,
      delegation_depth: 0,
      purpose_code: 'annual_tax_filing',
      purpose_hash: digest,
      scope_hash: digest,
      approval_policy_hash: digest,
      disclosure_policy_hash: digest,
      delegation_policy_hash: digest,
      proof_set_hash: digest,
      valid_from: 1_700_000_000,
      expires_at: 1_800_000_000,
      status: 'active',
    }).binding_id).toBe('abn_tax');
  });

  it('binds every authority use claim to the exact immutable binding digest', () => {
    const claim = {
      type: 'authority_use' as const,
      authority_use_id: 'aus_tax',
      binding_id: 'abn_tax',
      binding_version: 1,
      binding_digest: digest,
      passport_jti_hash: digest,
      mission_id: 'ms_tax',
      agent_id: 'agt_tax',
      agent_key_thumbprint: digest,
      receiver_id: 'rcv_tax',
      receiver_profile_version_id: 'apv_receiver_1',
      domain_profile_version_id: 'apv_domain_1',
      receiver_request_id_hash: digest,
      action_uri: 'urn:stack:tax:return:submit',
      resource_hash: digest,
      request_hash: digest,
      effective_scope_hash: digest,
      proof_set_hash: digest,
      disclosure_manifest_hash: digest,
      verification_mode: 'native_receiver' as const,
      proof_strength: 'native_issuer_evidence' as const,
      status: 'authorized' as const,
      denial_code: null,
      created_at: 1_700_000_000,
      completed_at: null,
      result_hash: null,
    };

    expect(AuthorityUseClaim.parse(claim).binding_digest).toBe(digest);
    const { binding_digest: _missing, ...withoutDigest } = claim;
    expect(() => AuthorityUseClaim.parse(withoutDigest)).toThrow();
    expect(() => AuthorityUseClaim.parse({ ...claim, binding_digest: 'b'.repeat(64) })).toThrow();
  });

  it('binds an approval claim to its exact phase, group, and threshold requirement', () => {
    const claim = {
      type: 'authority_approval' as const,
      decision_id: 'apd_one',
      request_id: 'apr_one',
      binding_id: 'abn_tax',
      binding_version: 1,
      authority_use_id: 'aus_tax',
      authoriser_principal_id: 'prn_authoriser',
      identity_proof_id: 'prf_identity',
      identity_proof_version: 1,
      capacity_proof_id: null,
      capacity_proof_version: null,
      decision_proof_id: 'prf_decision',
      decision_proof_version: 1,
      decision: 'approve' as const,
      weight: 1,
      request_hash: digest,
      phase: 'action' as const,
      group_key_hash: digest,
      approval_requirement_hash: digest,
      decided_at: 1_700_000_000,
      expires_at: 1_700_000_060,
      revoked_at: null,
    };

    expect(AuthorityApprovalClaim.parse(claim).phase).toBe('action');
    const { phase: _missing, ...withoutPhase } = claim;
    expect(() => AuthorityApprovalClaim.parse(withoutPhase)).toThrow();
  });

  it('binds a receiver receipt claim to the presented payload and action', () => {
    const claim = {
      type: 'receiver_transaction_receipt' as const,
      receipt_id: 'rtr_tax',
      authority_use_id: 'aus_tax',
      presentation_id: 'prs_tax',
      receiver_id: 'rcv_tax',
      receiver_profile_version_id: 'apv_receiver_1',
      receiver_key_id: 'rky_receipt',
      receipt_jti_hash: digest,
      native_format: 'jwt',
      receipt_hash: digest,
      presentation_payload_hash: digest,
      action_uri: 'urn:stack:tax:return:submit',
      request_hash: digest,
      result_hash: digest,
      outcome: 'accepted' as const,
      external_transaction_ref_hash: null,
      verified_at: 1_700_000_000,
      received_at: 1_700_000_001,
    };

    expect(ReceiverTransactionReceiptClaim.parse(claim).presentation_payload_hash).toBe(digest);
    const { action_uri: _missing, ...withoutAction } = claim;
    expect(() => ReceiverTransactionReceiptClaim.parse(withoutAction)).toThrow();
  });
});
