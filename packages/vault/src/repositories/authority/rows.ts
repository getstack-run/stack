import type {
  authorityBindings,
  authorityPresentations,
  authorityProofs,
  authorityReceiverKeys,
  authorityReceivers,
  authorityUses,
  receiverTransactionReceipts,
} from '@stack/shared';
import type {
  AuthorityBindingRecord,
  AuthorityPresentationRecord,
  AuthorityProofRecord,
  AuthorityProofStatus,
  AuthorityReceiverKeyRecord,
  AuthorityReceiverRecord,
  AuthorityUseRecord,
  ReceiverTransactionReceiptRecord,
} from '../../services/authority/records.js';

export function bindingRow(row: typeof authorityBindings.$inferSelect & { claim_hash?: string | null }): AuthorityBindingRecord {
  const delegation = row.delegation_policy as Record<string, unknown>;
  return {
    ...row,
    mission_ids: row.mission_ids,
    status: row.status as AuthorityBindingRecord['status'],
    allow_further_delegation: delegation.allow_further_delegation === true,
    max_delegation_depth: Number(delegation.max_delegation_depth ?? 0),
    claim_hash: row.claim_hash ?? null,
  };
}

export function proofRow(row: typeof authorityProofs.$inferSelect): AuthorityProofRecord {
  return {
    ...row,
    source_kind: row.source_kind as AuthorityProofRecord['source_kind'],
    status: row.status as AuthorityProofStatus,
    last_status_result: row.last_status_result as AuthorityProofRecord['last_status_result'],
  };
}

export function receiverRow(row: typeof authorityReceivers.$inferSelect): AuthorityReceiverRecord {
  return {
    ...row,
    mode: row.mode as AuthorityReceiverRecord['mode'],
    status: row.status as AuthorityReceiverRecord['status'],
  };
}

export function receiverKeyRow(row: typeof authorityReceiverKeys.$inferSelect): AuthorityReceiverKeyRecord {
  return {
    ...row,
    use: row.use as AuthorityReceiverKeyRecord['use'],
    public_jwk: row.public_jwk,
    status: row.status as AuthorityReceiverKeyRecord['status'],
  };
}

export function useRow(row: typeof authorityUses.$inferSelect): AuthorityUseRecord {
  return {
    ...row,
    disclosure_manifest: row.disclosure_manifest,
    verification_mode: row.verification_mode as AuthorityUseRecord['verification_mode'],
    proof_strength: row.proof_strength as AuthorityUseRecord['proof_strength'],
    status: row.status as AuthorityUseRecord['status'],
  };
}

export function presentationRow(row: typeof authorityPresentations.$inferSelect): AuthorityPresentationRecord {
  return { ...row, status: row.status as AuthorityPresentationRecord['status'] };
}

export function receiptRow(row: typeof receiverTransactionReceipts.$inferSelect): ReceiverTransactionReceiptRecord {
  return { ...row, outcome: row.outcome as ReceiverTransactionReceiptRecord['outcome'] };
}
