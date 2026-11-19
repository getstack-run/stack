// Provider reconciliation and late-response evidence. Evidence is authenticated against the
// immutable attempt that sent the request, never against mutable ownership on the operation row.

import { randomUUID } from 'node:crypto';
import { and, eq, inArray, or, sql } from 'drizzle-orm';
import {
  type Database,
  proxyOperationEvidence,
  proxyOperationAttempts,
  proxyOperations,
} from '@stack/shared';
import { governanceOperationIsCurrent, lockOperation, lockOperationByKey } from './internals.js';
import {
  type ProxyOperationTransaction,
  type ProxyOperationRow,
  type FencedDispatch,
} from './types.js';

export async function recordLateResponseEvidence(db: Database, input: FencedDispatch & {
  status: number;
  evidenceHash: string;
}): Promise<boolean> {
  return db.transaction((tx) => appendLateResponseEvidenceInTransaction(input, tx));
}

export async function recordReconciliation(db: Database, input: FencedDispatch & {
  state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
  resourceHash?: string;
  evidenceHash: string;
  providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
  late?: boolean;
}): Promise<boolean> {
  return db.transaction(async (tx) => recordReconciliationInTransaction(input, tx, true));
}

/** The operation key selects and locks the row; the browser never supplies a fence or DB id. */
export async function recordReconciliationByGovernance(input: {
  operationKeyHash: string;
  operatorId: string;
  state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
  resourceHash?: string;
  evidenceHash: string;
  providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
  late?: boolean;
}, transaction: ProxyOperationTransaction): Promise<boolean> {
  const operation = await lockOperationByKey(
    transaction,
    input.operatorId,
    input.operationKeyHash,
  );
  if (!operation || !['outcome_unknown', 'response_received'].includes(operation.delivery_state)
    || operation.adapter_kind !== 'stripe') return false;
  if (!await governanceOperationIsCurrent(transaction, operation)) return false;
  if (operation.reconciliation_state === input.state
    && operation.reconciliation_resource_hash === (input.resourceHash ?? null)
    && operation.reconciliation_evidence_hash === input.evidenceHash
    && operation.reconciliation_provider_status === (input.providerStatus ?? null)) return true;
  return recordReconciliationInTransaction({
    operatorId: input.operatorId,
    operationId: operation.id,
    dispatchFence: operation.dispatch_fence,
    state: input.state,
    resourceHash: input.resourceHash,
    evidenceHash: input.evidenceHash,
    providerStatus: input.providerStatus,
    late: input.late,
  }, transaction, false);
}

async function recordReconciliationInTransaction(input: {
  operatorId: string;
  operationId: string;
  dispatchFence: number;
  dispatchOwnerHash?: string;
  state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
  resourceHash?: string;
  evidenceHash: string;
  providerStatus?: 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';
  late?: boolean;
}, tx: ProxyOperationTransaction, requireOwner: boolean): Promise<boolean> {
  const now = new Date();
  if ((input.state === 'confirmed') !== (input.providerStatus !== undefined)) return false;
  const operation = await lockOperation(tx, input.operatorId, input.operationId);
  if (!operation || operation.adapter_kind !== 'stripe') return false;
  if (operation.dispatch_fence !== input.dispatchFence
    || (requireOwner && operation.dispatch_owner_hash !== input.dispatchOwnerHash)) {
    if (!requireOwner || !input.dispatchOwnerHash) return false;
    const [attempt] = await tx.select().from(proxyOperationAttempts).where(and(
      eq(proxyOperationAttempts.operation_id, input.operationId),
      eq(proxyOperationAttempts.operator_id, input.operatorId),
      eq(proxyOperationAttempts.dispatch_owner_hash, input.dispatchOwnerHash),
      eq(proxyOperationAttempts.dispatch_fence, input.dispatchFence),
    )).limit(1);
    if (!attempt) return false;
    await appendHistoricalReconciliationEvidence(operation, input, tx, now, attempt.id);
    return true;
  }
  if (operation.reconciliation_state === input.state
    && operation.reconciliation_resource_hash === (input.resourceHash ?? null)
    && operation.reconciliation_evidence_hash === input.evidenceHash
    && operation.reconciliation_provider_status === (input.providerStatus ?? null)) {
    return true;
  }
  const existingTerminal = ['contradictory', 'expired'].includes(operation.reconciliation_state)
    || (operation.reconciliation_state === 'confirmed'
      && ['succeeded', 'failed', 'canceled'].includes(operation.reconciliation_provider_status ?? ''));
  if (existingTerminal) {
    await appendHistoricalReconciliationEvidence(operation, input, tx, now);
    return true;
  }
  const [row] = await tx.update(proxyOperations).set({
    reconciliation_state: input.state,
    reconciliation_resource_hash: input.resourceHash ?? null,
    reconciliation_evidence_hash: input.evidenceHash,
    reconciliation_provider_status: input.providerStatus ?? null,
    reconciliation_checked_at: now,
    contradictory_evidence_hash: input.state === 'contradictory' ? input.evidenceHash : undefined,
    late_evidence_at: input.late ? now : undefined,
    post_response_work_state: input.state === 'confirmed'
      && ['succeeded', 'failed', 'canceled'].includes(input.providerStatus ?? '')
      && operation.post_response_work_state === 'waiting_provider'
      ? 'pending'
      : undefined,
    post_response_next_attempt_at: input.state === 'confirmed'
      && ['succeeded', 'failed', 'canceled'].includes(input.providerStatus ?? '')
      && operation.post_response_work_state === 'waiting_provider'
      ? now
      : undefined,
    updated_at: now,
  }).where(and(
    eq(proxyOperations.id, input.operationId), eq(proxyOperations.operator_id, input.operatorId),
    eq(proxyOperations.adapter_kind, 'stripe'), eq(proxyOperations.dispatch_fence, input.dispatchFence),
    requireOwner ? eq(proxyOperations.dispatch_owner_hash, input.dispatchOwnerHash!) : undefined,
    or(
      inArray(proxyOperations.reconciliation_state, ['pending', 'not_found']),
      and(
        eq(proxyOperations.reconciliation_state, 'confirmed'),
        inArray(proxyOperations.reconciliation_provider_status, ['pending', 'requires_action']),
      ),
    ),
  )).returning({ id: proxyOperations.id });
  if (!row) return false;
  await tx.insert(proxyOperationEvidence).values({
    id: `poe_${randomUUID()}`,
    operator_id: input.operatorId,
    operation_id: input.operationId,
    kind: input.state === 'contradictory' ? 'contradictory' : input.late ? 'late' : 'reconciliation',
    evidence_hash: input.evidenceHash,
    reconciliation_state: input.state,
    resource_hash: input.resourceHash ?? null,
    observed_at: now,
  });
  return true;
}

async function appendHistoricalReconciliationEvidence(
  operation: ProxyOperationRow,
  input: {
    operatorId: string;
    operationId: string;
    state: 'confirmed' | 'not_found' | 'contradictory' | 'expired';
    resourceHash?: string;
    evidenceHash: string;
  },
  tx: ProxyOperationTransaction,
  now: Date,
  attemptId?: string,
): Promise<void> {
  const existingTerminal = ['contradictory', 'expired'].includes(operation.reconciliation_state)
    || (operation.reconciliation_state === 'confirmed'
      && ['succeeded', 'failed', 'canceled'].includes(operation.reconciliation_provider_status ?? ''));
  const contradictory = existingTerminal && (
    operation.reconciliation_state !== input.state
    || operation.reconciliation_resource_hash !== (input.resourceHash ?? null)
  );
  const existingEvidence = await tx.query.proxyOperationEvidence.findFirst({ where: and(
    eq(proxyOperationEvidence.operation_id, input.operationId),
    eq(proxyOperationEvidence.operator_id, input.operatorId),
    eq(proxyOperationEvidence.evidence_hash, input.evidenceHash),
    eq(proxyOperationEvidence.reconciliation_state, input.state),
  ) });
  if (!existingEvidence) {
    await tx.insert(proxyOperationEvidence).values({
      id: `poe_${randomUUID()}`,
      operator_id: input.operatorId,
      operation_id: input.operationId,
      kind: contradictory ? 'contradictory' : 'late',
      evidence_hash: input.evidenceHash,
      reconciliation_state: input.state,
      resource_hash: input.resourceHash ?? null,
      observed_at: now,
    });
  }
  if (attemptId) {
    await tx.update(proxyOperationAttempts).set({
      late_evidence_at: now,
      contradictory_evidence_hash: contradictory ? input.evidenceHash : undefined,
    }).where(and(
      eq(proxyOperationAttempts.id, attemptId),
      eq(proxyOperationAttempts.operator_id, input.operatorId),
    ));
  }
  await tx.update(proxyOperations).set({
    late_evidence_at: now,
    contradictory_evidence_hash: contradictory
      ? sql`coalesce(${proxyOperations.contradictory_evidence_hash}, ${input.evidenceHash})`
      : undefined,
    updated_at: now,
  }).where(and(
    eq(proxyOperations.id, input.operationId),
    eq(proxyOperations.operator_id, input.operatorId),
  ));
}

export async function appendLateResponseEvidenceInTransaction(input: FencedDispatch & {
  status: number;
  evidenceHash: string;
}, tx: ProxyOperationTransaction): Promise<boolean> {
  const now = new Date();
  const operation = await lockOperation(tx, input.operatorId, input.operationId);
  if (!operation) {
    return false;
  }
  // The current operation owner may have advanced to a newer Stripe attempt.
  // Authenticate late evidence against the immutable attempt that actually
  // sent the request, not against mutable ownership on the operation row.
  const [attempt] = await tx.select().from(proxyOperationAttempts).where(and(
    eq(proxyOperationAttempts.operation_id, input.operationId),
    eq(proxyOperationAttempts.operator_id, input.operatorId),
    eq(proxyOperationAttempts.dispatch_owner_hash, input.dispatchOwnerHash),
    eq(proxyOperationAttempts.dispatch_fence, input.dispatchFence),
  )).limit(1);
  if (!attempt) return false;
  const existing = await tx.query.proxyOperationEvidence.findFirst({ where: and(
    eq(proxyOperationEvidence.operation_id, input.operationId),
    eq(proxyOperationEvidence.operator_id, input.operatorId),
    eq(proxyOperationEvidence.evidence_hash, input.evidenceHash),
  ) });
  if (!existing) {
    await tx.insert(proxyOperationEvidence).values({
      id: `poe_${randomUUID()}`,
      operator_id: input.operatorId,
      operation_id: input.operationId,
      kind: operation.reconciliation_state === 'contradictory' ? 'contradictory' : 'late',
      evidence_hash: input.evidenceHash,
      reconciliation_state: operation.reconciliation_state,
      resource_hash: null,
      observed_at: now,
    });
  }
  await tx.update(proxyOperationAttempts).set({
    response_status: input.status,
    late_evidence_at: now,
    outcome: operation.reconciliation_state === 'contradictory' ? 'contradictory' : undefined,
    completed_at: operation.reconciliation_state === 'contradictory' ? now : undefined,
  }).where(and(
    eq(proxyOperationAttempts.id, attempt.id),
    eq(proxyOperationAttempts.operator_id, input.operatorId),
  ));
  await tx.update(proxyOperations).set({
    late_evidence_at: now,
    contradictory_evidence_hash: operation.reconciliation_state === 'contradictory'
      ? sql`coalesce(${proxyOperations.contradictory_evidence_hash}, ${input.evidenceHash})`
      : undefined,
    updated_at: now,
  }).where(and(
    eq(proxyOperations.id, input.operationId),
    eq(proxyOperations.operator_id, input.operatorId),
  ));
  return true;
}
