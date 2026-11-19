// Admission and dispatch claims. An operation is inserted once per operator and operation key
// under the operator lock with a bounded count of non-terminal rows, then claimed by exactly one
// fenced dispatch owner. A pre-dispatch release scrubs the prepared payloads.

import { and, eq, gt, inArray, ne, sql } from 'drizzle-orm';
import { type Database, proxyOperations } from '@stack/shared';
import { insertAttempt, lockOperation, lockOperator } from './internals.js';
import { findByOperationKey } from './lookups.js';
import {
  type ProxyOperationTransaction,
  type ProxyOperationInsert,
  PROXY_NONTERMINAL_LIMIT,
  PROXY_REPLAY_CAPACITY_BYTES,
  type DbHandle,
  type InsertAdmittedResult,
  type DispatchClaimResult,
} from './types.js';

export async function insertAdmitted(
  database: Database,
  input: ProxyOperationInsert,
  transaction?: ProxyOperationTransaction,
): Promise<InsertAdmittedResult> {
  const execute = async (db: DbHandle): Promise<InsertAdmittedResult> => {
    await lockOperator(db, input.operator_id);
    const existing = await findByOperationKey(
      database,
      input.operator_id,
      input.operation_key_hash,
      db as ProxyOperationTransaction,
    );
    if (existing) return { state: 'existing', operation: existing };

    const [usage] = await db.select({
      count: sql<number>`count(*)::int`,
    }).from(proxyOperations).where(and(
      eq(proxyOperations.operator_id, input.operator_id),
      inArray(proxyOperations.delivery_state, ['admitted', 'dispatching', 'outcome_unknown']),
      ne(proxyOperations.accounting_state, 'released'),
    ));
    const used = usage?.count ?? 0;
    if (used >= PROXY_NONTERMINAL_LIMIT) {
      return { state: 'capacity_exceeded', kind: 'nonterminal', limit: PROXY_NONTERMINAL_LIMIT, used };
    }

    const [created] = await db.insert(proxyOperations).values(input).onConflictDoNothing().returning();
    if (created) return { state: 'created', operation: created };
    const raced = await findByOperationKey(
      database,
      input.operator_id,
      input.operation_key_hash,
      db as ProxyOperationTransaction,
    );
    if (!raced) throw new Error('Proxy operation admission lost without a durable row');
    return { state: 'existing', operation: raced };
  };
  return transaction ? execute(transaction) : database.transaction(execute);
}

export async function claimDispatch(database: Database, input: {
  operatorId: string;
  operationId: string;
  admissionOwnerHash: string;
  admissionFence: number;
  dispatchOwnerHash: string;
  leaseExpiresAt: Date;
  capacityBytes: number;
  requestEvidenceHash: string;
}, transaction?: ProxyOperationTransaction): Promise<DispatchClaimResult> {
  const execute = async (db: DbHandle): Promise<DispatchClaimResult> => {
    await lockOperator(db, input.operatorId);
    const operation = await lockOperation(db, input.operatorId, input.operationId);
    if (!operation) throw new Error('Proxy operation is unavailable');
    if (operation.delivery_state === 'response_received') return { state: 'replay', operation };
    if (operation.delivery_state === 'outcome_unknown') return { state: 'outcome_unknown', operation };
    if (operation.delivery_state !== 'admitted' || operation.accounting_state !== 'reserved'
      || operation.replay_state !== 'none') return { state: 'busy', operation };

    const [capacity] = await db.select({
      used: sql<number>`coalesce(sum(${proxyOperations.capacity_reserved_bytes}) filter
        (where ${proxyOperations.capacity_released_at} is null), 0)::bigint`,
    }).from(proxyOperations).where(eq(proxyOperations.operator_id, input.operatorId));
    const used = Number(capacity?.used ?? 0);
    if (used + input.capacityBytes > PROXY_REPLAY_CAPACITY_BYTES) {
      return { state: 'capacity_exceeded', kind: 'replay_bytes', limit: PROXY_REPLAY_CAPACITY_BYTES, used };
    }

    const [claimed] = await db.update(proxyOperations).set({
      delivery_state: 'dispatching',
      accounting_state: 'committed',
      accounting_committed_at: new Date(),
      dispatch_owner_hash: input.dispatchOwnerHash,
      dispatch_fence: 1,
      dispatch_lease_expires_at: input.leaseExpiresAt,
      dispatch_started_at: new Date(),
      transport_attempts: 1,
      capacity_reserved_bytes: input.capacityBytes,
      updated_at: new Date(),
    }).where(and(
      eq(proxyOperations.id, input.operationId),
      eq(proxyOperations.operator_id, input.operatorId),
      eq(proxyOperations.delivery_state, 'admitted'),
      eq(proxyOperations.replay_state, 'none'),
      eq(proxyOperations.accounting_state, 'reserved'),
      eq(proxyOperations.admission_owner_hash, input.admissionOwnerHash),
      eq(proxyOperations.admission_fence, input.admissionFence),
    )).returning();
    if (!claimed) return { state: 'busy', operation };
    await insertAttempt(db, claimed, input.dispatchOwnerHash, input.leaseExpiresAt, input.requestEvidenceHash);
    return { state: 'acquired', operation: claimed, dispatchFence: claimed.dispatch_fence };
  };
  return transaction ? execute(transaction) : database.transaction(execute);
}

/**
 * Stripe-only retry using the original native idempotency key when STACK has
 * no replay payload. Pending, not-found and confirmed provider evidence can
 * all be recovered safely; contradictory or expired evidence stays closed.
 */
export async function claimStripeRetry(database: Database, input: {
  operatorId: string;
  operationId: string;
  dispatchOwnerHash: string;
  leaseExpiresAt: Date;
  capacityBytes: number;
  requestEvidenceHash: string;
}, transaction?: ProxyOperationTransaction): Promise<DispatchClaimResult> {
  const execute = async (db: DbHandle): Promise<DispatchClaimResult> => {
    await lockOperator(db, input.operatorId);
    const operation = await lockOperation(db, input.operatorId, input.operationId);
    if (!operation) throw new Error('Proxy operation is unavailable');
    if (operation.delivery_state === 'response_received'
      && operation.replay_state === 'available') {
      return { state: 'replay', operation };
    }
    if (!['outcome_unknown', 'response_received'].includes(operation.delivery_state)
      || operation.adapter_kind !== 'stripe'
      || !['pending', 'not_found', 'confirmed'].includes(operation.reconciliation_state)
      || operation.replay_state === 'expired'
      || operation.replay_state === 'erased'
      || !operation.prepared_request_encrypted
      || operation.prepared_request_readable_until <= new Date()
      || !operation.retry_deadline
      || operation.retry_deadline <= new Date()
      || operation.transport_attempts >= 3) {
      return { state: 'outcome_unknown', operation };
    }
    const [capacity] = await db.select({
      used: sql<number>`coalesce(sum(${proxyOperations.capacity_reserved_bytes}) filter
        (where ${proxyOperations.capacity_released_at} is null
          and ${proxyOperations.id} <> ${input.operationId}), 0)::bigint`,
    }).from(proxyOperations).where(eq(proxyOperations.operator_id, input.operatorId));
    const used = Number(capacity?.used ?? 0);
    if (used + input.capacityBytes > PROXY_REPLAY_CAPACITY_BYTES) {
      return { state: 'capacity_exceeded', kind: 'replay_bytes', limit: PROXY_REPLAY_CAPACITY_BYTES, used };
    }
    const nextFence = operation.dispatch_fence + 1;
    const nextAttempt = operation.transport_attempts + 1;
    const [claimed] = await db.update(proxyOperations).set({
      delivery_state: 'dispatching',
      replay_state: 'none',
      dispatch_owner_hash: input.dispatchOwnerHash,
      dispatch_fence: nextFence,
      dispatch_lease_expires_at: input.leaseExpiresAt,
      transport_attempts: nextAttempt,
      // A fresh attempt after a provider-observed absence makes the outcome
      // unresolved again. Confirmed evidence is retained: the retry uses the
      // same native key to recover that already-observed resource, and the
      // historical provider fact must not be erased.
      reconciliation_state: sql`case when ${proxyOperations.reconciliation_state} = 'not_found' then 'pending' else ${proxyOperations.reconciliation_state} end`,
      reconciliation_resource_hash: sql`case when ${proxyOperations.reconciliation_state} = 'not_found' then null else ${proxyOperations.reconciliation_resource_hash} end`,
      reconciliation_evidence_hash: sql`case when ${proxyOperations.reconciliation_state} = 'not_found' then null else ${proxyOperations.reconciliation_evidence_hash} end`,
      reconciliation_provider_status: sql`case when ${proxyOperations.reconciliation_state} = 'not_found' then null else ${proxyOperations.reconciliation_provider_status} end`,
      response_status: null,
      response_hash: null,
      response_envelope_version: null,
      response_encrypted: null,
      response_key_ref: null,
      response_ciphertext_bytes: null,
      response_readable_until: null,
      response_received_at: null,
      capacity_reserved_bytes: input.capacityBytes,
      capacity_used_bytes: 0,
      capacity_released_at: null,
      updated_at: new Date(),
    }).where(and(
      eq(proxyOperations.id, input.operationId),
      eq(proxyOperations.operator_id, input.operatorId),
      inArray(proxyOperations.delivery_state, ['outcome_unknown', 'response_received']),
      eq(proxyOperations.dispatch_fence, operation.dispatch_fence),
      eq(proxyOperations.transport_attempts, operation.transport_attempts),
      inArray(proxyOperations.reconciliation_state, ['pending', 'not_found', 'confirmed']),
      inArray(proxyOperations.replay_state, ['none', 'screening', 'available']),
      sql`${proxyOperations.prepared_request_encrypted} is not null`,
      gt(proxyOperations.prepared_request_readable_until, new Date()),
    )).returning();
    if (!claimed) return { state: 'busy', operation };
    await insertAttempt(db, claimed, input.dispatchOwnerHash, input.leaseExpiresAt, input.requestEvidenceHash);
    return { state: 'acquired', operation: claimed, dispatchFence: claimed.dispatch_fence };
  };
  return transaction ? execute(transaction) : database.transaction(execute);
}

export async function releaseBeforeDispatch(db: Database, input: {
  operatorId: string; operationId: string; admissionOwnerHash: string; admissionFence: number;
}): Promise<boolean> {
  const rows = await db.update(proxyOperations).set({
    accounting_state: 'released', accounting_released_at: new Date(), replay_state: 'erased',
    prepared_request_encrypted: null, prepared_request_key_ref: null,
    scope_descriptor_encrypted: null, scope_descriptor_key_ref: null,
    capacity_reserved_bytes: 0, capacity_used_bytes: 0, capacity_released_at: new Date(),
    erased_at: new Date(), updated_at: new Date(),
  }).where(and(eq(proxyOperations.id, input.operationId), eq(proxyOperations.operator_id, input.operatorId),
    eq(proxyOperations.delivery_state, 'admitted'), eq(proxyOperations.accounting_state, 'reserved'),
    eq(proxyOperations.admission_owner_hash, input.admissionOwnerHash),
    eq(proxyOperations.admission_fence, input.admissionFence))).returning({ id: proxyOperations.id });
  return rows.length === 1;
}
