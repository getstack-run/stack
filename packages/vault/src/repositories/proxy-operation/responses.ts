// Dispatch outcomes written by the fenced owner: response screening, the stored response, and
// the honest unknown outcome when a dispatch lease dies.

import { and, eq, inArray, lte, notInArray, sql } from 'drizzle-orm';
import { type Database, proxyOperationAttempts, proxyOperations } from '@stack/shared';
import { ownsDispatch } from './internals.js';
import { appendLateResponseEvidenceInTransaction } from './reconciliation.js';
import { type ProxyOperationRow, type FencedDispatch } from './types.js';

export async function markResponseScreening(db: Database, input: FencedDispatch): Promise<boolean> {
  const rows = await db.update(proxyOperations).set({ replay_state: 'screening', updated_at: new Date() })
    .where(and(
      ownsDispatch(input, ['dispatching', 'outcome_unknown']),
      inArray(proxyOperations.replay_state, ['none', 'screening']),
      notInArray(proxyOperations.reconciliation_state, ['contradictory', 'expired']),
    )).returning({ id: proxyOperations.id });
  return rows.length === 1;
}

export async function storeResponse(db: Database, input: FencedDispatch & {
  status: number;
  responseHash: string;
  ciphertext: string;
  keyRef: string;
  ciphertextBytes: number;
  readableUntil: Date;
  transportEvidenceHash: string;
  providerRequestIdHash?: string;
  postResponseContext?: { ciphertext: string; keyRef: string };
}): Promise<ProxyOperationRow | null> {
  return db.transaction(async (tx) => {
    const [row] = await tx.update(proxyOperations).set({
      delivery_state: 'response_received', replay_state: 'available',
      response_status: input.status, response_hash: input.responseHash,
      response_envelope_version: 1, response_encrypted: input.ciphertext,
      response_key_ref: input.keyRef, response_ciphertext_bytes: input.ciphertextBytes,
      response_readable_until: input.readableUntil, response_received_at: new Date(),
      ...(input.postResponseContext ? {
        post_response_work_state: 'pending',
        post_response_next_attempt_at: new Date(),
        post_response_context_version: 1,
        post_response_context_encrypted: input.postResponseContext.ciphertext,
        post_response_context_key_ref: input.postResponseContext.keyRef,
      } : {}),
      capacity_reserved_bytes: input.ciphertextBytes,
      capacity_used_bytes: input.ciphertextBytes,
      dispatch_lease_expires_at: null, outcome_unknown_at: null, updated_at: new Date(),
    }).where(and(
      ownsDispatch(input, ['dispatching', 'outcome_unknown']),
      sql`${input.ciphertextBytes} <= ${proxyOperations.capacity_reserved_bytes}`,
      inArray(proxyOperations.replay_state, ['none', 'screening']),
      notInArray(proxyOperations.reconciliation_state, ['contradictory', 'expired']),
    )).returning();
    if (!row) {
      await appendLateResponseEvidenceInTransaction({
        operatorId: input.operatorId,
        operationId: input.operationId,
        dispatchOwnerHash: input.dispatchOwnerHash,
        dispatchFence: input.dispatchFence,
        status: input.status,
        evidenceHash: input.transportEvidenceHash,
      }, tx);
      return null;
    }
    await tx.update(proxyOperationAttempts).set({
      outcome: 'response_received', response_status: input.status,
      transport_evidence_hash: input.transportEvidenceHash,
      provider_request_id_hash: input.providerRequestIdHash ?? null,
      completed_at: new Date(),
    }).where(and(
      eq(proxyOperationAttempts.operation_id, input.operationId),
      eq(proxyOperationAttempts.attempt_number, row.transport_attempts),
      eq(proxyOperationAttempts.dispatch_owner_hash, input.dispatchOwnerHash),
      eq(proxyOperationAttempts.dispatch_fence, input.dispatchFence),
    ));
    return row;
  });
}

export async function markOutcomeUnknown(
  db: Database,
  input: FencedDispatch & { transportEvidenceHash?: string },
): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [row] = await tx.update(proxyOperations).set({
      delivery_state: 'outcome_unknown',
      replay_state: sql`case when ${proxyOperations.replay_state} in ('expired', 'erased')
        then ${proxyOperations.replay_state} else 'none' end`,
      outcome_unknown_at: new Date(),
      dispatch_lease_expires_at: null, updated_at: new Date(),
    }).where(ownsDispatch(input, ['dispatching'])).returning();
    if (!row) return false;
    await tx.update(proxyOperationAttempts).set({
      outcome: 'outcome_unknown', transport_evidence_hash: input.transportEvidenceHash ?? null,
      completed_at: new Date(),
    }).where(and(eq(proxyOperationAttempts.operation_id, input.operationId),
      eq(proxyOperationAttempts.attempt_number, row.transport_attempts),
      eq(proxyOperationAttempts.dispatch_owner_hash, input.dispatchOwnerHash),
      eq(proxyOperationAttempts.dispatch_fence, input.dispatchFence)));
    return true;
  });
}

/**
 * A dead dispatch owner never hands a generic write to a new owner. Expiry
 * only makes the uncertainty visible; the original fenced owner may still
 * record a late response or contradictory provider evidence.
 */
export async function markExpiredDispatchesUnknown(
  db: Database,
  now = new Date(),
): Promise<number> {
  return db.transaction(async (tx) => {
    const rows = await tx.update(proxyOperations).set({
      delivery_state: 'outcome_unknown',
      replay_state: sql`case when ${proxyOperations.replay_state} in ('expired', 'erased')
        then ${proxyOperations.replay_state} else 'none' end`,
      outcome_unknown_at: now,
      dispatch_lease_expires_at: null,
      updated_at: now,
    }).where(and(
      eq(proxyOperations.delivery_state, 'dispatching'),
      lte(proxyOperations.dispatch_lease_expires_at, now),
    )).returning({
      id: proxyOperations.id,
      attempt: proxyOperations.transport_attempts,
      owner: proxyOperations.dispatch_owner_hash,
      fence: proxyOperations.dispatch_fence,
    });
    for (const row of rows) {
      if (!row.owner) continue;
      await tx.update(proxyOperationAttempts).set({
        outcome: 'outcome_unknown',
        completed_at: now,
      }).where(and(
        eq(proxyOperationAttempts.operation_id, row.id),
        eq(proxyOperationAttempts.attempt_number, row.attempt),
        eq(proxyOperationAttempts.dispatch_owner_hash, row.owner),
        eq(proxyOperationAttempts.dispatch_fence, row.fence),
      ));
    }
    return rows.length;
  });
}

/** An outcome_unknown write that has now been unresolved too long, as the sweep that marked it returns it. */
export interface UnresolvedProxyOperation {
  id: string;
  operator_id: string;
  agent_id: string;
  operation_key_hash: string;
  provider: string;
  method: string;
}

/**
 * Writes whose outcome is unknown and that nothing settled since `olderThan` (no late response, no reconciliation that
 * ended them) are marked unresolved, at most `limit` at a time, and returned so their agent and owner can be told. A row
 * moves once; nothing here sends anything again.
 */
export async function markUnresolvedDue(
  db: Database,
  olderThan: Date,
  now: Date,
  limit: number,
): Promise<UnresolvedProxyOperation[]> {
  const due = db.select({ id: proxyOperations.id }).from(proxyOperations).where(and(
    eq(proxyOperations.delivery_state, 'outcome_unknown'),
    sql`${proxyOperations.unresolved_at} is null`,
    lte(proxyOperations.outcome_unknown_at, olderThan),
    // A Stripe write whose reconciliation settled it is not unresolved. One whose reconciliation window ran out
    // (`expired`) settled nothing, and is.
    sql`not (${proxyOperations.reconciliation_state} = 'contradictory'
      or (${proxyOperations.reconciliation_state} = 'confirmed'
        and ${proxyOperations.reconciliation_provider_status} in ('succeeded', 'failed', 'canceled')))`,
  )).limit(limit);
  return db.update(proxyOperations).set({ unresolved_at: now, updated_at: now }).where(and(
    inArray(proxyOperations.id, due),
    eq(proxyOperations.delivery_state, 'outcome_unknown'),
    sql`${proxyOperations.unresolved_at} is null`,
  )).returning({
    id: proxyOperations.id,
    operator_id: proxyOperations.operator_id,
    agent_id: proxyOperations.agent_id,
    operation_key_hash: proxyOperations.operation_key_hash,
    provider: proxyOperations.provider,
    method: proxyOperations.method,
  });
}
