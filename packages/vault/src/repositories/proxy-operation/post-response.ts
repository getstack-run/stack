// Post-response work queue: lease one stored operation, mark each completed step, and release it
// for retry, provider wait or completion.

import { and, asc, eq, inArray, isNull, lte, or, sql } from 'drizzle-orm';
import { type Database, proxyOperations } from '@stack/shared';
import {
  type ProxyOperationRow,
  type ProxyOperationInsert,
  type ProxyPostResponseStep,
} from './types.js';

export async function claimPostResponseWork(db: Database, input: {
  ownerHash: string;
  leaseExpiresAt: Date;
  operationId?: string;
  now?: Date;
}): Promise<ProxyOperationRow | null> {
  const now = input.now ?? new Date();
  return db.transaction(async (tx) => {
    const eligible = or(
      and(
        eq(proxyOperations.post_response_work_state, 'pending'),
        or(
          isNull(proxyOperations.post_response_next_attempt_at),
          lte(proxyOperations.post_response_next_attempt_at, now),
        ),
      ),
      and(
        eq(proxyOperations.post_response_work_state, 'processing'),
        lte(proxyOperations.post_response_lease_expires_at, now),
      ),
      and(
        eq(proxyOperations.post_response_work_state, 'waiting_provider'),
        eq(proxyOperations.reconciliation_state, 'confirmed'),
        inArray(proxyOperations.reconciliation_provider_status, ['succeeded', 'failed', 'canceled']),
      ),
    );
    const [candidate] = await tx.select().from(proxyOperations).where(and(
      input.operationId ? eq(proxyOperations.id, input.operationId) : undefined,
      eligible,
      sql`${proxyOperations.post_response_context_encrypted} is not null`,
    )).orderBy(asc(proxyOperations.response_received_at), asc(proxyOperations.id)).limit(1);
    if (!candidate) return null;
    const [claimed] = await tx.update(proxyOperations).set({
      post_response_work_state: 'processing',
      post_response_owner_hash: input.ownerHash,
      post_response_lease_expires_at: input.leaseExpiresAt,
      post_response_next_attempt_at: null,
      post_response_attempts: sql`${proxyOperations.post_response_attempts} + 1`,
      updated_at: now,
    }).where(and(
      eq(proxyOperations.id, candidate.id),
      eq(proxyOperations.operator_id, candidate.operator_id),
      eq(proxyOperations.post_response_work_state, candidate.post_response_work_state),
      candidate.post_response_owner_hash === null
        ? isNull(proxyOperations.post_response_owner_hash)
        : eq(proxyOperations.post_response_owner_hash, candidate.post_response_owner_hash),
      candidate.post_response_lease_expires_at === null
        ? isNull(proxyOperations.post_response_lease_expires_at)
        : eq(proxyOperations.post_response_lease_expires_at, candidate.post_response_lease_expires_at),
      candidate.post_response_next_attempt_at === null
        ? isNull(proxyOperations.post_response_next_attempt_at)
        : eq(proxyOperations.post_response_next_attempt_at, candidate.post_response_next_attempt_at),
    )).returning();
    return claimed ?? null;
  });
}

export async function markPostResponseStep(db: Database, input: {
  operatorId: string;
  operationId: string;
  ownerHash: string;
  step: ProxyPostResponseStep;
  intentClaimId?: string;
  outcomeClaimId?: string;
  now?: Date;
}): Promise<ProxyOperationRow | null> {
  const field = {
    credential: 'post_response_credential_at',
    audit: 'post_response_audit_at',
    claims: 'post_response_claims_at',
    security: 'post_response_security_at',
    analytics: 'post_response_analytics_at',
    authority: 'post_response_authority_at',
  }[input.step] as keyof ProxyOperationInsert;
  const [row] = await db.update(proxyOperations).set({
    [field]: input.now ?? new Date(),
    ...(input.step === 'claims' ? {
      post_response_intent_claim_id: input.intentClaimId ?? null,
      post_response_outcome_claim_id: input.outcomeClaimId ?? null,
    } : {}),
    updated_at: input.now ?? new Date(),
  }).where(and(
    eq(proxyOperations.id, input.operationId),
    eq(proxyOperations.operator_id, input.operatorId),
    eq(proxyOperations.post_response_work_state, 'processing'),
    eq(proxyOperations.post_response_owner_hash, input.ownerHash),
  )).returning();
  return row ?? null;
}

export async function releasePostResponseWork(db: Database, input: {
  operatorId: string;
  operationId: string;
  ownerHash: string;
  waitingForProvider?: boolean;
  complete?: boolean;
  retryAt?: Date;
  now?: Date;
}): Promise<boolean> {
  const now = input.now ?? new Date();
  const rows = await db.update(proxyOperations).set({
    post_response_work_state: input.complete
      ? 'completed'
      : input.waitingForProvider ? 'waiting_provider' : 'pending',
    post_response_owner_hash: null,
    post_response_lease_expires_at: null,
    post_response_next_attempt_at: input.complete || input.waitingForProvider
      ? null
      : input.retryAt ?? new Date(now.getTime() + 1_000),
    ...(input.complete ? {
      post_response_context_encrypted: null,
      post_response_context_key_ref: null,
      post_response_completed_at: now,
    } : {}),
    updated_at: now,
  }).where(and(
    eq(proxyOperations.id, input.operationId),
    eq(proxyOperations.operator_id, input.operatorId),
    eq(proxyOperations.post_response_work_state, 'processing'),
    eq(proxyOperations.post_response_owner_hash, input.ownerHash),
  )).returning({ id: proxyOperations.id });
  return rows.length === 1;
}

/**
 * Work that is queued (waiting its turn, or waiting for a provider) and still holds its stored context, in id order after
 * `afterId`. Work someone is processing is left alone: it clears its context when it completes.
 */
export async function listQueuedPostResponseContexts(db: Database, input: {
  afterId?: string;
  limit: number;
}): Promise<Array<Pick<ProxyOperationRow, 'id' | 'operator_id' | 'post_response_context_encrypted'>>> {
  return db.select({
    id: proxyOperations.id,
    operator_id: proxyOperations.operator_id,
    post_response_context_encrypted: proxyOperations.post_response_context_encrypted,
  }).from(proxyOperations).where(and(
    inArray(proxyOperations.post_response_work_state, ['pending', 'waiting_provider']),
    sql`${proxyOperations.post_response_context_encrypted} is not null`,
    input.afterId ? sql`${proxyOperations.id} > ${input.afterId}` : undefined,
  )).orderBy(asc(proxyOperations.id)).limit(input.limit);
}

/**
 * Put a rewritten context in place of the one that was read, only while the work is still queued and the stored
 * context is still that one (a worker that claimed it meanwhile, or a change, wins and nothing is written).
 */
export async function replacePostResponseContext(db: Database, input: {
  operatorId: string;
  operationId: string;
  expectedCiphertext: string;
  ciphertext: string;
  keyRef: string;
  now?: Date;
}): Promise<boolean> {
  const rows = await db.update(proxyOperations).set({
    post_response_context_encrypted: input.ciphertext,
    post_response_context_key_ref: input.keyRef,
    updated_at: input.now ?? new Date(),
  }).where(and(
    eq(proxyOperations.id, input.operationId),
    eq(proxyOperations.operator_id, input.operatorId),
    inArray(proxyOperations.post_response_work_state, ['pending', 'waiting_provider']),
    eq(proxyOperations.post_response_context_encrypted, input.expectedCiphertext),
  )).returning({ id: proxyOperations.id });
  return rows.length === 1;
}
