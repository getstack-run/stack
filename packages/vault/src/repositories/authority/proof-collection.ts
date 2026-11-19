import { and, eq, lte, sql } from 'drizzle-orm';
import { ConflictError, authorityIdempotencyKeys } from '@stack/shared';
import type { AuthorityProofCollectionWorkflowRecord } from '../../services/authority/contracts.js';
import { sha256 as digest } from '../../services/authority/digest.js';
import { AuthorityAggregateRepository } from './context.js';

function proofCollectionWorkflowRow(
  row: typeof authorityIdempotencyKeys.$inferSelect | null | undefined,
): AuthorityProofCollectionWorkflowRecord | null {
  if (!row || row.resource_type !== 'proof_collection_session' || !row.resource_id
    || !row.workflow_payload_encrypted || !row.workflow_phase
    || !['reserved', 'initiating', 'ready', 'callback_verifying', 'callback_verified', 'completed', 'failed']
      .includes(row.workflow_phase)) return null;
  return {
    ledger_id: row.id,
    operator_id: row.operator_id,
    session_id: row.resource_id,
    request_hash: row.request_hash,
    state: row.state as 'started' | 'completed',
    response_status: row.response_status,
    response_body: row.response_body,
    workflow_phase: row.workflow_phase as AuthorityProofCollectionWorkflowRecord['workflow_phase'],
    workflow_payload_encrypted: row.workflow_payload_encrypted,
    lease_token_hash: row.lease_token_hash,
    lease_expires_at: row.lease_expires_at,
    expires_at: row.expires_at,
  };
}

/** The proof-collection session workflow, stored as rows of the idempotency ledger. */
export class AuthorityProofCollectionRepository extends AuthorityAggregateRepository {
  async reserveProofCollectionWorkflow(input: {
    ledgerId: string; operatorId: string; sessionId: string; idempotencyKey: string; requestHash: string;
    workflowPayloadEncrypted: string; expiresAt: Date; now: Date;
  }) {
    return this.db.transaction(async (tx) => {
      const keyHash = digest(input.idempotencyKey);
      await tx.delete(authorityIdempotencyKeys).where(and(
        eq(authorityIdempotencyKeys.operator_id, input.operatorId),
        eq(authorityIdempotencyKeys.route_key, 'proof.collection.create'),
        lte(authorityIdempotencyKeys.expires_at, input.now),
      ));
      const [created] = await tx.insert(authorityIdempotencyKeys).values({
        id: input.ledgerId, operator_id: input.operatorId, route_key: 'proof.collection.create',
        idempotency_key_hash: keyHash, request_hash: input.requestHash, state: 'started',
        resource_type: 'proof_collection_session', resource_id: input.sessionId,
        workflow_phase: 'reserved', workflow_payload_encrypted: input.workflowPayloadEncrypted,
        created_at: input.now, updated_at: input.now, expires_at: input.expiresAt,
      }).onConflictDoNothing().returning();
      const row = created ?? (await tx.select().from(authorityIdempotencyKeys).where(and(
        eq(authorityIdempotencyKeys.operator_id, input.operatorId),
        eq(authorityIdempotencyKeys.route_key, 'proof.collection.create'),
        eq(authorityIdempotencyKeys.idempotency_key_hash, keyHash),
      )).limit(1))[0];
      const workflow = proofCollectionWorkflowRow(row);
      if (!workflow) throw new ConflictError('proof collection reservation is invalid or expired');
      return { workflow, created: Boolean(created) };
    });
  }

  async findProofCollectionWorkflow(sessionId: string, operatorId?: string) {
    const conditions = [eq(authorityIdempotencyKeys.route_key, 'proof.collection.create'),
      eq(authorityIdempotencyKeys.resource_id, sessionId)];
    if (operatorId) conditions.push(eq(authorityIdempotencyKeys.operator_id, operatorId));
    const [row] = await this.db.select().from(authorityIdempotencyKeys).where(and(...conditions)).limit(1);
    return proofCollectionWorkflowRow(row);
  }

  async acquireProofCollectionWorkflowLease(input: {
    operatorId: string; sessionId: string; from: Array<AuthorityProofCollectionWorkflowRecord['workflow_phase']>;
    to: 'initiating' | 'callback_verifying'; leaseTokenHash: string; leaseExpiresAt: Date; now: Date;
  }) {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`select id from ${authorityIdempotencyKeys}
        where operator_id=${input.operatorId} and route_key='proof.collection.create'
          and resource_id=${input.sessionId} for update`);
      const [row] = await tx.select().from(authorityIdempotencyKeys).where(and(
        eq(authorityIdempotencyKeys.operator_id, input.operatorId),
        eq(authorityIdempotencyKeys.route_key, 'proof.collection.create'),
        eq(authorityIdempotencyKeys.resource_id, input.sessionId),
      )).limit(1);
      const workflow = proofCollectionWorkflowRow(row);
      if (!workflow || workflow.expires_at <= input.now) return null;
      const resumableLease = workflow.workflow_phase === input.to
        && workflow.lease_expires_at !== null && workflow.lease_expires_at <= input.now;
      if (!input.from.includes(workflow.workflow_phase) && !resumableLease) {
        return { workflow, acquired: false };
      }
      const [updated] = await tx.update(authorityIdempotencyKeys).set({
        workflow_phase: input.to, lease_token_hash: input.leaseTokenHash,
        lease_expires_at: input.leaseExpiresAt, updated_at: input.now,
      }).where(eq(authorityIdempotencyKeys.id, workflow.ledger_id)).returning();
      const acquired = proofCollectionWorkflowRow(updated);
      return acquired ? { workflow: acquired, acquired: true } : null;
    });
  }

  async transitionProofCollectionWorkflow(input: {
    operatorId: string; sessionId: string; from: AuthorityProofCollectionWorkflowRecord['workflow_phase'];
    leaseTokenHash: string; to: AuthorityProofCollectionWorkflowRecord['workflow_phase'];
    workflowPayloadEncrypted: string; now: Date; safeResponse?: Record<string, unknown>; responseStatus?: number;
  }) {
    const [updated] = await this.db.update(authorityIdempotencyKeys).set({
      workflow_phase: input.to, workflow_payload_encrypted: input.workflowPayloadEncrypted,
      lease_token_hash: null, lease_expires_at: null, updated_at: input.now,
      ...(input.safeResponse ? { state: 'completed', response_body: input.safeResponse,
        response_status: input.responseStatus ?? 200 } : {}),
    }).where(and(eq(authorityIdempotencyKeys.operator_id, input.operatorId),
      eq(authorityIdempotencyKeys.route_key, 'proof.collection.create'),
      eq(authorityIdempotencyKeys.resource_id, input.sessionId),
      eq(authorityIdempotencyKeys.workflow_phase, input.from),
      eq(authorityIdempotencyKeys.lease_token_hash, input.leaseTokenHash))).returning();
    return proofCollectionWorkflowRow(updated);
  }
}
