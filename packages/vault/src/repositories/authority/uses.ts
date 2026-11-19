import { and, asc, desc, eq, inArray } from 'drizzle-orm';
import { authorityPresentations, authorityUses } from '@stack/shared';
import type {
  AuthorityDbTransaction,
  AuthorityUseInsert,
  AuthorityUseRecord,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { presentationRow, useRow } from './rows.js';

/** Authority uses: recording a runtime request, authorising it, dispatching it and completing it. */
export class AuthorityUseRepository extends AuthorityAggregateRepository {
  async insertAuthorityUse(input: AuthorityUseInsert) {
    const [row] = await this.db.insert(authorityUses).values({
      ...input,
      disclosure_manifest: input.disclosure_manifest,
    }).returning();
    return useRow(row!);
  }

  async findAuthorityUseByRuntimeRequest(operatorId: string, receiverId: string, receiverRequestId: string) {
    const [row] = await this.db.select().from(authorityUses).where(and(
      eq(authorityUses.operator_id, operatorId), eq(authorityUses.receiver_id, receiverId),
      eq(authorityUses.receiver_request_id, receiverRequestId),
    )).limit(1);
    return row ? useRow(row) : null;
  }

  async authorizeWaitingAuthorityUse(operatorId: string, useId: string, now: Date) {
    const [row] = await this.db.update(authorityUses).set({ status: 'authorized', authorized_at: now,
      denial_code: null }).where(and(eq(authorityUses.operator_id, operatorId), eq(authorityUses.id, useId),
      eq(authorityUses.status, 'waiting_approval'))).returning();
    if (row) return useRow(row);
    const existing = await this.findAuthorityUseForOperator(operatorId, useId);
    return existing?.status === 'authorized' ? existing : null;
  }

  async setAuthorityUseProofStrength(input: {
    operatorId: string;
    useId: string;
    from: AuthorityUseRecord['proof_strength'];
    to: AuthorityUseRecord['proof_strength'];
  }) {
    const [updated] = await this.db.update(authorityUses).set({ proof_strength: input.to }).where(and(
      eq(authorityUses.operator_id, input.operatorId), eq(authorityUses.id, input.useId),
      eq(authorityUses.status, 'authorized'), eq(authorityUses.proof_strength, input.from),
    )).returning();
    if (updated) return useRow(updated);
    const existing = await this.findAuthorityUseForOperator(input.operatorId, input.useId);
    return existing?.status === 'authorized' && existing.proof_strength === input.to ? existing : null;
  }

  async markAuthorityUseDispatched(operatorId: string, useId: string, now: Date) {
    const [updated] = await this.db.update(authorityUses).set({ status: 'dispatched', dispatched_at: now })
      .where(and(eq(authorityUses.operator_id, operatorId), eq(authorityUses.id, useId), eq(authorityUses.status, 'authorized')))
      .returning();
    if (updated) return useRow(updated);
    const existing = await this.findAuthorityUseForOperator(operatorId, useId);
    return existing?.status === 'dispatched' ? existing : null;
  }

  /**
   * Strict dispatch ownership claim for the proxy operation transaction.
   * Unlike the legacy idempotent helper above, an already-dispatched row is
   * never reported as this caller's successful transition.
   */
  async claimAuthorityUseDispatched(
    operatorId: string,
    useId: string,
    now: Date,
    transaction?: AuthorityDbTransaction,
  ) {
    const db = transaction ?? this.transaction ?? this.db;
    const [updated] = await db.update(authorityUses).set({ status: 'dispatched', dispatched_at: now })
      .where(and(
        eq(authorityUses.operator_id, operatorId),
        eq(authorityUses.id, useId),
        eq(authorityUses.status, 'authorized'),
      ))
      .returning();
    return updated ? useRow(updated) : null;
  }

  async completeAuthorityUse(input: {
    operatorId: string; useId: string; outcome: 'succeeded' | 'failed'; resultHash: string;
    intentClaimId?: string; outcomeClaimId?: string; now: Date;
  }) {
    const [updated] = await this.db.update(authorityUses).set({
      status: input.outcome, result_hash: input.resultHash, completed_at: input.now,
      ...(input.intentClaimId ? { intent_claim_id: input.intentClaimId } : {}),
      ...(input.outcomeClaimId ? { outcome_claim_id: input.outcomeClaimId } : {}),
    }).where(and(eq(authorityUses.operator_id, input.operatorId), eq(authorityUses.id, input.useId),
      input.outcome === 'failed'
        ? inArray(authorityUses.status, ['authorized', 'dispatched'])
        : eq(authorityUses.status, 'dispatched'))).returning();
    if (updated) return useRow(updated);
    const existing = await this.findAuthorityUseForOperator(input.operatorId, input.useId);
    if (existing?.status !== input.outcome || existing.result_hash !== input.resultHash) return null;
    return existing;
  }

  async findAuthorityUseById(receiverId: string, useId: string) {
    const [row] = await this.db.select().from(authorityUses).where(and(
      eq(authorityUses.receiver_id, receiverId), eq(authorityUses.id, useId),
    )).limit(1);
    return row ? useRow(row) : null;
  }

  async findAuthorityUseForPresentation(receiverId: string, receiverRequestId: string, requestHash: string) {
    const [row] = await this.db.select().from(authorityUses).where(and(
      eq(authorityUses.receiver_id, receiverId), eq(authorityUses.receiver_request_id, receiverRequestId),
      eq(authorityUses.request_hash, requestHash),
    )).limit(1);
    return row ? useRow(row) : null;
  }

  async listAuthorityUses(operatorId: string) {
    return (await this.db.select().from(authorityUses).where(eq(authorityUses.operator_id, operatorId))
      .orderBy(desc(authorityUses.created_at))).map(useRow);
  }

  async listAgentAuthorityUses(operatorId: string, agentId: string, page: number, limit: number,
    binding?: { id: string; version: number }) {
    const conditions = [eq(authorityUses.operator_id, operatorId), eq(authorityUses.agent_id, agentId)];
    if (binding) conditions.push(eq(authorityUses.binding_id, binding.id), eq(authorityUses.binding_version, binding.version));
    const rows = await this.db.select().from(authorityUses).where(and(...conditions))
      .orderBy(desc(authorityUses.created_at), asc(authorityUses.id)).limit(limit + 1).offset((page - 1) * limit);
    const uses = rows.slice(0, limit).map(useRow);
    // authority_use_id is unique on presentations: at most one per page item.
    const presentations = uses.length === 0 ? [] : await this.db.select().from(authorityPresentations)
      .where(and(eq(authorityPresentations.operator_id, operatorId),
        inArray(authorityPresentations.authority_use_id, uses.map((use) => use.id))));
    return { uses, presentations: presentations.map(presentationRow), has_more: rows.length > limit };
  }

  async findAuthorityUseForOperator(operatorId: string, useId: string) {
    const [row] = await this.db.select().from(authorityUses).where(and(
      eq(authorityUses.operator_id, operatorId), eq(authorityUses.id, useId),
    )).limit(1);
    return row ? useRow(row) : null;
  }
}
