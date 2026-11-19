// Policies and the actions they hold for a person.
//
// Every write to a policy is one transaction that locks the row, checks the
// revision the caller read, changes the row and appends its revision. A
// revision is compare-and-swap on the revision number, so two callers can never
// both apply a change that each judged against the same stored policy.

import { and, asc, desc, eq, gt, inArray, isNull, lte, sql } from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';
import {
  agentServiceGrants,
  ConflictError,
  controlPolicies,
  controlPolicyRevisions,
  controlReviews,
  ids,
  operators,
  serviceConnections,
  type Constraint,
  type ControlPolicyRevisionRow,
  type ControlPolicyRow,
  type ControlReviewRow,
  type ControlReviewStatus,
  type Database,
  type PolicyChangeKind,
} from '@stack/shared';

export interface ApplyPolicyInput {
  operatorId: string;
  /** Null: the customer's default policy. */
  agentId: string | null;
  /**
   * The revision the caller judged its change against: 0 when it saw no policy
   * (a create), otherwise the stored revision. A different stored revision is a
   * conflict, never an overwrite.
   */
  expectedRevision: number;
  /** The new definition, or null to delete the policy. */
  next: { name: string; definition: Record<string, unknown>; digest: string } | null;
  change: Exclude<PolicyChangeKind, 'unchanged'>;
  actor: string;
  approvalId?: string | null;
}

const scopeCondition = (operatorId: string, agentId: string | null) =>
  and(
    eq(controlPolicies.operator_id, operatorId),
    eq(controlPolicies.status, 'active'),
    agentId === null ? isNull(controlPolicies.agent_id) : eq(controlPolicies.agent_id, agentId),
  );

export class ControlPolicyRepository {
  constructor(protected readonly db: Database) {}

  async get(operatorId: string, agentId: string | null): Promise<ControlPolicyRow | null> {
    const [row] = await this.db.select().from(controlPolicies).where(scopeCondition(operatorId, agentId)).limit(1);
    return row ?? null;
  }

  /** The agent's own policy and the customer's default, in one read. */
  async forAgent(operatorId: string, agentId: string | null): Promise<{ agent: ControlPolicyRow | null; fallback: ControlPolicyRow | null }> {
    const rows = await this.db
      .select()
      .from(controlPolicies)
      .where(
        and(
          eq(controlPolicies.operator_id, operatorId),
          eq(controlPolicies.status, 'active'),
          agentId === null ? isNull(controlPolicies.agent_id) : sql`(${controlPolicies.agent_id} IS NULL OR ${controlPolicies.agent_id} = ${agentId})`,
        ),
      );
    return {
      agent: agentId === null ? null : (rows.find((row) => row.agent_id === agentId) ?? null),
      fallback: rows.find((row) => row.agent_id === null) ?? null,
    };
  }

  async list(operatorId: string): Promise<ControlPolicyRow[]> {
    return this.db
      .select()
      .from(controlPolicies)
      .where(and(eq(controlPolicies.operator_id, operatorId), eq(controlPolicies.status, 'active')))
      .orderBy(asc(controlPolicies.created_at), asc(controlPolicies.id));
  }

  async revisions(operatorId: string, policyId: string, limit = 50): Promise<ControlPolicyRevisionRow[]> {
    return this.db
      .select()
      .from(controlPolicyRevisions)
      .where(and(eq(controlPolicyRevisions.operator_id, operatorId), eq(controlPolicyRevisions.policy_id, policyId)))
      .orderBy(desc(controlPolicyRevisions.revision))
      .limit(limit);
  }

  async revision(operatorId: string, policyId: string, revision: number): Promise<ControlPolicyRevisionRow | null> {
    const [row] = await this.db
      .select()
      .from(controlPolicyRevisions)
      .where(
        and(
          eq(controlPolicyRevisions.operator_id, operatorId),
          eq(controlPolicyRevisions.policy_id, policyId),
          eq(controlPolicyRevisions.revision, revision),
        ),
      )
      .limit(1);
    return row ?? null;
  }

  /**
   * Create, revise or delete one policy. Returns the policy as it is after
   * (for a delete, the row marked deleted).
   */
  async apply(input: ApplyPolicyInput): Promise<ControlPolicyRow> {
    return this.db.transaction(async (tx) => {
      const [current] = await tx
        .select()
        .from(controlPolicies)
        .where(scopeCondition(input.operatorId, input.agentId))
        .for('update')
        .limit(1);
      const seen = current?.revision ?? 0;
      if (seen !== input.expectedRevision) {
        throw new ConflictError('This policy changed since it was read; read it again and retry');
      }
      if (input.next === null) {
        if (!current) throw new ConflictError('There is no policy to delete');
        const [deleted] = await tx
          .update(controlPolicies)
          .set({ status: 'deleted', revision: current.revision + 1, last_change: 'delete', updated_at: new Date() })
          .where(eq(controlPolicies.id, current.id))
          .returning();
        await this.appendRevision(tx, deleted!, input, 'delete');
        return deleted!;
      }
      if (!current) {
        const id = ids.controlPolicy();
        let created: ControlPolicyRow | undefined;
        try {
          [created] = await tx
            .insert(controlPolicies)
            .values({
              id,
              operator_id: input.operatorId,
              agent_id: input.agentId,
              name: input.next.name,
              revision: 1,
              definition: input.next.definition,
              definition_digest: input.next.digest,
              last_change: input.change,
            })
            .returning();
        } catch (error) {
          // Two creates for one scope: the unique index let one through.
          if ((error as { code?: string; cause?: { code?: string } }).code === '23505' || (error as { cause?: { code?: string } }).cause?.code === '23505') {
            throw new ConflictError('A policy was created for this agent at the same time; read it and retry');
          }
          throw error;
        }
        await this.appendRevision(tx, created!, input, input.change);
        return created!;
      }
      const [updated] = await tx
        .update(controlPolicies)
        .set({
          name: input.next.name,
          definition: input.next.definition,
          definition_digest: input.next.digest,
          revision: current.revision + 1,
          last_change: input.change,
          updated_at: new Date(),
        })
        .where(eq(controlPolicies.id, current.id))
        .returning();
      await this.appendRevision(tx, updated!, input, input.change);
      return updated!;
    });
  }

  /** The provider of each of these connections, within one customer. */
  async connectionProviders(operatorId: string, connectionIds: readonly string[]): Promise<Map<string, string>> {
    if (connectionIds.length === 0) return new Map();
    const rows = await this.db
      .select({ id: serviceConnections.id, provider: serviceConnections.provider })
      .from(serviceConnections)
      .where(and(eq(serviceConnections.operator_id, operatorId), inArray(serviceConnections.id, [...connectionIds])));
    return new Map(rows.map((row) => [row.id, row.provider]));
  }

  /** What an agent holds a live grant for: the connection and the constraints the grant already carries. */
  async grantsOf(operatorId: string, agentId: string): Promise<Array<{ connection_id: string; constraints: Constraint[] | null }>> {
    const rows = await this.db
      .select({ connection_id: agentServiceGrants.service_connection_id, constraints: agentServiceGrants.constraints })
      .from(agentServiceGrants)
      .innerJoin(serviceConnections, eq(serviceConnections.id, agentServiceGrants.service_connection_id))
      .where(
        and(
          eq(agentServiceGrants.agent_id, agentId),
          isNull(agentServiceGrants.revoked_at),
          eq(serviceConnections.operator_id, operatorId),
          eq(serviceConnections.status, 'active'),
        ),
      );
    return rows;
  }

  /**
   * The agents of this customer's accounts that are still in use. An install without agent accounts has none; a
   * deployment that sells them reads its own table.
   */
  async accountAgents(_operatorId: string): Promise<string[]> {
    return [];
  }

  /**
   * The active white-label tenants of an active partner. A tenant's controls
   * follow its partner's, but its policies, sockets and accounts are its own.
   * Empty for an operator that is not an active top-level partner.
   */
  async tenantsOf(partnerOperatorId: string): Promise<string[]> {
    const partner = alias(operators, 'policy_partner');
    const rows = await this.db
      .select({ id: operators.id })
      .from(operators)
      .innerJoin(partner, eq(partner.id, operators.parent_operator_id))
      .where(
        and(
          eq(partner.id, partnerOperatorId),
          eq(partner.is_partner, true),
          eq(partner.status, 'active'),
          isNull(partner.parent_operator_id),
          eq(operators.status, 'active'),
        ),
      )
      .orderBy(asc(operators.id));
    return rows.map((row) => row.id);
  }

  /** The account an agent runs, when it runs one of this customer's. An install without agent accounts has none. */
  async accountOfAgent(_operatorId: string, _agentId: string): Promise<{ accountId: string; missionId: string | null } | null> {
    return null;
  }

  /** The agent an account belongs to. Fixed for the life of the account. An install without agent accounts has none. */
  async agentOfAccount(_accountId: string): Promise<{ operatorId: string; agentId: string } | null> {
    return null;
  }

  private async appendRevision(
    tx: Parameters<Parameters<Database['transaction']>[0]>[0],
    row: ControlPolicyRow,
    input: ApplyPolicyInput,
    change: Exclude<PolicyChangeKind, 'unchanged'>,
  ): Promise<void> {
    await tx.insert(controlPolicyRevisions).values({
      policy_id: row.id,
      revision: row.revision,
      operator_id: row.operator_id,
      agent_id: row.agent_id,
      definition: row.definition,
      definition_digest: row.definition_digest,
      change,
      actor: input.actor,
      approval_id: input.approvalId ?? null,
    });
  }
}

// ─── reviews ────────────────────────────────────────────────────────

export type ControlReviewInsert = typeof controlReviews.$inferInsert;
const LIVE_REVIEW_STATUSES: ControlReviewStatus[] = ['pending', 'approved', 'consuming'];

/**
 * The held actions of a customer. Each transition is a compare-and-swap, the
 * intent approval gate's own pattern: of two requests presenting one approval
 * at the same instant, exactly one reserves it.
 */
export class ControlReviewRepository {
  constructor(private readonly db: Database) {}

  async get(operatorId: string, id: string): Promise<ControlReviewRow | null> {
    const [row] = await this.db
      .select()
      .from(controlReviews)
      .where(and(eq(controlReviews.operator_id, operatorId), eq(controlReviews.id, id)))
      .limit(1);
    return row ?? null;
  }

  /** The live review for exactly this call, if one is open. */
  async findLive(operatorId: string, callDigest: string): Promise<ControlReviewRow | null> {
    const [row] = await this.db
      .select()
      .from(controlReviews)
      .where(
        and(
          eq(controlReviews.operator_id, operatorId),
          eq(controlReviews.call_digest, callDigest),
          inArray(controlReviews.status, LIVE_REVIEW_STATUSES),
        ),
      )
      .limit(1);
    return row ?? null;
  }

  /** Insert a review; a second live review for the same call returns the one that is there. */
  async insert(row: ControlReviewInsert): Promise<{ row: ControlReviewRow; created: boolean }> {
    const [created] = await this.db.insert(controlReviews).values(row).onConflictDoNothing().returning();
    if (created) return { row: created, created: true };
    const existing = await this.findLive(row.operator_id, row.call_digest);
    if (!existing) throw new ConflictError('The review could not be opened; retry');
    return { row: existing, created: false };
  }

  async list(operatorId: string, query: { statuses?: ControlReviewStatus[]; limit: number }): Promise<ControlReviewRow[]> {
    return this.db
      .select()
      .from(controlReviews)
      .where(
        and(
          eq(controlReviews.operator_id, operatorId),
          query.statuses ? inArray(controlReviews.status, query.statuses) : undefined,
        ),
      )
      .orderBy(desc(controlReviews.created_at), desc(controlReviews.id))
      .limit(query.limit);
  }

  /** pending -> approved, once: the person said yes, and the agent may retry for a while. */
  async approve(id: string, expiresAt: Date, now: Date): Promise<ControlReviewRow | null> {
    const [row] = await this.db
      .update(controlReviews)
      .set({ status: 'approved', decided_at: now, expires_at: expiresAt })
      .where(and(eq(controlReviews.id, id), eq(controlReviews.status, 'pending')))
      .returning();
    return row ?? null;
  }

  /** pending -> rejected or expired. */
  async close(id: string, status: 'rejected' | 'expired', now: Date): Promise<ControlReviewRow | null> {
    const [row] = await this.db
      .update(controlReviews)
      .set({ status, decided_at: now })
      .where(and(eq(controlReviews.id, id), eq(controlReviews.status, 'pending')))
      .returning();
    return row ?? null;
  }

  /** approved -> consuming, by exactly one operation. */
  async reserve(id: string, ownerHash: string, now: Date): Promise<ControlReviewRow | null> {
    const [row] = await this.db
      .update(controlReviews)
      .set({ status: 'consuming', consuming_owner_hash: ownerHash })
      .where(and(eq(controlReviews.id, id), eq(controlReviews.status, 'approved'), gt(controlReviews.expires_at, now)))
      .returning();
    return row ?? null;
  }

  /** consuming -> consumed, by the operation that reserved it. */
  async consume(id: string, ownerHash: string): Promise<boolean> {
    const rows = await this.db
      .update(controlReviews)
      .set({ status: 'consumed' })
      .where(and(eq(controlReviews.id, id), eq(controlReviews.status, 'consuming'), eq(controlReviews.consuming_owner_hash, ownerHash)))
      .returning({ id: controlReviews.id });
    return rows.length > 0;
  }

  /** consuming -> approved: the action did not run, so the same approval may be used again. */
  async release(id: string, ownerHash: string): Promise<boolean> {
    const rows = await this.db
      .update(controlReviews)
      .set({ status: 'approved', consuming_owner_hash: null })
      .where(and(eq(controlReviews.id, id), eq(controlReviews.status, 'consuming'), eq(controlReviews.consuming_owner_hash, ownerHash)))
      .returning({ id: controlReviews.id });
    return rows.length > 0;
  }

  /** Pending reviews past their time become `expired`, at most `limit` at a time, returned so each agent can be told. */
  async expirePendingDue(now: Date, limit: number): Promise<ControlReviewRow[]> {
    const due = this.db
      .select({ id: controlReviews.id })
      .from(controlReviews)
      .where(and(eq(controlReviews.status, 'pending'), lte(controlReviews.expires_at, now)))
      .limit(limit);
    return this.db
      .update(controlReviews)
      .set({ status: 'expired', decided_at: now })
      .where(and(inArray(controlReviews.id, due), eq(controlReviews.status, 'pending'), lte(controlReviews.expires_at, now)))
      .returning();
  }

  /**
   * Approved reviews past their use window lapse unused. A pending one is not closed here: it ends through
   * `expirePendingDue` or the review's own sync, which tell the agent waiting on it.
   */
  async expireDue(now: Date): Promise<number> {
    const rows = await this.db
      .update(controlReviews)
      .set({ status: 'expired', decided_at: now })
      .where(and(inArray(controlReviews.status, ['approved', 'consuming']), lte(controlReviews.expires_at, now)))
      .returning({ id: controlReviews.id });
    return rows.length;
  }
}
