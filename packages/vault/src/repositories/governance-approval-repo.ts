// governance_approvals persistence. Every transition is
// CAS-guarded (intent-approvals pattern): concurrent decide/consume
// races resolve to exactly one winner; losers see undefined and the
// service fails closed.

import { aliasedTable, and, eq, gt, inArray, lt, sql } from 'drizzle-orm';
import { type Database, governanceApprovals, operators } from '@stack/shared';

export type GovernanceApprovalRow = typeof governanceApprovals.$inferSelect;

export class GovernanceApprovalRepository {
  constructor(private db: Database) {}

  async insertIdenticalOnce(input: Parameters<GovernanceApprovalRepository['insert']>[0]) {
    return this.db.transaction(async tx => {
      // Serialize only identical reviews. The lock and insert share a
      // transaction, so retries across processes cannot produce duplicate prompts.
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${JSON.stringify([input.operator_id, input.member_id, input.action, input.resource_id, input.payload_hash])}, 0))`);
      const [existing] = await tx.select().from(governanceApprovals).where(and(
        eq(governanceApprovals.operator_id, input.operator_id), eq(governanceApprovals.action, input.action),
        eq(governanceApprovals.resource_id, input.resource_id), eq(governanceApprovals.payload_hash, input.payload_hash),
        sql`${governanceApprovals.member_id} is not distinct from ${input.member_id}`,
        inArray(governanceApprovals.status, ['pending', 'approved']), gt(governanceApprovals.expires_at, new Date()),
      ));
      if (existing) return { row: existing, created: false };
      const [row] = await tx.insert(governanceApprovals).values(input).returning();
      if (!row) throw new Error('Invalid input');
      return { row, created: true };
    });
  }

  async insert(input: {
    id: string;
    operator_id: string;
    member_id: string | null;
    action: string;
    resource_id: string;
    payload_hash: string;
    summary: string;
    policy_preview?: Record<string, unknown> | null;
    requested_via: string;
    expires_at: Date;
  }): Promise<GovernanceApprovalRow> {
    const [row] = await this.db.insert(governanceApprovals).values(input).returning();
    if (!row) throw new Error('governance_approvals: insert returned no row');
    return row;
  }

  async findById(id: string): Promise<GovernanceApprovalRow | undefined> {
    return this.db.query.governanceApprovals.findFirst({
      where: eq(governanceApprovals.id, id),
    });
  }

  async findByIdForOperator(
    id: string,
    operatorId: string,
  ): Promise<GovernanceApprovalRow | undefined> {
    return this.db.query.governanceApprovals.findFirst({
      where: and(eq(governanceApprovals.id, id), eq(governanceApprovals.operator_id, operatorId)),
    });
  }

  /**
   * approvals of the ACTIVE white-label tenants of one partner
   * each with the tenant's id and the partner's own name for it. The tenant
   * relation is read from operators.parent_operator_id, never from input.
   */
  async listForPartnerTenants(
    partnerOperatorId: string,
  ): Promise<Array<{ row: GovernanceApprovalRow; tenant: { id: string; external_customer_id: string | null } }>> {
    const rows = await this.db
      .select({
        row: governanceApprovals,
        tenant_id: operators.id,
        external_customer_id: operators.external_customer_id,
      })
      .from(governanceApprovals)
      .innerJoin(operators, eq(operators.id, governanceApprovals.operator_id))
      .where(and(
        eq(operators.parent_operator_id, partnerOperatorId),
        eq(operators.status, 'active'),
      ))
      .orderBy(sql`${governanceApprovals.created_at} DESC`)
      .limit(100);
    return rows.map(({ row, tenant_id, external_customer_id }) => ({
      row,
      tenant: { id: tenant_id, external_customer_id },
    }));
  }

  /**
   * One approval of an ACTIVE tenant of this partner, with the tenant. The
   * relation comes from operators.parent_operator_id, never from input.
   */
  async findForPartnerTenant(
    id: string,
    partnerOperatorId: string,
  ): Promise<{ row: GovernanceApprovalRow; tenant: { id: string; external_customer_id: string | null } } | undefined> {
    const [found] = await this.db
      .select({
        row: governanceApprovals,
        tenant_id: operators.id,
        external_customer_id: operators.external_customer_id,
      })
      .from(governanceApprovals)
      .innerJoin(operators, eq(operators.id, governanceApprovals.operator_id))
      .where(and(
        eq(governanceApprovals.id, id),
        eq(operators.parent_operator_id, partnerOperatorId),
        eq(operators.status, 'active'),
      ))
      .limit(1);
    return found
      ? { row: found.row, tenant: { id: found.tenant_id, external_customer_id: found.external_customer_id } }
      : undefined;
  }

  /**
   * the active partner that decides an active tenant's approvals
   * with the partner's own name for the tenant. undefined for a normal
   * operator, a deleted or suspended tenant, or a partner that is not active.
   */
  async findActivePartnerOf(
    tenantOperatorId: string,
  ): Promise<{ partner_operator_id: string; external_customer_id: string | null } | undefined> {
    const partner = aliasedTable(operators, 'partner');
    const [row] = await this.db
      .select({ partner_operator_id: partner.id, external_customer_id: operators.external_customer_id })
      .from(operators)
      .innerJoin(partner, eq(partner.id, operators.parent_operator_id))
      .where(and(
        eq(operators.id, tenantOperatorId),
        eq(operators.status, 'active'),
        eq(partner.status, 'active'),
        eq(partner.is_partner, true),
      ))
      .limit(1);
    return row;
  }

  async listForOperator(
    operatorId: string,
    statuses?: string[],
  ): Promise<GovernanceApprovalRow[]> {
    return this.db
      .select()
      .from(governanceApprovals)
      .where(
        and(
          eq(governanceApprovals.operator_id, operatorId),
          ...(statuses?.length ? [inArray(governanceApprovals.status, statuses)] : []),
        ),
      )
      .orderBy(sql`${governanceApprovals.created_at} DESC`)
      .limit(100);
  }

  /** CAS pending → approved|rejected. undefined = already decided/expired/consumed. */
  async decide(
    id: string,
    decision: 'approved' | 'rejected',
    decidedByMemberId?: string | null,
  ): Promise<GovernanceApprovalRow | undefined> {
    const [row] = await this.db
      .update(governanceApprovals)
      .set({ status: decision, decided_at: new Date(), decided_by_member_id: decidedByMemberId ?? null })
      .where(and(eq(governanceApprovals.id, id), eq(governanceApprovals.status, 'pending')))
      .returning();
    return row;
  }

  /** CAS approved → consumed. Single-use: exactly one caller wins. */
  async consume(id: string): Promise<GovernanceApprovalRow | undefined> {
    const [row] = await this.db
      .update(governanceApprovals)
      .set({ status: 'consumed', consumed_at: new Date() })
      .where(and(eq(governanceApprovals.id, id), eq(governanceApprovals.status, 'approved')))
      .returning();
    return row;
  }

  /**
   * Authority management uses its mutation Idempotency-Key to make approval
   * consumption crash-safe. The first caller atomically consumes; an exact
   * concurrent/retry caller receives the already-consumed row for comparison.
   */
  async consumeAuthorityIdempotently(input: {
    id: string;
    operatorId: string;
    action: string;
    resourceId: string;
    payloadHash: string;
    idempotencyKeyHash: string;
    now: Date;
  }): Promise<{ row: GovernanceApprovalRow; consumedNow: boolean } | undefined> {
    return this.db.transaction(async (tx) => {
      const [consumed] = await tx
        .update(governanceApprovals)
        .set({
          status: 'consumed',
          consumed_at: input.now,
          consumed_idempotency_key_hash: input.idempotencyKeyHash,
        })
        .where(and(
          eq(governanceApprovals.id, input.id),
          eq(governanceApprovals.operator_id, input.operatorId),
          eq(governanceApprovals.action, input.action),
          eq(governanceApprovals.resource_id, input.resourceId),
          eq(governanceApprovals.payload_hash, input.payloadHash),
          eq(governanceApprovals.status, 'approved'),
          gt(governanceApprovals.expires_at, input.now),
        ))
        .returning();
      if (consumed) return { row: consumed, consumedNow: true };

      const row = await tx.query.governanceApprovals.findFirst({
        where: and(
          eq(governanceApprovals.id, input.id),
          eq(governanceApprovals.operator_id, input.operatorId),
        ),
      });
      return row ? { row, consumedNow: false } : undefined;
    });
  }

  /** CAS pending → expired (lazy, on read past TTL). */
  async expire(id: string): Promise<GovernanceApprovalRow | undefined> {
    const [row] = await this.db
      .update(governanceApprovals)
      .set({ status: 'expired' })
      .where(and(eq(governanceApprovals.id, id), eq(governanceApprovals.status, 'pending')))
      .returning();
    return row;
  }

  /** Bulk sweep for a future cron — flips every past-TTL pending row. */
  async sweepExpired(): Promise<number> {
    const rows = await this.db
      .update(governanceApprovals)
      .set({ status: 'expired' })
      .where(
        and(
          eq(governanceApprovals.status, 'pending'),
          lt(governanceApprovals.expires_at, new Date()),
        ),
      )
      .returning({ id: governanceApprovals.id });
    return rows.length;
  }
}
