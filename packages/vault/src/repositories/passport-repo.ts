import { eq, and, isNull, gt, desc, lt, sql } from 'drizzle-orm';
import {
  type Database,
  acquireOAuthOperatorLock,
  agents,
  NotFoundError,
  passports,
} from '@stack/shared';

type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export interface RevokedPassportRow {
  jti: string;
  agent_id: string;
  parent_passport_id: string | null;
  expires_at: Date;
}

/**
 * Set the agent block and revoke every unrevoked Passport rooted at that agent,
 * including delegated descendants owned by other agents. The operator lock is
 * the same lock used by issue/refresh/delegate, so no new Passport can be
 * inserted between the block update and the recursive revoke.
 */
export async function blockAgentAndRevokePassportChain(
  transaction: DbTransaction,
  input: {
    agentId: string;
    operatorId: string;
    reason: string;
    blockedAt: Date;
  },
): Promise<RevokedPassportRow[]> {
  await acquireOAuthOperatorLock(transaction, input.operatorId);

  const [agent] = await transaction
    .update(agents)
    .set({
      passport_blocked: true,
      passport_blocked_reason: input.reason,
      passport_blocked_at: input.blockedAt,
      updated_at: input.blockedAt,
    })
    .where(and(eq(agents.id, input.agentId), eq(agents.operator_id, input.operatorId)))
    .returning({ id: agents.id });
  if (!agent) throw new NotFoundError('Agent', input.agentId);

  const blockedAtIso = input.blockedAt.toISOString();
  const result = await transaction.execute(sql`
    WITH RECURSIVE active_chain AS (
      SELECT p.jti
      FROM passports p
      WHERE p.agent_id = ${input.agentId}
        AND p.operator_id = ${input.operatorId}
        AND p.revoked_at IS NULL

      UNION

      SELECT child.jti
      FROM passports child
      INNER JOIN active_chain parent ON child.parent_passport_id = parent.jti
      WHERE child.operator_id = ${input.operatorId}
        AND child.revoked_at IS NULL
    )
    UPDATE passports
    SET revoked_at = ${blockedAtIso}::timestamptz, revoked_reason = ${input.reason}
    WHERE jti IN (SELECT jti FROM active_chain)
      AND revoked_at IS NULL
    RETURNING jti, agent_id, parent_passport_id, expires_at
  `);

  const rows = Array.isArray(result)
    ? result as unknown as RevokedPassportRow[]
    : ((result as { rows?: RevokedPassportRow[] }).rows ?? []);
  return rows.map((row) => ({
    ...row,
    expires_at: new Date(row.expires_at),
  }));
}

/**
 * revoke every unrevoked Passport bound to a Mission, plus every
 * delegated descendant, inside the caller's transaction. Expired rows are
 * included because a root Passport stays refreshable for a grace window.
 * The caller must already hold the operator lock, the same lock
 * issue/refresh/delegate take, so no Passport for the Mission can be
 * minted between the Mission's state change and this revoke.
 */
export async function revokeMissionPassportChain(
  transaction: DbTransaction,
  input: { operatorId: string; missionId: string; reason: string; revokedAt: Date },
): Promise<RevokedPassportRow[]> {
  const revokedAtIso = input.revokedAt.toISOString();
  const result = await transaction.execute(sql`
    WITH RECURSIVE active_chain AS (
      SELECT p.jti
      FROM passports p
      WHERE p.operator_id = ${input.operatorId}
        AND p.mission_ids @> ARRAY[${input.missionId}]::text[]
        AND p.revoked_at IS NULL

      UNION

      SELECT child.jti
      FROM passports child
      INNER JOIN active_chain parent ON child.parent_passport_id = parent.jti
      WHERE child.operator_id = ${input.operatorId}
        AND child.revoked_at IS NULL
    )
    UPDATE passports
    SET revoked_at = ${revokedAtIso}::timestamptz, revoked_reason = ${input.reason}
    WHERE jti IN (SELECT jti FROM active_chain)
      AND revoked_at IS NULL
    RETURNING jti, agent_id, parent_passport_id, expires_at
  `);
  const rows = Array.isArray(result)
    ? result as unknown as RevokedPassportRow[]
    : ((result as { rows?: RevokedPassportRow[] }).rows ?? []);
  return rows.map((row) => ({ ...row, expires_at: new Date(row.expires_at) }));
}

export class PassportRepository {
  constructor(private db: Database) {}

  async create(data: typeof passports.$inferInsert, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor.insert(passports).values(data).returning();
    return row!;
  }

  /** Who a Passport was issued to and the one it was delegated from, inside one operator: what the policy check follows up a chain. */
  async findLineageRow(operatorId: string, jti: string): Promise<{ agent_id: string; parent_passport_id: string | null } | null> {
    const row = await this.db.query.passports.findFirst({
      where: and(eq(passports.jti, jti), eq(passports.operator_id, operatorId)),
      columns: { agent_id: true, parent_passport_id: true },
    });
    return row ?? null;
  }

  async findByJti(jti: string, transaction?: DbTransaction) {
    return (transaction ?? this.db).query.passports.findFirst({
      where: eq(passports.jti, jti),
    });
  }

  async revoke(jti: string, reason: string, transaction?: DbTransaction) {
    const [row] = await (transaction ?? this.db)
      .update(passports)
      .set({ revoked_at: new Date(), revoked_reason: reason })
      .where(eq(passports.jti, jti))
      .returning();
    return row;
  }

  async revokeAllForAgent(agentId: string, reason: string, transaction?: DbTransaction) {
    return (transaction ?? this.db)
      .update(passports)
      .set({ revoked_at: new Date(), revoked_reason: reason })
      .where(
        and(
          eq(passports.agent_id, agentId),
          isNull(passports.revoked_at),
        ),
      )
      .returning({ jti: passports.jti, expires_at: passports.expires_at });
  }

  async blockAgentAndRevokeChain(input: {
    agentId: string;
    operatorId: string;
    reason: string;
    blockedAt?: Date;
  }): Promise<RevokedPassportRow[]> {
    return this.db.transaction((transaction) => blockAgentAndRevokePassportChain(
      transaction,
      { ...input, blockedAt: input.blockedAt ?? new Date() },
    ));
  }

  async revokeAllForOperator(operatorId: string, reason: string, transaction?: DbTransaction) {
    return (transaction ?? this.db)
      .update(passports)
      .set({ revoked_at: new Date(), revoked_reason: reason })
      .where(
        and(
          eq(passports.operator_id, operatorId),
          isNull(passports.revoked_at),
        ),
      )
      .returning({ jti: passports.jti, expires_at: passports.expires_at });
  }

  async revokeBySession(sessionId: string, operatorId: string, reason: string, transaction?: DbTransaction) {
    return (transaction ?? this.db)
      .update(passports)
      .set({ revoked_at: new Date(), revoked_reason: reason })
      .where(
        and(
          eq(passports.session_id, sessionId),
          eq(passports.operator_id, operatorId),
          isNull(passports.revoked_at),
        ),
      )
      .returning({ jti: passports.jti, expires_at: passports.expires_at });
  }

  async extendExpiry(jti: string, newExpiresAt: Date) {
    const [row] = await this.db
      .update(passports)
      .set({ expires_at: newExpiresAt })
      .where(eq(passports.jti, jti))
      .returning();
    return row;
  }

  async updateCheckpoint(jti: string, checkpointAt: Date, checkpointCount: number) {
    const [row] = await this.db
      .update(passports)
      .set({ last_checkpoint_at: checkpointAt, checkpoint_count: checkpointCount })
      .where(eq(passports.jti, jti))
      .returning();
    return row;
  }

  async updateCheckout(jti: string, checkedOutAt: Date, status: string, flags?: { type: string; severity: string; message: string }[]) {
    const [row] = await this.db
      .update(passports)
      .set({ checked_out_at: checkedOutAt, checkout_status: status, checkout_flags: flags ?? null })
      .where(eq(passports.jti, jti))
      .returning();
    return row;
  }

  async isRevoked(jti: string): Promise<boolean> {
    const row = await this.db.query.passports.findFirst({
      where: eq(passports.jti, jti),
      columns: { revoked_at: true },
    });
    return row?.revoked_at != null;
  }

  async findActiveByAgent(agentId: string) {
    return this.db.query.passports.findMany({
      where: and(
        eq(passports.agent_id, agentId),
        isNull(passports.revoked_at),
        gt(passports.expires_at, new Date()),
      ),
    });
  }

  /** Unrevoked children, including expired tokens still eligible for refresh. */
  async findActiveChildren(parentJti: string, transaction?: DbTransaction) {
    return (transaction ?? this.db).query.passports.findMany({
      where: and(
        eq(passports.parent_passport_id, parentJti),
        isNull(passports.revoked_at),
      ),
      columns: {
        jti: true,
        operator_id: true,
        expires_at: true,
        parent_passport_id: true,
      },
    });
  }

  async findActiveByOperator(
    operatorId: string,
    filters?: { agent_id?: string; session_id?: string },
  ) {
    const conditions = [
      eq(passports.operator_id, operatorId),
      isNull(passports.revoked_at),
      gt(passports.expires_at, new Date()),
    ];
    if (filters?.agent_id) conditions.push(eq(passports.agent_id, filters.agent_id));
    if (filters?.session_id) conditions.push(eq(passports.session_id, filters.session_id));

    return this.db.query.passports.findMany({
      where: and(...conditions),
      orderBy: (p, { desc }) => [desc(p.issued_at)],
    });
  }

  async findRecentByAgent(agentId: string, limit: number) {
    return this.db.query.passports.findMany({
      where: eq(passports.agent_id, agentId),
      orderBy: [desc(passports.issued_at)],
      limit,
    });
  }

  /** Find enforced/logged passports that are overdue for checkpoints */
  async findCheckpointOverdue() {
    const now = new Date();
    // Active passports with checkpoint_interval set (enforced mode)
    return this.db.query.passports.findMany({
      where: and(
        isNull(passports.revoked_at),
        isNull(passports.checked_out_at),
        gt(passports.expires_at, now),
        // has a checkpoint interval set (enforced agents)
        gt(passports.checkpoint_interval_seconds, 0),
      ),
    });
  }

  /** Find passports that expired recently without checkout */
  async findExpiredWithoutCheckout(sinceHoursAgo: number = 24) {
    const now = new Date();
    const since = new Date(now.getTime() - sinceHoursAgo * 60 * 60 * 1000);
    return this.db.query.passports.findMany({
      where: and(
        isNull(passports.revoked_at),
        isNull(passports.checked_out_at),
        lt(passports.expires_at, now),
        gt(passports.expires_at, since),
        // has intent (enforced/logged) — standard passports don't need checkout
        gt(passports.checkpoint_interval_seconds, 0),
      ),
    });
  }

  /** Revoke only passports that carry a specific identity claim */
  async revokeByCarriedClaim(operatorId: string, claimId: string, reason: string) {
    return this.db.transaction(async (transaction) => {
      await acquireOAuthOperatorLock(transaction, operatorId);
      return transaction.execute(sql`
      UPDATE passports
      SET revoked_at = NOW(), revoked_reason = ${reason}
      WHERE operator_id = ${operatorId}
        AND revoked_at IS NULL
        AND identity_claim_ids::jsonb @> ${JSON.stringify([claimId])}::jsonb
      RETURNING jti, expires_at
      `);
    });
  }

  async findActiveBySession(sessionId: string, operatorId: string) {
    return this.db.query.passports.findMany({
      where: and(
        eq(passports.session_id, sessionId),
        eq(passports.operator_id, operatorId),
        isNull(passports.revoked_at),
        gt(passports.expires_at, new Date()),
      ),
    });
  }
}
