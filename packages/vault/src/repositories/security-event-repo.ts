import { eq, and, or, not, like, inArray, desc, sql, isNull, gte } from 'drizzle-orm';
import {
  type Database,
  securityEvents,
  SYNTHETIC_AGENT_PREFIXES,
  SYNTHETIC_AGENT_IDS,
} from '@stack/shared';

// Build a Drizzle WHERE condition that EXCLUDES synthetic-agent rows.
// Three flavours of "synthetic" all merge here:
//   1. The literal id list (e.g. 'oauth' — agent_id with no agents row,
//      used by the OAuth refresh smoke)
//   2. The id-prefix list (e.g. 'agt_sandbox_' — public landing-page
//      runner's auto-generated agents)
//   3. The durable agents.is_synthetic flag (added 2026-05-25 — for smoke
//      agents that use normal agt_* ids, e.g. a smoke-test agent)
// Keep the row when agent_id is NULL OR none of the three conditions
// match.
function notSyntheticCondition() {
  const prefixMatchers = SYNTHETIC_AGENT_PREFIXES.map((p) =>
    like(securityEvents.agent_id, `${p}%`),
  );
  const idMatcher =
    SYNTHETIC_AGENT_IDS.length > 0
      ? inArray(securityEvents.agent_id, [...SYNTHETIC_AGENT_IDS])
      : null;
  // SQL subquery on the agents table: any agent flagged synthetic excludes
  // its security_events. Using raw sql so we don't need to import the
  // agents table here (would risk a circular dep with the shared package's
  // re-export ordering).
  const flaggedMatcher = sql`${securityEvents.agent_id} IN (SELECT id FROM agents WHERE is_synthetic = true)`;
  const syntheticMatchers = [
    ...prefixMatchers,
    ...(idMatcher ? [idMatcher] : []),
    flaggedMatcher,
  ];
  if (syntheticMatchers.length === 0) return undefined;
  const isSynthetic = syntheticMatchers.length === 1 ? syntheticMatchers[0]! : or(...syntheticMatchers)!;
  return or(isNull(securityEvents.agent_id), not(isSynthetic));
}

export class SecurityEventRepository {
  constructor(private db: Database) {}

  async create(data: typeof securityEvents.$inferInsert) {
    const [row] = await this.db.insert(securityEvents).values(data).returning();
    return row!;
  }

  /**
   * (Option F) — link a freshly-emitted detector_signal
   * claim to its security_events row via the additive claim_id FK.
   * Called from SecurityEventService.record() right after the dual-
   * write registerClaim returns a claim_id. Best-effort: failure logs
   * and the row keeps claim_id NULL.
   */
  async linkClaim(eventId: string, claimId: string): Promise<void> {
    await this.db
      .update(securityEvents)
      .set({ claim_id: claimId })
      .where(eq(securityEvents.id, eventId));
  }

  async findById(id: string) {
    return this.db.query.securityEvents.findFirst({
      where: eq(securityEvents.id, id),
    });
  }

  async findByPassport(jti: string) {
    return this.db.query.securityEvents.findMany({
      where: eq(securityEvents.passport_jti, jti),
      orderBy: [desc(securityEvents.created_at)],
    });
  }

  async findByAgent(agentId: string, since?: Date) {
    const conditions = [eq(securityEvents.agent_id, agentId)];
    if (since) {
      conditions.push(gte(securityEvents.created_at, since));
    }
    return this.db.query.securityEvents.findMany({
      where: and(...conditions),
      orderBy: [desc(securityEvents.created_at)],
    });
  }

  async findByOperator(
    operatorId: string,
    opts?: {
      resolved?: boolean;
      agentId?: string;
      limit?: number;
      offset?: number;
      excludeSynthetic?: boolean;
    },
  ) {
    const conditions = [eq(securityEvents.operator_id, operatorId)];
    if (opts?.resolved !== undefined) {
      conditions.push(eq(securityEvents.resolved, opts.resolved));
    }
    if (opts?.agentId) {
      conditions.push(eq(securityEvents.agent_id, opts.agentId));
    }
    // When the caller explicitly filters by agent_id we honor that even if
    // the agent is synthetic — the caller asked for it. excludeSynthetic
    // only trims the broad listing.
    if (opts?.excludeSynthetic && !opts?.agentId) {
      const cond = notSyntheticCondition();
      if (cond) conditions.push(cond);
    }
    return this.db.query.securityEvents.findMany({
      where: and(...conditions),
      orderBy: [desc(securityEvents.created_at)],
      limit: opts?.limit ?? 50,
      offset: opts?.offset ?? 0,
    });
  }

  async countUnresolved(
    operatorId: string,
    opts?: { excludeSynthetic?: boolean },
  ): Promise<number> {
    const conditions = [
      eq(securityEvents.operator_id, operatorId),
      eq(securityEvents.resolved, false),
    ];
    if (opts?.excludeSynthetic) {
      const cond = notSyntheticCondition();
      if (cond) conditions.push(cond);
    }
    const rows = await this.db.query.securityEvents.findMany({
      where: and(...conditions),
      columns: { id: true },
    });
    return rows.length;
  }

  async resolve(id: string, resolvedBy: string) {
    const [row] = await this.db
      .update(securityEvents)
      .set({ resolved: true, resolved_by: resolvedBy, resolved_at: new Date() })
      .where(eq(securityEvents.id, id))
      .returning();
    return row;
  }

  /**
   * One more occurrence of a signal already recorded: the count and the time of the last one go on the event's
   * metadata (`repeat_count`, the first occurrence counting as 1, and `last_repeat_at`). One statement, so
   * parallel repeats never lose a count. A resolved event is left as it is.
   */
  async addRepeat(id: string, operatorId: string): Promise<void> {
    await this.db.execute(sql`
      UPDATE security_events
         SET metadata = jsonb_set(
               jsonb_set(
                 COALESCE(metadata, '{}'::jsonb),
                 '{repeat_count}',
                 to_jsonb(COALESCE((metadata->>'repeat_count')::int, 1) + 1)
               ),
               '{last_repeat_at}',
               to_jsonb(to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
             )
       WHERE id = ${id} AND operator_id = ${operatorId} AND resolved = false
    `);
  }

  /** Resolve every open event of one agent with one of the given severities. Returns what was resolved. */
  async resolveOpenForAgent(
    operatorId: string,
    agentId: string,
    resolvedBy: string,
    severities: readonly string[],
  ): Promise<Array<{ id: string; signal_type: string; severity: string; mission_id: string | null }>> {
    return this.db
      .update(securityEvents)
      .set({ resolved: true, resolved_by: resolvedBy, resolved_at: new Date() })
      .where(
        and(
          eq(securityEvents.operator_id, operatorId),
          eq(securityEvents.agent_id, agentId),
          eq(securityEvents.resolved, false),
          inArray(securityEvents.severity, [...severities]),
        ),
      )
      .returning({
        id: securityEvents.id,
        signal_type: securityEvents.signal_type,
        severity: securityEvents.severity,
        mission_id: securityEvents.mission_id,
      });
  }

  async existsForPassport(jti: string, signalType: string): Promise<boolean> {
    const row = await this.db.query.securityEvents.findFirst({
      where: and(
        eq(securityEvents.passport_jti, jti),
        eq(securityEvents.signal_type, signalType),
      ),
      columns: { id: true },
    });
    return row != null;
  }

  /** Used by system-level signals (e.g. audit-chain integrity) where there
   *  is no passport_jti to dedup on - dedup by operator + signal type
   *  among unresolved events instead. */
  async existsUnresolvedForOperator(operatorId: string, signalType: string): Promise<boolean> {
    const row = await this.db.query.securityEvents.findFirst({
      where: and(
        eq(securityEvents.operator_id, operatorId),
        eq(securityEvents.signal_type, signalType),
        isNull(securityEvents.resolved_at),
      ),
      columns: { id: true },
    });
    return row != null;
  }

  /**
   * Delete security_events rows older than the retention window, the same
   * `retentionDays` for every account. Returns the number of rows deleted.
   */
  async pruneExpired(retentionDays: number): Promise<number> {
    if (!(retentionDays > 0) || !Number.isFinite(retentionDays)) {
      throw new Error('Retention prune needs a positive, finite number of days');
    }
    // postgres-js doesn't accept JS Date in tagged templates - pass an ISO
    // string + cast to timestamptz in SQL.
    const cutoffIso = new Date(Date.now() - retentionDays * 86400 * 1000).toISOString();
    const result = await this.db.execute(sql`
      DELETE FROM security_events
      WHERE created_at < ${cutoffIso}::timestamptz
      AND operator_id IN (SELECT id FROM operators)
    `);
    return (result as unknown as { rowCount?: number }).rowCount ?? 0;
  }
}
