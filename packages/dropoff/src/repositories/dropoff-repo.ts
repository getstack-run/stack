import { and, asc, eq, gt, inArray, isNotNull, lt, or, sql } from 'drizzle-orm';
import { type Database, agents, dropoffRecipients, dropoffs, missions } from '@stack/shared';

export type DropoffDbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];
export type DropoffRow = typeof dropoffs.$inferSelect;
export type MissionRow = typeof missions.$inferSelect;

/** One agent a drop-off names, and when it collected it (null: not that one). */
export interface DropoffRecipient {
  agent_id: string;
  collected_at: Date | null;
}

/**
 * Whether an agent is one a drop-off names. A drop-off made before the recipients table exists has no rows there and
 * names its `to_agent_id` alone, so that column always counts.
 */
function namesAgent(agentId: string) {
  return or(
    eq(dropoffs.to_agent_id, agentId),
    sql`exists (select 1 from ${dropoffRecipients} where ${dropoffRecipients.dropoff_id} = ${dropoffs.id} and ${dropoffRecipients.agent_id} = ${agentId})`,
  )!;
}

const dropoffViewColumns = {
  id: dropoffs.id,
  operator_id: dropoffs.operator_id,
  from_agent_id: dropoffs.from_agent_id,
  to_agent_id: dropoffs.to_agent_id,
  schema: dropoffs.schema,
  status: dropoffs.status,
  on_expire: dropoffs.on_expire,
  created_at: dropoffs.created_at,
  deposited_at: dropoffs.deposited_at,
  collected_at: dropoffs.collected_at,
  expires_at: dropoffs.expires_at,
  mission_id: dropoffs.mission_id,
  deposited_bytes: dropoffs.deposited_bytes,
} as const;

/**
 * Drop the payload-derived digest maps from a provenance record and keep the
 * source list. The worker's bulk `markExpired` must also run against the
 * pre-0069 schema (pinned by dropoff-pre0069-expiry.test.ts), so it cannot
 * name this column; the digests it leaves on a worker-expired row are the same
 * one-way values the depositor's observation claims already hold.
 */
const STRIP_PROVENANCE_ITEMS = sql`${dropoffs.provenance} - 'entity_sources' - 'fingerprint_sources'`;

export class DropoffRepository {
  constructor(private db: Database) {}

  async transaction<T>(callback: (transaction: DropoffDbTransaction) => Promise<T>): Promise<T> {
    return this.db.transaction(callback);
  }

  async create(data: typeof dropoffs.$inferInsert, transaction?: DropoffDbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor.insert(dropoffs).values(data).returning();
    return row!;
  }

  /** How many of these agents belong to the customer. A caller that needs all of them compares with the list's length. */
  async countAgentsOfOperator(operatorId: string, agentIds: readonly string[], transaction?: DropoffDbTransaction): Promise<number> {
    if (agentIds.length === 0) return 0;
    const executor = transaction ?? this.db;
    const [row] = await executor
      .select({ n: sql<number>`count(*)::int` })
      .from(agents)
      .where(and(eq(agents.operator_id, operatorId), inArray(agents.id, [...agentIds])));
    return Number(row?.n ?? 0);
  }

  /** Name the agents a new drop-off is for, in the order named. */
  async addRecipients(
    dropoffId: string,
    operatorId: string,
    agentIds: readonly string[],
    transaction: DropoffDbTransaction,
  ): Promise<void> {
    await transaction.insert(dropoffRecipients).values(
      agentIds.map((agentId, position) => ({ dropoff_id: dropoffId, operator_id: operatorId, agent_id: agentId, position })),
    );
  }

  /**
   * Whom each drop-off names, in the order named, with who collected it. A drop-off with no rows of its own names its
   * `to_agent_id` alone.
   */
  async recipientsOf(
    rows: ReadonlyArray<Pick<DropoffRow, 'id' | 'to_agent_id' | 'status' | 'collected_at'>>,
    transaction?: DropoffDbTransaction,
  ): Promise<Map<string, DropoffRecipient[]>> {
    const result = new Map<string, DropoffRecipient[]>();
    if (rows.length === 0) return result;
    const executor = transaction ?? this.db;
    const named = await executor
      .select({ dropoff_id: dropoffRecipients.dropoff_id, agent_id: dropoffRecipients.agent_id, collected_at: dropoffRecipients.collected_at })
      .from(dropoffRecipients)
      .where(inArray(dropoffRecipients.dropoff_id, rows.map((r) => r.id)))
      .orderBy(asc(dropoffRecipients.dropoff_id), asc(dropoffRecipients.position));
    for (const entry of named) {
      const list = result.get(entry.dropoff_id) ?? [];
      list.push({ agent_id: entry.agent_id, collected_at: entry.collected_at });
      result.set(entry.dropoff_id, list);
    }
    for (const row of rows) {
      if (!result.has(row.id)) {
        result.set(row.id, [{ agent_id: row.to_agent_id, collected_at: row.status === 'collected' ? row.collected_at : null }]);
      }
    }
    return result;
  }

  /** Whether the drop-off names this agent. */
  async isRecipient(dropoffId: string, agentId: string, transaction?: DropoffDbTransaction): Promise<boolean> {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .select({ id: dropoffs.id })
      .from(dropoffs)
      .where(and(eq(dropoffs.id, dropoffId), namesAgent(agentId)))
      .limit(1);
    return Boolean(row);
  }

  /** Record which named agent took it. The index on the table lets one agent per drop-off ever be recorded. */
  async markRecipientCollected(dropoffId: string, agentId: string, transaction: DropoffDbTransaction): Promise<void> {
    await transaction
      .update(dropoffRecipients)
      .set({ collected_at: sql`now()` })
      .where(and(eq(dropoffRecipients.dropoff_id, dropoffId), eq(dropoffRecipients.agent_id, agentId)));
  }

  /** The agent that collected a drop-off, with its name, or null when none did. */
  async collectorOf(
    dropoff: Pick<DropoffRow, 'id' | 'to_agent_id' | 'status'>,
    transaction?: DropoffDbTransaction,
  ): Promise<{ agent_id: string; name: string | null } | null> {
    if (dropoff.status !== 'collected') return null;
    const executor = transaction ?? this.db;
    const [named] = await executor
      .select({ agent_id: dropoffRecipients.agent_id })
      .from(dropoffRecipients)
      .where(and(eq(dropoffRecipients.dropoff_id, dropoff.id), isNotNull(dropoffRecipients.collected_at)))
      .limit(1);
    // A drop-off collected before the table existed had one named agent.
    const agentId = named?.agent_id ?? dropoff.to_agent_id;
    const [agent] = await executor.select({ name: agents.name }).from(agents).where(eq(agents.id, agentId)).limit(1);
    return { agent_id: agentId, name: agent?.name ?? null };
  }

  async findById(id: string, transaction?: DropoffDbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor.select().from(dropoffs).where(eq(dropoffs.id, id)).limit(1);
    return row;
  }

  /** Lock one custody row before evaluating or changing its state. */
  async findByIdForUpdate(id: string, transaction: DropoffDbTransaction) {
    const [row] = await transaction
      .select()
      .from(dropoffs)
      .where(eq(dropoffs.id, id))
      .limit(1)
      .for('update');
    return row;
  }

  async findByOperator(operatorId: string, transaction?: DropoffDbTransaction) {
    const executor = transaction ?? this.db;
    return executor
      .select()
      .from(dropoffs)
      .where(eq(dropoffs.operator_id, operatorId))
      .orderBy(sql`${dropoffs.created_at} DESC`);
  }

  async findByParticipant(operatorId: string, agentId: string, transaction?: DropoffDbTransaction) {
    const executor = transaction ?? this.db;
    return executor
      .select()
      .from(dropoffs)
      .where(
        and(
          eq(dropoffs.operator_id, operatorId),
          or(eq(dropoffs.from_agent_id, agentId), namesAgent(agentId)),
        ),
      )
      .orderBy(sql`${dropoffs.created_at} DESC`);
  }

  async findPendingForAgent(agentId: string, transaction?: DropoffDbTransaction) {
    const executor = transaction ?? this.db;
    return executor
      .select()
      .from(dropoffs)
      .where(and(namesAgent(agentId), eq(dropoffs.status, 'deposited')))
      .orderBy(sql`${dropoffs.created_at} DESC`);
  }

  /**
   * Serialize every deposit attributed to a mission. The mission row is the
   * common lock for different drop-offs racing against the same byte cap.
   */
  async findMissionForUpdate(
    missionId: string,
    operatorId: string,
    transaction: DropoffDbTransaction,
  ): Promise<MissionRow | undefined> {
    const [row] = await transaction
      .select()
      .from(missions)
      .where(and(eq(missions.mission_id, missionId), eq(missions.operator_id, operatorId)))
      .limit(1)
      .for('update');
    return row;
  }

  async sumDepositedBytesForMission(
    missionId: string,
    transaction: DropoffDbTransaction,
  ): Promise<number> {
    const [result] = await transaction
      .select({ total: sql<number>`COALESCE(SUM(${dropoffs.deposited_bytes}), 0)::bigint` })
      .from(dropoffs)
      .where(eq(dropoffs.mission_id, missionId));
    return Number(result?.total ?? 0);
  }

  /** Record that the deployment's deposit hooks have run for a drop-off. The first record stands. */
  async markDepositAnnounced(id: string, transaction?: DropoffDbTransaction): Promise<void> {
    const executor = transaction ?? this.db;
    await executor
      .update(dropoffs)
      .set({ deposit_announced_at: sql`now()` })
      .where(and(eq(dropoffs.id, id), sql`${dropoffs.deposit_announced_at} IS NULL`));
  }

  /** CREATED -> DEPOSITED, guarded again even though the caller holds the row lock. */
  async deposit(
    id: string,
    operatorId: string,
    payloadHash: string,
    payloadEncrypted: string,
    depositedBytes: number,
    missionId: string | null,
    payloadEnvelopeVersion: 2,
    transaction: DropoffDbTransaction,
    provenance: Record<string, unknown> | null = null,
  ) {
    const [row] = await transaction
      .update(dropoffs)
      .set({
        status: 'deposited',
        payload_hash: payloadHash,
        payload_encrypted: payloadEncrypted,
        deposited_bytes: depositedBytes,
        deposited_at: sql`now()`,
        mission_id: missionId,
        payload_envelope_version: payloadEnvelopeVersion,
        provenance,
      })
      .where(
        and(
          eq(dropoffs.id, id),
          eq(dropoffs.operator_id, operatorId),
          eq(dropoffs.status, 'created'),
          gt(dropoffs.expires_at, sql`now()`),
        ),
      )
      .returning();
    return row;
  }

  /** DEPOSITED -> COLLECTED and purge, in the caller's audit transaction. */
  async collect(id: string, operatorId: string, transaction: DropoffDbTransaction) {
    const [row] = await transaction
      .update(dropoffs)
      // The item-level provenance maps are digests derived from the payload,
      // so they go with it. The source list stays as evidence.
      .set({ status: 'collected', payload_encrypted: null, collected_at: sql`now()`, provenance: STRIP_PROVENANCE_ITEMS })
      .where(
        and(
          eq(dropoffs.id, id),
          eq(dropoffs.operator_id, operatorId),
          eq(dropoffs.status, 'deposited'),
          gt(dropoffs.expires_at, sql`now()`),
        ),
      )
      .returning();
    return row;
  }

  /**
   * CREATED|DEPOSITED -> EXPIRED and purge. Terminal rows cannot be rewritten. `endAnnounced`: the end needs no
   * announcement (the depositor ended it itself), so the deployment's sweep leaves it alone.
   */
  async expireActive(id: string, operatorId: string, transaction: DropoffDbTransaction, endAnnounced = false) {
    const [row] = await transaction
      .update(dropoffs)
      .set({ status: 'expired', payload_encrypted: null, provenance: STRIP_PROVENANCE_ITEMS, ...(endAnnounced ? { end_announced_at: sql`now()` } : {}) })
      .where(
        and(
          eq(dropoffs.id, id),
          eq(dropoffs.operator_id, operatorId),
          inArray(dropoffs.status, ['created', 'deposited']),
        ),
      )
      .returning();
    return row;
  }

  /** Claim overdue active rows without blocking another worker instance. */
  async findExpiredForUpdate(limit: number, transaction: DropoffDbTransaction) {
    return transaction
      // This cleanup must run against the schema immediately before 0069.
      // Selecting the newer envelope-version field makes its guard impossible
      // to satisfy through the normal application service.
      .select({ id: dropoffs.id })
      .from(dropoffs)
      .where(
        and(
          lt(dropoffs.expires_at, sql`now()`),
          inArray(dropoffs.status, ['created', 'deposited']),
        ),
      )
      .orderBy(dropoffs.expires_at, dropoffs.id)
      .limit(limit)
      .for('update', { skipLocked: true });
  }

  async markExpired(ids: string[], transaction: DropoffDbTransaction) {
    if (ids.length === 0) return [];
    return transaction
      .update(dropoffs)
      .set({ status: 'expired', payload_encrypted: null })
      .where(and(inArray(dropoffs.id, ids), inArray(dropoffs.status, ['created', 'deposited'])))
      .returning(dropoffViewColumns);
  }
}
