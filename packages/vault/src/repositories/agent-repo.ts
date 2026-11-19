import { eq, and, gte, lt, ne, notExists, sql } from 'drizzle-orm';
import { ConflictError, type Database, agents, fleetPolicies } from '@stack/shared';

/** Whether an insert failed on the live-name index (PostgreSQL 23505), whichever way the driver wraps the error. */
function isLiveNameConflict(error: unknown): boolean {
  const seen = new Set<unknown>();
  for (let current: unknown = error; current && typeof current === 'object' && !seen.has(current); ) {
    seen.add(current);
    const { code, constraint_name: constraintName, constraint, cause } = current as {
      code?: unknown; constraint_name?: unknown; constraint?: unknown; cause?: unknown;
    };
    if (code === '23505' && (constraintName ?? constraint) === 'agents_operator_name_idx') return true;
    current = cause;
  }
  return false;
}

export class AgentRepository {
  constructor(private db: Database) {}

  async create(data: typeof agents.$inferInsert) {
    try {
      const [row] = await this.db.insert(agents).values(data).returning();
      return row!;
    } catch (error) {
      // Two requests for the same name at once: the check before the insert passed for both, and the live-name index
      // refuses the second. That is the same answer as a name that was taken a moment earlier, never a server error.
      if (isLiveNameConflict(error)) throw new ConflictError(`Agent "${data.name}" already exists`);
      throw error;
    }
  }

  async findById(id: string, transaction?: Parameters<Parameters<Database['transaction']>[0]>[0]) {
    return (transaction ?? this.db).query.agents.findFirst({
      where: eq(agents.id, id),
    });
  }

  async findByOperatorId(operatorId: string) {
    return this.db.query.agents.findMany({
      where: eq(agents.operator_id, operatorId),
    });
  }

  /** The live agent of this name: a retired (revoked) agent does not hold its name (the index is over the live ones). */
  async findByOperatorAndName(operatorId: string, name: string) {
    return this.db.query.agents.findFirst({
      where: and(eq(agents.operator_id, operatorId), eq(agents.name, name), ne(agents.status, 'revoked')),
    });
  }

  async updateStatus(id: string, status: string) {
    const [row] = await this.db
      .update(agents)
      .set({ status, updated_at: new Date() })
      .where(eq(agents.id, id))
      .returning();
    return row;
  }

  async update(id: string, data: Partial<typeof agents.$inferInsert>) {
    const [row] = await this.db
      .update(agents)
      .set({ ...data, updated_at: new Date() })
      .where(eq(agents.id, id))
      .returning();
    return row;
  }

  async delete(id: string) {
    const [row] = await this.db.delete(agents).where(eq(agents.id, id)).returning();
    return row;
  }

  async countByOperator(operatorId: string): Promise<number> {
    const rows = await this.db.query.agents.findMany({
      where: and(eq(agents.operator_id, operatorId), eq(agents.status, 'active'),
        notExists(this.db.select({ id: fleetPolicies.root_agent_id })
          .from(fleetPolicies)
          .where(eq(fleetPolicies.root_agent_id, agents.id)))),
      columns: { id: true },
    });
    return rows.length;
  }

  /**
   * Count agents CREATED in the window [since, until) for one operator.
   * Not the same as active inventory — this is a flow count ("new agents this
   * period"), status-agnostic (a created-then-revoked agent still counts as
   * created in the window). `until` exclusive; omit for "up to now".
   */
  async countCreatedBetween(operatorId: string, since: Date, until?: Date): Promise<number> {
    const [row] = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(agents)
      .where(and(
        eq(agents.operator_id, operatorId),
        notExists(this.db.select({ id: fleetPolicies.root_agent_id })
          .from(fleetPolicies)
          .where(eq(fleetPolicies.root_agent_id, agents.id))),
        gte(agents.created_at, since),
        until ? lt(agents.created_at, until) : undefined,
      ));
    return row?.count ?? 0;
  }
}
