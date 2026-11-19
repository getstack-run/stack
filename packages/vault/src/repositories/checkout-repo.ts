import { eq, and, desc } from 'drizzle-orm';
import { type Database, passportCheckouts, passports } from '@stack/shared';

export class CheckoutRepository {
  constructor(private db: Database) {}

  async create(data: typeof passportCheckouts.$inferInsert) {
    const [row] = await this.db.insert(passportCheckouts).values(data).returning();
    return row!;
  }

  async findById(id: string) {
    return this.db.query.passportCheckouts.findFirst({
      where: eq(passportCheckouts.id, id),
    });
  }

  async findByPassport(passportJti: string) {
    return this.db.query.passportCheckouts.findFirst({
      where: eq(passportCheckouts.passport_jti, passportJti),
    });
  }

  async findByOperator(operatorId: string, filters?: { review_status?: string; limit?: number; offset?: number }) {
    const conditions = [eq(passportCheckouts.operator_id, operatorId)];
    if (filters?.review_status) {
      conditions.push(eq(passportCheckouts.review_status, filters.review_status));
    }

    return this.db.query.passportCheckouts.findMany({
      where: and(...conditions),
      orderBy: (c, { desc }) => [desc(c.submitted_at)],
      limit: filters?.limit ?? 20,
      offset: filters?.offset ?? 0,
    });
  }

  async countByOperator(operatorId: string, reviewStatus?: string): Promise<number> {
    const conditions = [eq(passportCheckouts.operator_id, operatorId)];
    if (reviewStatus) {
      conditions.push(eq(passportCheckouts.review_status, reviewStatus));
    }
    const rows = await this.db.query.passportCheckouts.findMany({
      where: and(...conditions),
      columns: { id: true },
    });
    return rows.length;
  }

  /**
   * Find the N most recent completed checkouts for a specific agent.
   * Joins through `passports.agent_id`. Used by the Behavioral Anomaly
   * detector to compute rolling per-agent baselines.
   */
  async findRecentByAgent(agentId: string, limit: number) {
    const rows = await this.db
      .select({
        id: passportCheckouts.id,
        passport_jti: passportCheckouts.passport_jti,
        submitted_at: passportCheckouts.submitted_at,
        services_used: passportCheckouts.services_used,
        actions_count: passportCheckouts.actions_count,
        issued_at: passports.issued_at,
      })
      .from(passportCheckouts)
      .innerJoin(passports, eq(passportCheckouts.passport_jti, passports.jti))
      .where(eq(passports.agent_id, agentId))
      .orderBy(desc(passportCheckouts.submitted_at))
      .limit(limit);
    return rows;
  }

  async updateReviewStatus(id: string, status: string, flags?: { type: string; severity: string; message: string }[]) {
    const [row] = await this.db
      .update(passportCheckouts)
      .set({
        review_status: status,
        review_flags: flags ?? null,
        reviewed_at: new Date(),
      })
      .where(eq(passportCheckouts.id, id))
      .returning();
    return row;
  }
}
