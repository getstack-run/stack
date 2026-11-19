import { eq, and } from 'drizzle-orm';
import { type Database, operatorOauthApps } from '@stack/shared';

export class OauthAppRepository {
  constructor(private db: Database) {}

  async create(data: typeof operatorOauthApps.$inferInsert) {
    const [row] = await this.db.insert(operatorOauthApps).values(data).returning();
    return row!;
  }

  async findByOperatorAndProvider(operatorId: string, provider: string) {
    return this.db.query.operatorOauthApps.findFirst({
      where: and(
        eq(operatorOauthApps.operator_id, operatorId),
        eq(operatorOauthApps.provider, provider),
      ),
    });
  }

  async findByOperator(operatorId: string) {
    return this.db.query.operatorOauthApps.findMany({
      where: eq(operatorOauthApps.operator_id, operatorId),
    });
  }

  async deleteByOperatorAndProvider(operatorId: string, provider: string) {
    const [row] = await this.db
      .delete(operatorOauthApps)
      .where(
        and(
          eq(operatorOauthApps.operator_id, operatorId),
          eq(operatorOauthApps.provider, provider),
        ),
      )
      .returning();
    return row;
  }
}
