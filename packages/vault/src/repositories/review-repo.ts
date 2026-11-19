import { eq } from 'drizzle-orm';
import { type Database, passportReviews } from '@stack/shared';

export class ReviewRepository {
  constructor(private db: Database) {}

  async create(data: typeof passportReviews.$inferInsert) {
    const [row] = await this.db.insert(passportReviews).values(data).returning();
    return row!;
  }

  async findByCheckout(checkoutId: string) {
    return this.db.query.passportReviews.findFirst({
      where: eq(passportReviews.checkout_id, checkoutId),
    });
  }

  async findByAgent(agentId: string) {
    return this.db.query.passportReviews.findMany({
      where: eq(passportReviews.agent_id, agentId),
      orderBy: (r, { desc }) => [desc(r.decided_at)],
    });
  }
}
