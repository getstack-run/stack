import { eq } from 'drizzle-orm';
import { type Database, notificationChannels, notificationDestinations } from '@stack/shared';

export class NotificationChannelRepository {
  constructor(private db: Database) {}

  async create(data: typeof notificationChannels.$inferInsert) {
    const [row] = await this.db.insert(notificationChannels).values(data).returning();
    return row!;
  }

  async findById(id: string) {
    return this.db.query.notificationChannels.findFirst({
      where: eq(notificationChannels.id, id),
    });
  }

  async findByOperator(operatorId: string) {
    return this.db.query.notificationChannels.findMany({
      where: eq(notificationChannels.operator_id, operatorId),
      orderBy: (c, { desc }) => [desc(c.created_at)],
    });
  }

  /** Returns channels with their joined destination info for dispatch. */
  async findByOperatorWithDestinations(operatorId: string) {
    const rows = await this.db
      .select({
        channel: notificationChannels,
        dest: notificationDestinations,
      })
      .from(notificationChannels)
      .leftJoin(notificationDestinations, eq(notificationChannels.destination_id, notificationDestinations.id))
      .where(eq(notificationChannels.operator_id, operatorId));
    return rows;
  }

  async delete(id: string) {
    const [row] = await this.db.delete(notificationChannels).where(eq(notificationChannels.id, id)).returning();
    return row;
  }

  async update(id: string, data: Partial<typeof notificationChannels.$inferInsert>) {
    const [row] = await this.db
      .update(notificationChannels)
      .set(data)
      .where(eq(notificationChannels.id, id))
      .returning();
    return row;
  }
}
