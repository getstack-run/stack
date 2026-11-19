import { eq, and } from 'drizzle-orm';
import { type Database, notificationDestinations } from '@stack/shared';

export class NotificationDestinationRepository {
  constructor(private db: Database) {}

  async create(data: typeof notificationDestinations.$inferInsert) {
    const [row] = await this.db.insert(notificationDestinations).values(data).returning();
    return row!;
  }

  async findById(id: string) {
    return this.db.query.notificationDestinations.findFirst({
      where: eq(notificationDestinations.id, id),
    });
  }

  async findByOperator(operatorId: string) {
    return this.db.query.notificationDestinations.findMany({
      where: eq(notificationDestinations.operator_id, operatorId),
      orderBy: (d, { desc }) => [desc(d.created_at)],
    });
  }

  async findByOperatorAndTypeAndDest(operatorId: string, channelType: string, destination: string) {
    return this.db.query.notificationDestinations.findFirst({
      where: and(
        eq(notificationDestinations.operator_id, operatorId),
        eq(notificationDestinations.channel_type, channelType),
        eq(notificationDestinations.destination, destination),
      ),
    });
  }

  async delete(id: string) {
    const [row] = await this.db.delete(notificationDestinations).where(eq(notificationDestinations.id, id)).returning();
    return row;
  }

  async update(id: string, data: Partial<typeof notificationDestinations.$inferInsert>) {
    const [row] = await this.db
      .update(notificationDestinations)
      .set(data)
      .where(eq(notificationDestinations.id, id))
      .returning();
    return row;
  }
}
