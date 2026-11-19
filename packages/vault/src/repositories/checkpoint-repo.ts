import { eq, and, isNull } from 'drizzle-orm';
import { type Database, passportCheckpoints } from '@stack/shared';

export class CheckpointRepository {
  constructor(private db: Database) {}

  async create(data: typeof passportCheckpoints.$inferInsert) {
    const [row] = await this.db.insert(passportCheckpoints).values(data).returning();
    return row!;
  }

  /**
   * best-effort link from a checkpoint row to
   * its paired checkpoint_approval claim. Only updates if claim_id is
   * currently null (idempotent against retries; never clobbers an
   * existing link). Mirror of SecurityEventRepository.linkClaim
   */
  async linkClaim(checkpointId: string, claimId: string): Promise<void> {
    await this.db
      .update(passportCheckpoints)
      .set({ claim_id: claimId })
      .where(
        and(
          eq(passportCheckpoints.id, checkpointId),
          isNull(passportCheckpoints.claim_id),
        ),
      );
  }

  async findByPassport(passportJti: string) {
    return this.db.query.passportCheckpoints.findMany({
      where: eq(passportCheckpoints.passport_jti, passportJti),
      orderBy: (c, { asc }) => [asc(c.submitted_at)],
    });
  }

  async countByPassport(passportJti: string): Promise<number> {
    const rows = await this.db.query.passportCheckpoints.findMany({
      where: eq(passportCheckpoints.passport_jti, passportJti),
      columns: { id: true },
    });
    return rows.length;
  }

  async findLatestByPassport(passportJti: string) {
    return this.db.query.passportCheckpoints.findFirst({
      where: eq(passportCheckpoints.passport_jti, passportJti),
      orderBy: (c, { desc }) => [desc(c.submitted_at)],
    });
  }
}
