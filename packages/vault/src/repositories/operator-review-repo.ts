import type { Database } from '@stack/shared';
import { sql } from 'drizzle-orm';
import { PassportClaimsRepository } from './passport-claims-repo.js';

export type OperatorReviewDbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export class OperatorReviewRepository {
  constructor(private readonly db: Database) {}

  async transaction<T>(
    operatorId: string,
    missionId: string,
    callback: (claims: PassportClaimsRepository, transaction: OperatorReviewDbTransaction) => Promise<T>,
  ): Promise<T> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(
        hashtextextended(${`${operatorId}:${missionId}:operator-review`}, 0)
      )`);
      return callback(new PassportClaimsRepository(tx as unknown as Database), tx);
    });
  }
}
