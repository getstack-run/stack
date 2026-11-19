import { sql } from 'drizzle-orm';
import type { Database } from './connection.js';

type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0];

const OAUTH_OPERATOR_LOCK_NAMESPACE = 239;
const OAUTH_REFRESH_FAMILY_LOCK_NAMESPACE = 240;

export async function acquireOAuthOperatorLock(
  tx: Transaction,
  operatorId: string,
): Promise<void> {
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtextextended(${operatorId}, ${sql.raw(String(OAUTH_OPERATOR_LOCK_NAMESPACE))}))`,
  );
}

export async function acquireOAuthRefreshFamilyLocks(
  tx: Transaction,
  familyIds: readonly string[],
): Promise<void> {
  for (const familyId of [...new Set(familyIds)].sort()) {
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtextextended(${familyId}, ${sql.raw(String(OAUTH_REFRESH_FAMILY_LOCK_NAMESPACE))}))`,
    );
  }
}
