import { sql } from 'drizzle-orm';
import type { Database } from './connection.js';

type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0];

/** Run historical DDL on the current table shapes without locking shared fixtures. */
export async function isolateMigrationTables(tx: Transaction, tables: string[]): Promise<void> {
  for (const table of tables) {
    // LIKE copies columns, defaults, checks and indexes, but deliberately omits
    // foreign keys. The exact migration under test installs those constraints.
    await tx.execute(sql`CREATE TEMP TABLE ${sql.identifier(table)}
      (LIKE public.${sql.identifier(table)} INCLUDING ALL) ON COMMIT DROP`);
  }
  await tx.execute(sql`SET LOCAL search_path = pg_temp`);
}
