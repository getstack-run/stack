import { and, eq, sql } from 'drizzle-orm';
import { type Database, cmekMigrations } from '@stack/shared';

type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export type MigrationDirection = 'enable' | 'disable';
export type MigrationStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface CmekMigrationRow {
  id: string;
  operator_id: string;
  direction: MigrationDirection;
  table_name: string;
  rows_total: number;
  rows_done: number;
  status: MigrationStatus;
  error: string | null;
  started_at: Date | null;
  completed_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * Persistence for the CMEK migration worker's per-table progress.
 * The (operator_id, direction, table_name) unique index makes the worker
 * idempotent: re-running an enable after a crash UPSERTs into the same row.
 */
export class CmekMigrationRepository {
  constructor(private db: Database) {}

  async upsertPending(
    id: string,
    operatorId: string,
    direction: MigrationDirection,
    tableName: string,
    transaction?: DbTransaction,
  ): Promise<CmekMigrationRow> {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .insert(cmekMigrations)
      .values({
        id,
        operator_id: operatorId,
        direction,
        table_name: tableName,
        rows_total: 0,
        rows_done: 0,
        status: 'pending',
      })
      .onConflictDoUpdate({
        target: [cmekMigrations.operator_id, cmekMigrations.direction, cmekMigrations.table_name],
        set: { updated_at: new Date() },
      })
      .returning();
    return row as CmekMigrationRow;
  }

  async markRunning(id: string, rowsTotal: number, transaction?: DbTransaction): Promise<void> {
    const executor = transaction ?? this.db;
    await executor
      .update(cmekMigrations)
      .set({
        status: 'running',
        rows_total: rowsTotal,
        started_at: new Date(),
        updated_at: new Date(),
      })
      .where(eq(cmekMigrations.id, id));
  }

  async bumpProgress(id: string, delta: number): Promise<void> {
    await this.db
      .update(cmekMigrations)
      .set({
        rows_done: sql`${cmekMigrations.rows_done} + ${delta}`,
        updated_at: new Date(),
      })
      .where(eq(cmekMigrations.id, id));
  }

  async markCompleted(id: string, transaction?: DbTransaction): Promise<void> {
    const executor = transaction ?? this.db;
    await executor
      .update(cmekMigrations)
      .set({
        status: 'completed',
        completed_at: new Date(),
        updated_at: new Date(),
      })
      .where(eq(cmekMigrations.id, id));
  }

  async markFailed(id: string, error: string): Promise<void> {
    await this.db
      .update(cmekMigrations)
      .set({
        status: 'failed',
        error: error.slice(0, 2000),
        updated_at: new Date(),
      })
      .where(eq(cmekMigrations.id, id));
  }

  async listByOperator(operatorId: string): Promise<CmekMigrationRow[]> {
    const rows = await this.db
      .select()
      .from(cmekMigrations)
      .where(eq(cmekMigrations.operator_id, operatorId));
    return rows as CmekMigrationRow[];
  }

  async listByOperatorAndDirection(
    operatorId: string,
    direction: MigrationDirection,
    transaction?: DbTransaction,
  ): Promise<CmekMigrationRow[]> {
    const executor = transaction ?? this.db;
    const rows = await executor
      .select()
      .from(cmekMigrations)
      .where(
        and(eq(cmekMigrations.operator_id, operatorId), eq(cmekMigrations.direction, direction)),
      );
    return rows as CmekMigrationRow[];
  }

  async deleteByOperator(operatorId: string, transaction?: DbTransaction): Promise<void> {
    const executor = transaction ?? this.db;
    await executor.delete(cmekMigrations).where(eq(cmekMigrations.operator_id, operatorId));
  }
}
