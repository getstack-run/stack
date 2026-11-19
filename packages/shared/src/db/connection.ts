import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as engineSchema from './schema/index.js';

/** The tables the engine owns. A hosted build passes these merged with its own (see `@stack/shared/hosted`). */
export { engineSchema };
export type EngineSchema = typeof engineSchema;

function open<TSchema extends Record<string, unknown>>(connectionString: string, schema: TSchema) {
  const client = postgres(connectionString, {
    max: 20,
    idle_timeout: 30,
    connect_timeout: 10,
    // A managed Postgres service fronts the DB with pgbouncer in transaction-pooling
    // mode. prepare:false is required there (prepared statements aren't
    // supported and trigger connection errors). max_lifetime recycles client
    // connections so we never reuse a server connection pgbouncer has already
    // closed — the cause of `write CONNECTION_CLOSED ... pgbouncer` errors
    // (Sentry STACK-API-H, 2026-06).
    max_lifetime: 60 * 30,
    prepare: false,
  });

  return drizzle(client, { schema });
}

/** A database handle that can read the tables of `TSchema` relationally (`db.query.<table>`). */
export type DbHandle<TSchema extends Record<string, unknown>> = ReturnType<typeof open<TSchema>>;

/** The engine's handle: `db.query` knows the engine's tables only. */
export type Database = DbHandle<EngineSchema>;

/**
 * Opens the database. Without a schema the handle knows the engine's tables; a
 * build that has more tables passes its own schema, which must contain the
 * engine's (the hosted build has its own opener).
 */
export function createDb<TSchema extends Record<string, unknown>>(connectionString: string, schema: TSchema): DbHandle<TSchema>;
export function createDb(connectionString: string): Database;
export function createDb(connectionString: string, schema?: Record<string, unknown>): unknown {
  return open(connectionString, schema ?? engineSchema);
}
