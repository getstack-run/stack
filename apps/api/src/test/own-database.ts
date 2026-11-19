import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { isDedicatedStackTestDatabase } from './dedicated-test-database.js';

/**
 * A migrated database of a test file's own, next to the shared test database.
 *
 * Most `*.postgres.test.ts` suites share one database and are written for it: every one creates its own
 * operators and only reads those. A suite that changes rows it did not create, or the schema itself, cannot be
 * written that way, and run beside the others it changes what they read (an install that moves every
 * operator to its contract plan, a build that drops and re-creates an index on a table the others write).
 * Such a suite creates a database of its own in `beforeAll`, points `DATABASE_URL` at it for the code under
 * test, and drops it in `afterAll`.
 *
 * The server and the credentials are those of the shared database the run was given, which must itself be a
 * dedicated test database (`isDedicatedStackTestDatabase`); the new name passes the same check, so everything
 * that refuses a database that is not a test one accepts it. The schema is the migration chain of the tree the
 * test runs in (`packages/shared/drizzle`: the full chain in the private repository, the engine chain in the
 * public one), applied with the real migrator.
 */

const MIGRATIONS_FOLDER = fileURLToPath(new URL('../../../../packages/shared/drizzle', import.meta.url));

export interface OwnDatabase {
  /** The connection URL of the new database. */
  url: string;
  /** The database's name. */
  name: string;
  /** Drops the database, closing any connection still open to it. */
  drop(): Promise<void>;
}

/** The name of a new database on the same server: it keeps the prefix its server's guard accepts. */
function nameFor(sharedUrl: string, label: string): string {
  if (!/^[a-z0-9]{1,19}$/.test(label)) throw new Error(`the label ${label} must be 1 to 19 lowercase letters or digits`);
  const suffix = `${label}_${randomBytes(4).toString('hex')}`;
  return new URL(sharedUrl).port === '5433' ? `stack_ci_iso_${suffix}` : `stack_iso_${suffix}`;
}

function atDatabase(sharedUrl: string, name: string): string {
  const next = new URL(sharedUrl);
  next.pathname = `/${name}`;
  return next.toString();
}

export async function createOwnDatabase(sharedUrl: string | undefined, label: string): Promise<OwnDatabase> {
  if (!isDedicatedStackTestDatabase(sharedUrl)) throw new Error('an own database is only created next to a dedicated test database');
  const name = nameFor(sharedUrl, label);
  const url = atDatabase(sharedUrl, name);
  if (!isDedicatedStackTestDatabase(url)) throw new Error(`${name} is not a name the test-database guard accepts`);

  const withAdmin = async <T>(run: (sql: postgres.Sql) => Promise<T>): Promise<T> => {
    const admin = postgres(sharedUrl, { max: 1, onnotice: () => {} });
    try {
      return await run(admin);
    } finally {
      await admin.end({ timeout: 5 });
    }
  };
  const drop = () => withAdmin((admin) => admin.unsafe(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`).then(() => undefined));

  await withAdmin((admin) => admin.unsafe(`CREATE DATABASE "${name}"`));
  try {
    const sql = postgres(url, { max: 1, onnotice: () => {} });
    try {
      await migrate(drizzle(sql), { migrationsFolder: MIGRATIONS_FOLDER });
    } finally {
      await sql.end({ timeout: 5 });
    }
  } catch (error) {
    await drop();
    throw error;
  }
  return { url, name, drop };
}
