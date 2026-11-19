// A mounted secret (DATABASE_URL_FILE) is read into its setting before the line below reads the environment.
import '../secret-files.js';
import { drizzle } from 'drizzle-orm/postgres-js';
import { readMigrationFiles } from 'drizzle-orm/migrator';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { describeMigrationFailure, secretsOf, type MigrationFile } from './migration-failure.js';

// Resolve the migrations folder relative to this file, not process.cwd().
// A release command invokes us from /app (repo root); pnpm --filter
// in CI invokes us from apps/api/. A relative path breaks one or the
// other — an absolute path resolved from __dirname works everywhere.
const __dirname = dirname(fileURLToPath(import.meta.url));
const SHARED_DIR = resolve(__dirname, '..', '..', '..', '..', 'packages', 'shared');

// One database. The /attack guestbook used to be the second, and is not any
// more: it lives on Cloudflare D1, off our infrastructure entirely, because it
// is the one store whose content an attacker authored. Migration 0036 drops it
// from here. The deployment's own store is built where it is configured.

const DATABASE_URL = process.env['DATABASE_URL'];
if (!DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}

const MIGRATIONS_FOLDER = join(SHARED_DIR, 'drizzle');

// drizzle's migrate() reads meta/_journal.json to decide what to apply.
// A SQL file present in the folder but absent from the journal is
// silently skipped — migrate() still reports 'Migrations complete'.
// That is how a migration can sit unapplied through a deploy while the
// schema already references its column. Fail loudly before drizzle gets a
// chance to no-op past the drift.
function assertJournalCoversAllSqlFiles(folder: string): void {
  const journalPath = join(folder, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf-8')) as {
    entries: Array<{ tag: string }>;
  };
  const journaled = new Set(journal.entries.map((e) => e.tag));
  const unjournaled = readdirSync(folder)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => f.replace(/\.sql$/, ''))
    .filter((tag) => !journaled.has(tag));
  if (unjournaled.length === 0) return;
  console.error(
    '[migrate] Migration journal drift:', unjournaled.length, 'SQL files in', folder, 'are not registered in meta/_journal.json. drizzle would silently skip them:',
  );
  for (const tag of unjournaled) {
    console.error('[migrate] unjournaled migration:', `${tag}.sql`);
  }
  console.error(
    '[migrate] Add a journal entry for each file and redeploy:', 'each entry needs idx, version, when, tag and breakpoints in meta/_journal.json.',
  );
  process.exit(1);
}

async function runMigrations() {
  assertJournalCoversAllSqlFiles(MIGRATIONS_FOLDER);
  console.log('Running database migrations...');

  const client = postgres(DATABASE_URL!, { max: 1 });
  try {
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    console.log('Migrations complete.');
  } finally {
    await client.end();
  }
}
// The files in journal order, for naming the one that failed. Reading them again cannot make a failure worse: it is best effort.
function migrationFiles(): MigrationFile[] {
  try {
    const journal = JSON.parse(readFileSync(join(MIGRATIONS_FOLDER, 'meta', '_journal.json'), 'utf-8')) as { entries: Array<{ tag: string }> };
    const read = readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER });
    return journal.entries.map((entry, index) => ({ tag: entry.tag, statements: read[index]?.sql ?? [] }));
  } catch {
    return [];
  }
}

runMigrations().catch((error: unknown) => {
  // The label is fixed so the console guard keeps it; the message carries the same prefix, so it is not printed twice.
  console.error('[migrate]', describeMigrationFailure(error, migrationFiles(), secretsOf(DATABASE_URL)).replace(/^\[migrate\] /, ''));
  process.exit(1);
});
