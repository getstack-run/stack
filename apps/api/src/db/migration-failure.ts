// What a failed migration says. drizzle runs every pending migration in one transaction and reports only the database's
// error, so the release log named neither the file nor the reason. The failing statement is on the error (postgres.js
// keeps it as `query`), which names the file; the reason is the Postgres error's own code, message, detail and hint.
// Nothing else is printed: not the connection string, not the host, and any URL or the database password that a message
// happens to quote is blanked.

export interface MigrationFile {
  tag: string;
  statements: string[];
}

interface PgErrorFields {
  name?: unknown;
  code?: unknown;
  message?: unknown;
  detail?: unknown;
  hint?: unknown;
  query?: unknown;
  cause?: unknown;
}

const REDACTED = '[redacted]';

function scrub(value: string, secrets: readonly string[]): string {
  let out = value.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s'")]+/gi, REDACTED);
  for (const secret of secrets) {
    if (secret.length >= 4) out = out.split(secret).join(REDACTED);
  }
  return out.replace(/\s+/g, ' ').trim();
}

/** The credentials inside a connection string, for blanking wherever an error message quotes them. */
export function secretsOf(connectionString: string | undefined): string[] {
  if (!connectionString) return [];
  try {
    const url = new URL(connectionString);
    return [decodeURIComponent(url.password), url.password, connectionString].filter((part) => part.length > 0);
  } catch {
    return [connectionString];
  }
}

function asPgError(error: unknown): PgErrorFields | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < 3 && current && typeof current === 'object'; depth += 1) {
    const candidate = current as PgErrorFields;
    if (candidate.name === 'PostgresError') return candidate;
    current = candidate.cause;
  }
  return undefined;
}

/** The tag of the migration whose statement failed, or undefined when the error does not carry the statement. */
export function failingTag(error: unknown, files: readonly MigrationFile[]): string | undefined {
  const pg = asPgError(error);
  const query = pg && typeof pg.query === 'string' ? pg.query.trim() : '';
  if (!query) return undefined;
  return files.find((file) => file.statements.some((statement) => statement.trim() === query))?.tag
    ?? files.find((file) => file.statements.some((statement) => statement.includes(query)))?.tag;
}

/** The one line the release log gets when a migration fails. */
export function describeMigrationFailure(error: unknown, files: readonly MigrationFile[], secrets: readonly string[] = []): string {
  const tag = failingTag(error, files);
  const where = tag ? `${tag}.sql` : 'migration not identified';
  const pg = asPgError(error);
  if (!pg) return `[migrate] Migration failed (${where}): not a database error, details suppressed.`;
  const parts: string[] = [];
  for (const [label, value] of [['code', pg.code], ['message', pg.message], ['detail', pg.detail], ['hint', pg.hint]] as const) {
    if (typeof value === 'string' && value.length > 0) parts.push(`${label}=${JSON.stringify(scrub(value, secrets))}`);
  }
  return `[migrate] Migration failed (${where}): ${parts.join(' ')}`;
}
