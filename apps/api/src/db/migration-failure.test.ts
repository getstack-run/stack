import { describe, expect, it } from 'vitest';
import { describeMigrationFailure, failingTag, secretsOf, type MigrationFile } from './migration-failure.js';

const files: MigrationFile[] = [
  { tag: '0001_first', statements: ['CREATE TABLE a (id int)'] },
  { tag: '0002_second', statements: ['\nINSERT INTO a VALUES (1);\n', 'ALTER TABLE a ADD COLUMN b text'] },
];

function pgError(fields: Record<string, unknown>): Error {
  const error = new Error(String(fields['message']));
  error.name = 'PostgresError';
  return Object.assign(error, fields);
}

describe('describeMigrationFailure', () => {
  it('names the failing migration and the database error code, message, detail and hint', () => {
    const error = pgError({
      code: '23505', message: 'duplicate key value violates unique constraint "a_pkey"',
      detail: 'Key (id)=(1) already exists.', hint: 'Remove the row first.', query: 'INSERT INTO a VALUES (1);',
    });
    expect(failingTag(error, files)).toBe('0002_second');
    expect(describeMigrationFailure(error, files)).toBe(
      '[migrate] Migration failed (0002_second.sql): code="23505" message="duplicate key value violates unique constraint \\"a_pkey\\"" detail="Key (id)=(1) already exists." hint="Remove the row first."',
    );
  });

  it('finds the migration through a wrapping error and says so when the statement is unknown', () => {
    const inner = pgError({ code: '42P01', message: 'relation "x" does not exist', query: 'ALTER TABLE a ADD COLUMN b text' });
    expect(describeMigrationFailure(Object.assign(new Error('wrapped'), { cause: inner }), files)).toContain('(0002_second.sql)');
    expect(describeMigrationFailure(pgError({ code: '42P01', message: 'relation "x" does not exist' }), files)).toContain('(migration not identified)');
  });

  it('never prints a connection string, the password or the host of a connection error', () => {
    const password = 's3cr3t-pw!';
    const url = ['postgresql://stack:', password, '@db.internal.example:5432/stack'].join('');
    const secrets = secretsOf(url);
    const quoting = pgError({
      code: '08006', message: `could not connect to ${url} with s3cr3t-pw!`, detail: `tried ${['postgres://u:', 'p', '@h/db'].join('')} and s3cr3t-pw!`, hint: 'check s3cr3t-pw!',
    });
    const line = describeMigrationFailure(quoting, files, secrets);
    for (const forbidden of ['s3cr3t-pw!', 'postgresql://', 'postgres://', 'db.internal.example']) expect(line).not.toContain(forbidden);
    const connection = Object.assign(new Error(`write ECONNREFUSED db.internal.example:5432 ${url}`), { code: 'ECONNREFUSED' });
    const other = describeMigrationFailure(connection, files, secrets);
    for (const forbidden of ['s3cr3t-pw!', 'postgresql://', 'db.internal.example']) expect(other).not.toContain(forbidden);
    expect(other).toBe('[migrate] Migration failed (migration not identified): not a database error, details suppressed.');
  });
});
