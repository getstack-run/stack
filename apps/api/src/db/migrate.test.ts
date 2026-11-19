import { expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => ({ migrate: vi.fn(), end: vi.fn() }));
vi.mock('postgres', () => ({ default: () => ({ end: fixture.end }) }));
vi.mock('drizzle-orm/postgres-js', () => ({ drizzle: () => ({}) }));
vi.mock('drizzle-orm/postgres-js/migrator', () => ({ migrate: fixture.migrate }));

it('fails without serializing database errors or connection details', async () => {
  const canary = 'synthetic-database-credential-canary';
  fixture.migrate.mockRejectedValue(Object.assign(new Error(canary), { connection: canary }));
  fixture.end.mockResolvedValue(undefined);
  vi.stubEnv('DATABASE_URL', 'postgresql://fixture:fixture@127.0.0.1:1/fixture');
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  const log = vi.spyOn(console, 'log').mockImplementation(() => {});
  const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
  try {
    await import('./migrate.js');
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));
    expect(fixture.end).toHaveBeenCalled();
    expect(error.mock.calls).toEqual([['[migrate]', 'Migration failed (migration not identified): not a database error, details suppressed.']]);
    expect(JSON.stringify([...error.mock.calls, ...log.mock.calls])).not.toContain(canary);
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  }
}, 30_000); // the first import loads the whole shared package, which is slow on a cold file system
