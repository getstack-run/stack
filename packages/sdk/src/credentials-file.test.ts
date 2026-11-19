import { mkdtemp, readFile, rm, stat, utimes, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { credentialsFilePath, readCredentialsFile, withCredentialsLock, writeCredentialsFile, type StoredCredentials } from './credentials-file.js';

// ~/.stack/credentials.json as spec/credentials-files describes it: what this client reads, what it writes, with which mode.

const CREDENTIALS: StoredCredentials = {
  client_id: 'oclient_example',
  refresh_token: 'refresh-one',
  issued_at: 1_790_000_000,
  refresh_expires_at: 1_792_592_000,
  operator_email: 'owner@example.test',
  scope: 'agents:read',
};

describe('the operator sign-in file', () => {
  let home = '';
  const saved = { HOME: process.env['HOME'], USERPROFILE: process.env['USERPROFILE'] };
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), 'stack-home-'));
    process.env['HOME'] = home;
    process.env['USERPROFILE'] = home;
  });
  afterEach(async () => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(home, { recursive: true, force: true });
  });

  it('lives at .stack/credentials.json under the home directory', async () => {
    expect(await credentialsFilePath()).toBe(join(home, '.stack', 'credentials.json'));
  });

  it('writes what it reads, whole', async () => {
    await writeCredentialsFile(CREDENTIALS);
    expect(JSON.parse(await readFile(join(home, '.stack', 'credentials.json'), 'utf8'))).toEqual(CREDENTIALS);
    expect(await readCredentialsFile()).toEqual(CREDENTIALS);
  });

  it.runIf(process.platform !== 'win32')('creates the file readable by its owner only, and keeps it so when it rewrites one that was open to others', async () => {
    await writeCredentialsFile(CREDENTIALS);
    expect((await stat(join(home, '.stack', 'credentials.json'))).mode & 0o777).toBe(0o600);
    const path = join(home, '.stack', 'credentials.json');
    await rm(path);
    await mkdir(join(home, '.stack'), { recursive: true });
    await writeFile(path, '{}', { mode: 0o644 });
    await writeCredentialsFile(CREDENTIALS);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it('treats a file that cannot sign anyone in as no sign-in', async () => {
    const path = join(home, '.stack', 'credentials.json');
    await mkdir(join(home, '.stack'), { recursive: true });
    expect(await readCredentialsFile()).toBeNull(); // no file
    for (const body of ['', 'not json', '[]', 'null', '"text"', '{}', '{"client_id":"x"}', '{"refresh_token":"x"}', '{"client_id":"","refresh_token":"x"}', '{"client_id":"x","refresh_token":5}']) {
      await writeFile(path, body);
      expect(await readCredentialsFile(), body).toBeNull();
    }
  });

  describe('the lock', () => {
    const lockPath = () => join(home, '.stack', 'credentials.lock');

    it('is held while the renewal runs, holds the process id, and is gone after, whatever happened', async () => {
      await withCredentialsLock(async () => {
        expect(await readFile(lockPath(), 'utf8')).toBe(String(process.pid));
      });
      await expect(readFile(lockPath(), 'utf8')).rejects.toThrow();
      await expect(withCredentialsLock(async () => { throw new Error('the exchange failed'); })).rejects.toThrow('the exchange failed');
      await expect(readFile(lockPath(), 'utf8')).rejects.toThrow();
    });

    it('takes the lock of a holder that died, and waits for one that is alive', async () => {
      await mkdir(join(home, '.stack'), { recursive: true });
      await writeFile(lockPath(), '12345');
      const old = new Date(Date.now() - 60_000);
      await utimes(lockPath(), old, old);
      await withCredentialsLock(async () => {
        expect(await readFile(lockPath(), 'utf8')).toBe(String(process.pid));
      });

      await writeFile(lockPath(), '999');
      setTimeout(() => void rm(lockPath()), 300);
      const started = Date.now();
      await withCredentialsLock(async () => {
        expect(Date.now() - started).toBeGreaterThanOrEqual(250);
      });
    });

    it('runs one renewal after another, never two at once', async () => {
      const order: string[] = [];
      const renew = (name: string) => withCredentialsLock(async () => {
        order.push(`${name} start`);
        await new Promise((resolve) => setTimeout(resolve, 100));
        order.push(`${name} end`);
      });
      await Promise.all([renew('a'), renew('b')]);
      expect(order.slice(0, 2).map((entry) => entry.split(' ')[0])).toHaveLength(2);
      expect(order[0]!.split(' ')[0]).toBe(order[1]!.split(' ')[0]);
      expect(order[2]!.split(' ')[0]).toBe(order[3]!.split(' ')[0]);
    });
  });

  it('keeps the fields it does not know', async () => {
    await writeCredentialsFile({ ...CREDENTIALS, future_field: 'kept' } as StoredCredentials);
    expect((await readCredentialsFile()) as unknown as Record<string, unknown>).toMatchObject({ future_field: 'kept' });
  });
});
