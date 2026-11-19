import { beforeEach, describe, expect, it, vi } from 'vitest';
import { takeDailyLock, forgetUnconfirmedDailyLocks, unconfirmedDailyLockCount, DAILY_LOCK_TTL_SECONDS } from './daily-lock.js';
import { maybeRunColdArchive } from './jobs/cold-archive.js';

function timedOut(): Error {
  return new Error('Command timed out');
}

/** A Redis whose SET can run on the server and still fail for the caller, as a late reply does. */
function fakeRedis(options: { executeThenFail?: boolean; failGet?: boolean; heldBy?: string } = {}) {
  const store = new Map<string, string>();
  if (options.heldBy) store.set('lock', options.heldBy);
  const redis = {
    set: vi.fn(async (key: string, value: string, _ex: 'EX', _seconds: number, _nx: 'NX') => {
      if (store.has(key)) {
        if (options.executeThenFail) throw timedOut();
        return null;
      }
      store.set(key, value);
      if (options.executeThenFail) throw timedOut();
      return 'OK';
    }),
    get: vi.fn(async (key: string) => {
      if (options.failGet) throw timedOut();
      return store.get(key) ?? null;
    }),
  };
  return { redis, store };
}

describe('takeDailyLock', () => {
  beforeEach(() => forgetUnconfirmedDailyLocks());

  it('takes a free day and writes the time with a token', async () => {
    const { redis, store } = fakeRedis();
    await expect(takeDailyLock(redis, 'lock')).resolves.toBe(true);
    expect(redis.set).toHaveBeenCalledWith('lock', expect.stringMatching(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z#[0-9a-f-]{36}$/), 'EX', DAILY_LOCK_TTL_SECONDS, 'NX');
    expect(store.get('lock')).toContain('#');
  });

  it('answers false when another run holds the day', async () => {
    const { redis } = fakeRedis({ heldBy: '2026-10-27T00:00:00.000Z#other' });
    await expect(takeDailyLock(redis, 'lock')).resolves.toBe(false);
    expect(redis.get).not.toHaveBeenCalled();
  });

  it('holds the lock when the SET ran on the server but its reply was lost: the day is not skipped', async () => {
    const { redis } = fakeRedis({ executeThenFail: true });
    await expect(takeDailyLock(redis, 'lock')).resolves.toBe(true);
  });

  it('answers false, not an error, when the lost reply was for a SET another run had already beaten', async () => {
    const { redis } = fakeRedis({ executeThenFail: true, heldBy: '2026-10-27T00:00:00.000Z#other' });
    await expect(takeDailyLock(redis, 'lock')).resolves.toBe(false);
  });

  it('throws the outage, so the tick retries, when the SET did not run', async () => {
    const redis = { set: vi.fn(async () => { throw timedOut(); }), get: vi.fn(async () => null) };
    await expect(takeDailyLock(redis, 'lock')).rejects.toThrow('Command timed out');
  });

  it('throws the outage when the key cannot be read either', async () => {
    const { redis } = fakeRedis({ executeThenFail: true, failGet: true });
    await expect(takeDailyLock(redis, 'lock')).rejects.toThrow('Command timed out');
  });

  it('holds the day on the next tick when the lost SET landed and the read failed too, instead of skipping it', async () => {
    const store = new Map<string, string>();
    let silent = true;
    const redis = {
      set: vi.fn(async (key: string, value: string) => {
        if (store.has(key)) return null;
        store.set(key, value);
        if (silent) throw timedOut();
        return 'OK';
      }),
      get: vi.fn(async (key: string) => {
        if (silent) throw timedOut();
        return store.get(key) ?? null;
      }),
    };
    // The first tick: the SET ran on the server, and neither its reply nor the read came back.
    await expect(takeDailyLock(redis, 'lock-silent')).rejects.toThrow('Command timed out');
    // The next tick: Redis answers. The key holds this process's own value from the lost attempt.
    silent = false;
    await expect(takeDailyLock(redis, 'lock-silent')).resolves.toBe(true);
    // Remembered once: a further tick finds the day held by a run that is no longer this one's unconfirmed attempt.
    await expect(takeDailyLock(redis, 'lock-silent')).resolves.toBe(false);
  });

  it('forgets a lost attempt once its day has passed, instead of keeping it for the life of the process', async () => {
    const silent = { set: vi.fn(async () => { throw timedOut(); }), get: vi.fn(async () => { throw timedOut(); }) };
    const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
    const today = new Date().toISOString().slice(0, 10);
    await expect(takeDailyLock(silent, `cold_archive:${yesterday}`)).rejects.toThrow('Command timed out');
    await expect(takeDailyLock(silent, `cold_archive:${today}`)).rejects.toThrow('Command timed out');
    expect(unconfirmedDailyLockCount()).toBe(1);
    // The next tick, on any key, drops what belonged to a day that has gone.
    await expect(takeDailyLock(silent, `usage_rollup:${today}`)).rejects.toThrow('Command timed out');
    expect(unconfirmedDailyLockCount()).toBe(2);
  });

  it('takes the day normally on the next tick when the lost SET had not landed', async () => {
    const store = new Map<string, string>();
    let silent = true;
    const redis = {
      set: vi.fn(async (key: string, value: string) => {
        if (silent) throw timedOut();
        if (store.has(key)) return null;
        store.set(key, value);
        return 'OK';
      }),
      get: vi.fn(async (key: string) => {
        if (silent) throw timedOut();
        return store.get(key) ?? null;
      }),
    };
    await expect(takeDailyLock(redis, 'lock-never-landed')).rejects.toThrow('Command timed out');
    silent = false;
    await expect(takeDailyLock(redis, 'lock-never-landed')).resolves.toBe(true);
  });

  it('answers false on the next tick when another run took the day after the lost attempt', async () => {
    const store = new Map<string, string>();
    let silent = true;
    const redis = {
      set: vi.fn(async () => { throw timedOut(); }),
      get: vi.fn(async (key: string) => {
        if (silent) throw timedOut();
        return store.get(key) ?? null;
      }),
    };
    await expect(takeDailyLock(redis, 'lock-other')).rejects.toThrow('Command timed out');
    silent = false;
    store.set('lock-other', '2026-10-27T00:00:00.000Z#another');
    await expect(takeDailyLock(redis, 'lock-other')).resolves.toBe(false);
  });

  it('does not hide an error that is not an outage', async () => {
    const redis = { set: vi.fn(async () => { throw new Error('WRONGTYPE Operation against a key'); }), get: vi.fn(async () => null) };
    await expect(takeDailyLock(redis, 'lock')).rejects.toThrow('WRONGTYPE');
    expect(redis.get).not.toHaveBeenCalled();
  });
});

describe('a daily job under a lost reply', () => {
  beforeEach(() => forgetUnconfirmedDailyLocks());

  it('still runs the cold archive once for the day', async () => {
    const { redis } = fakeRedis({ executeThenFail: true });
    const archiveAll = vi.fn(async () => ({}));
    await maybeRunColdArchive({ archive: { archiveAll }, redis } as never);
    expect(archiveAll).toHaveBeenCalledTimes(1);
  });
});
