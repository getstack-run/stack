import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sentry = vi.hoisted(() => ({ captureException: vi.fn() }));
vi.mock('@sentry/node', () => ({ captureException: sentry.captureException }));

import { createPoll, REDIS_OUTAGE_MAX_BACKOFF_MS } from './loop.js';
import { isTransientDependencyError } from './transient-db-error.js';
import { redisBackoffMs, runBootWithRedisRetry, waitForRedis } from './redis.js';

function redisDown(): Error {
  const error = new Error('Reached the max retries per request limit (which is 2).');
  error.name = 'MaxRetriesPerRequestError';
  return error;
}

beforeEach(() => {
  sentry.captureException.mockClear();
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('isTransientDependencyError', () => {
  it('treats a Redis outage as transient, also when wrapped, and a database blip as before', () => {
    expect(isTransientDependencyError(redisDown())).toBe(true);
    expect(isTransientDependencyError(Object.assign(new Error('job failed'), { cause: redisDown() }))).toBe(true);
    expect(isTransientDependencyError(Object.assign(new Error('x'), { code: 'ECONNRESET' }))).toBe(true);
    expect(isTransientDependencyError(new Error('WRONGTYPE Operation against a key'))).toBe(false);
    expect(isTransientDependencyError(new Error('plain bug'))).toBe(false);
  });
});

describe('createPoll under a Redis outage', () => {
  it('keeps going, backs off between attempts and does not page on the first ticks', async () => {
    let clock = 1_000_000;
    const tick = vi.fn(async () => {
      throw redisDown();
    });
    const poll = createPoll({ tick, sentryDsn: 'https://dsn.invalid/1', now: () => clock });

    await poll(); // fails, schedules the next attempt
    expect(tick).toHaveBeenCalledTimes(1);

    clock += 5_000; // still inside the backoff window: skipped, not run
    await poll();
    expect(tick).toHaveBeenCalledTimes(1);

    clock += 10_000; // past it: tried again
    await poll();
    expect(tick).toHaveBeenCalledTimes(2);

    expect(sentry.captureException).not.toHaveBeenCalled();
  });

  it('doubles the wait with each failure up to a cap, and escalates to Sentry once sustained', async () => {
    let clock = 0;
    const tick = vi.fn(async () => {
      throw redisDown();
    });
    const poll = createPoll({ tick, sentryDsn: 'https://dsn.invalid/1', now: () => clock });
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await poll();
      clock += REDIS_OUTAGE_MAX_BACKOFF_MS + 1; // always past the window
    }
    expect(tick).toHaveBeenCalledTimes(8);
    expect(sentry.captureException).toHaveBeenCalled();
    expect(sentry.captureException.mock.calls[0]![1]).toMatchObject({ tags: { kind: 'sustained_redis_outage' } });
  });

  it('runs normally again the tick after Redis returns and forgets the outage', async () => {
    let clock = 0;
    let healthy = false;
    const tick = vi.fn(async () => {
      if (!healthy) throw redisDown();
    });
    const poll = createPoll({ tick, sentryDsn: undefined, now: () => clock });
    await poll();
    healthy = true;
    clock += REDIS_OUTAGE_MAX_BACKOFF_MS + 1;
    await poll();
    clock += 1; // no backoff left after a clean tick
    await poll();
    expect(tick).toHaveBeenCalledTimes(3);
  });

  it('still reports an unrelated error straight away', async () => {
    const poll = createPoll({
      tick: async () => {
        throw new Error('a real bug');
      },
      sentryDsn: 'https://dsn.invalid/1',
    });
    await poll();
    expect(sentry.captureException).toHaveBeenCalledTimes(1);
  });
});

describe('redisBackoffMs', () => {
  it('doubles from one second and stops at thirty', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 20].map(redisBackoffMs)).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
  });
});

describe('waitForRedis', () => {
  it('retries until Redis answers and never throws', async () => {
    const ping = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(redisDown())
      .mockRejectedValueOnce(redisDown())
      .mockResolvedValue('PONG');
    const sleeps: number[] = [];
    await waitForRedis({ ping } as never, async (ms) => {
      sleeps.push(ms);
    });
    expect(ping).toHaveBeenCalledTimes(3);
    expect(sleeps).toEqual([1000, 2000]);
  });
});

describe('runBootWithRedisRetry', () => {
  it('retries a boot that failed on a Redis outage instead of letting the process exit', async () => {
    const boot = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(redisDown())
      .mockResolvedValue(undefined);
    const sleeps: number[] = [];
    await runBootWithRedisRetry(boot, async (ms) => {
      sleeps.push(ms);
    });
    expect(boot).toHaveBeenCalledTimes(2);
    expect(sleeps).toEqual([1000]);
  });

  it('rethrows any other boot failure so a real misconfiguration still stops the worker', async () => {
    const boot = vi.fn(async () => {
      throw new Error('missing AUDIT_ARCHIVE_BUCKET');
    });
    await expect(runBootWithRedisRetry(boot, async () => undefined)).rejects.toThrow('missing AUDIT_ARCHIVE_BUCKET');
    expect(boot).toHaveBeenCalledTimes(1);
  });
});
