import {
  observeRedisClient,
  REDIS_COMMAND_TIMEOUT_MS,
  REDIS_CONNECT_TIMEOUT_MS,
  redisBackoffMs,
  safeErrorSummary,
  waitForRedis,
  type Database,
} from '@stack/shared';
import { isRedisOutageError } from './transient-db-error.js';

export type WorkerDb = Database;

/** `ioredis` is loaded with a dynamic `import()` for ESM interop; keep it that way. */
export async function createRedis(url: string) {
  const { Redis } = await import('ioredis');
  // A command gives up after two reconnect attempts, so a Redis outage fails a
  // tick quickly and the poll's backoff takes over, instead of one command
  // holding the tick for the library's twenty retries.
  // A command also gives up after REDIS_COMMAND_TIMEOUT_MS: a socket that is open
  // and never answers does not reconnect, and one hung command would hold the
  // guarded tick (which never overlaps itself) for ever. The timeout reads as an
  // outage (`isRedisOutageError`) and the poll backs off. No command here blocks.
  const redis = new Redis(url, {
    maxRetriesPerRequest: 2,
    commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
    connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
  });
  // Without a listener ioredis prints every reconnect error; keep one line per
  // half minute, with the connection string and driver text left out, on this
  // client and on the subscriber copied from it.
  return observeRedisClient(redis);
}

export type WorkerRedis = Awaited<ReturnType<typeof createRedis>>;

type Sleep = (ms: number) => Promise<void>;
const realSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The worker calls `waitForRedis` at boot so a Redis that is still starting, or briefly down, delays it instead of exiting it. */
export { redisBackoffMs, waitForRedis };

/**
 * Run the boot, and run it again after a backoff when it failed because Redis
 * dropped out part-way. Any other failure (a missing secret, a refused
 * configuration) propagates so the worker still stops on a real misconfiguration.
 */
export async function runBootWithRedisRetry(boot: () => Promise<void>, sleep: Sleep = realSleep): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await boot();
      return;
    } catch (err) {
      if (!isRedisOutageError(err)) throw err;
      const waitMs = redisBackoffMs(attempt);
      console.warn('[boot] Redis unavailable during startup and retrying:', 'attempt', attempt, 'wait s', Math.round(waitMs / 1000), safeErrorSummary(err));
      await sleep(waitMs);
    }
  }
}
