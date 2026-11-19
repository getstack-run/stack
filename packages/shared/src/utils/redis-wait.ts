import { safeErrorSummary } from './safe-telemetry.js';

type Sleep = (ms: number) => Promise<void>;
const realSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Wait before retry number `attempt` (1-based): one second, doubling, at most thirty. */
export function redisBackoffMs(attempt: number): number {
  return Math.min(1000 * 2 ** (attempt - 1), 30_000);
}

/**
 * Block until Redis answers a PING, retrying with backoff. It never throws unless the caller gives a cap
 * (`maxAttempts`): a one-shot command (a script, the install's command line) passes one so that an unreachable Redis
 * ends it with an error instead of leaving it waiting for ever; a server passes none.
 * A process calls it at boot before it opens a subscriber (`subscribe` on a
 * duplicate has no command timeout, so a Redis that accepts the socket and never
 * answers would hold the boot for ever on the first one): the PING is on the
 * client with the command timeout, so each attempt ends within the cap, is
 * logged and is retried, and a Redis that is still starting, or briefly down,
 * delays the boot instead of ending it (a process that exits is restarted by the
 * platform only a few times before it is left stopped).
 */
export async function waitForRedis(
  redis: { ping(): Promise<unknown> },
  sleep: Sleep = realSleep,
  maxAttempts: number = Infinity,
): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await redis.ping();
      return;
    } catch (err) {
      if (attempt >= maxAttempts) {
        // The driver's error is deliberately not attached: it can carry the address, and a caller may log the whole error.
        // eslint-disable-next-line preserve-caught-error
        throw new Error(`[redis] not reachable after ${attempt} attempts; ${safeErrorSummary(err)}`);
      }
      const waitMs = redisBackoffMs(attempt);
      console.warn('[redis] not reachable yet and retrying:', 'attempt', attempt, 'wait s', Math.round(waitMs / 1000), safeErrorSummary(err));
      await sleep(waitMs);
    }
  }
}
