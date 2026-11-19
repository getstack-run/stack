import * as Sentry from '@sentry/node';
import { safeErrorSummary } from '@stack/shared';
import { isRedisOutageError, isTransientDbError } from './transient-db-error.js';

/** Time between polls. */
export const POLL_INTERVAL_MS = 10_000;

/** Consecutive transient DB errors before the worker reports to Sentry. */
const SUSTAINED_TRANSIENT_TICKS = 3;

/** The longest the worker waits between attempts while Redis is unreachable. */
export const REDIS_OUTAGE_MAX_BACKOFF_MS = 120_000;

/**
 * Run `task` every `intervalMs`, never concurrently with itself. A tick that
 * fires while the previous run is still in flight is skipped, so a slow poll
 * delays the next run instead of overlapping it. Returns a function that
 * stops the loop; an already-running tick is left to finish.
 */
export function startGuardedInterval(
  task: () => Promise<void>,
  intervalMs: number,
): () => void {
  let inFlight = false;
  const timer = setInterval(() => {
    if (inFlight) return;
    inFlight = true;
    void task()
      .catch(() => {})
      .finally(() => {
        inFlight = false;
      });
  }, intervalMs);
  return () => clearInterval(timer);
}

/** How one tick ended, for whatever records the worker's own state (its heartbeat, the Systems page). */
export type TickOutcome =
  | { ok: true }
  | { ok: false; kind: 'redis' | 'database' | 'other' };

export interface PollOptions {
  /** The ordered work of one tick. A throw aborts the tick; the next one retries. */
  tick: () => Promise<void>;
  /**
   * Started before the tick and never awaited, so a database blip in the tick
   * cannot skip it. Must never reject.
   */
  detached?: () => void;
  /** Sentry is only called when a DSN is configured. */
  sentryDsn: string | undefined;
  /** Clock for the Redis backoff; tests pass their own. */
  now?: () => number;
  /**
   * Told how each tick ended, once the tick has: the worker's heartbeat is written from a clean tick, so a worker that is stuck stops
   * looking online. A tick skipped by the Redis backoff is not told. Must not throw.
   */
  onTick?: (outcome: TickOutcome) => void;
}

/**
 * Wrap one tick with error classification. Transient DB blips self-recover on
 * the next tick (10s), so they are noise in Sentry. Real sustained problems
 * escalate through the consecutive-failure counter: 3+ consecutive transient
 * errors flips to Sentry capture. Any other error is reported straight away.
 *
 * A Redis outage keeps the process alive and is retried with backoff: after
 * each failed tick the poll waits twice as long as before (10s, 20s, ... up to
 * `REDIS_OUTAGE_MAX_BACKOFF_MS`) before it tries again, so a down Redis is not
 * hammered every ten seconds, and a clean tick forgets the outage.
 */
export function createPoll({ tick, detached, sentryDsn, now = Date.now, onTick }: PollOptions): () => Promise<void> {
  const told = (outcome: TickOutcome): void => {
    try {
      onTick?.(outcome);
    } catch {
      // A record of the tick never changes what the tick did.
    }
  };
  let consecutiveTransientErrors = 0;
  let consecutiveRedisOutages = 0;
  let retryRedisAt = 0;
  return async () => {
    detached?.();
    if (consecutiveRedisOutages > 0 && now() < retryRedisAt) return;
    try {
      await tick();
    } catch (err) {
      if (isRedisOutageError(err)) {
        told({ ok: false, kind: 'redis' });
        consecutiveRedisOutages += 1;
        const waitMs = Math.min(POLL_INTERVAL_MS * 2 ** (consecutiveRedisOutages - 1), REDIS_OUTAGE_MAX_BACKOFF_MS);
        retryRedisAt = now() + waitMs;
        if (consecutiveRedisOutages >= SUSTAINED_TRANSIENT_TICKS) {
          console.error(
            '[poll] Redis unreachable for sustained outage:',
            'ticks',
            consecutiveRedisOutages,
            'wait s',
            Math.round(waitMs / 1000),
            safeErrorSummary(err),
          );
          if (sentryDsn) {
            Sentry.captureException(err, {
              tags: { source: 'worker.poll', kind: 'sustained_redis_outage' },
              extra: { consecutive_ticks: consecutiveRedisOutages },
            });
          }
        } else {
          console.warn(
            '[poll] Redis unreachable and retrying:',
            'tick',
            `${consecutiveRedisOutages}/${SUSTAINED_TRANSIENT_TICKS}`,
            'wait s',
            Math.round(waitMs / 1000),
            safeErrorSummary(err),
          );
        }
        return;
      }
      consecutiveRedisOutages = 0;
      if (isTransientDbError(err)) {
        told({ ok: false, kind: 'database' });
        consecutiveTransientErrors += 1;
        if (consecutiveTransientErrors >= SUSTAINED_TRANSIENT_TICKS) {
          console.error(
            '[poll] sustained DB issues:',
            'ticks',
            consecutiveTransientErrors,
            safeErrorSummary(err),
          );
          if (sentryDsn) {
            Sentry.captureException(err, {
              tags: { source: 'worker.poll', kind: 'sustained_db_outage' },
              extra: { consecutive_ticks: consecutiveTransientErrors },
            });
          }
        } else {
          console.warn(
            '[poll] transient DB blip:',
            'tick',
            `${consecutiveTransientErrors}/${SUSTAINED_TRANSIENT_TICKS}`,
            safeErrorSummary(err),
          );
        }
      } else {
        told({ ok: false, kind: 'other' });
        consecutiveTransientErrors = 0;
        console.error('Worker error', safeErrorSummary(err));
        if (sentryDsn) {
          Sentry.captureException(err, { tags: { source: 'worker.poll' } });
        }
      }
      return;
    }
    // On a clean tick, reset the consecutive-error counters so the next
    // transient blip starts the 3-tick countdown fresh.
    consecutiveTransientErrors = 0;
    consecutiveRedisOutages = 0;
    told({ ok: true });
  };
}
