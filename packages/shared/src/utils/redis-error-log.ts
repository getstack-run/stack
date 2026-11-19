import { safeErrorSummary } from './safe-telemetry.js';

/** One line per window while a Redis connection keeps failing. */
export const REDIS_ERROR_LOG_WINDOW_MS = 30_000;

/**
 * How long a command on a request-path Redis client may take before it fails
 * (`Command timed out`, which `isRedisUnavailableError` reads as an outage and
 * the API answers 503). A real round trip is a few milliseconds; the cap exists
 * for a socket that is open and silent, where the client never reconnects and
 * a command would otherwise wait for ever.
 */
export const REDIS_COMMAND_TIMEOUT_MS = 2_000;

/** How long a connection attempt may take before the client tries again. */
export const REDIS_CONNECT_TIMEOUT_MS = 5_000;

/** The part of an ioredis client the listener needs. */
export interface RedisErrorSource {
  on(event: 'error', listener: (err: unknown) => void): unknown;
}

export interface RedisErrorLogOptions {
  /** Label at the start of the log line. */
  label?: string;
  windowMs?: number;
  /** Clock and sink, for tests. */
  now?: () => number;
  warn?: (message: string, summary: ReturnType<typeof safeErrorSummary>) => void;
}

/**
 * Give a Redis client an `error` listener that logs at most one line per window.
 * Without a listener ioredis prints every reconnect failure (about every ten
 * seconds, for as long as an outage lasts) with the driver's own text. The line
 * written here carries only the fixed fields of `safeErrorSummary`: never the
 * connection string, a password or the driver's message.
 */
export function logRedisErrorsThrottled(redis: RedisErrorSource, options: RedisErrorLogOptions = {}): void {
  const { label = '[redis] connection error', windowMs = REDIS_ERROR_LOG_WINDOW_MS, now = Date.now } = options;
  const warn = options.warn ?? ((message, summary) => console.warn(message, summary));
  let lastLoggedAt: number | null = null;
  redis.on('error', (err: unknown) => {
    const at = now();
    if (lastLoggedAt !== null && at - lastLoggedAt < windowMs) return;
    lastLoggedAt = at;
    warn(label, safeErrorSummary(err));
  });
}

/** An ioredis client that can be copied into another connection. */
export interface ObservableRedis extends RedisErrorSource {
  duplicate(override?: Record<string, unknown>): unknown;
}

/**
 * Attach the throttled error log to a client AND to every client derived from it
 * with `duplicate()` (the pub/sub subscribers: ioredis copies a client's options
 * to a duplicate, never its listeners). Wrapping the one factory means a client
 * added later cannot be missed. A duplicate is built without `commandTimeout`:
 * it is a subscriber, whose only commands are the subscribe and the
 * re-subscribe after a reconnect, and a silent subscriber is not an outage the
 * request path waits on.
 */
export function observeRedisClient<T extends ObservableRedis>(redis: T, options: RedisErrorLogOptions = {}): T {
  logRedisErrorsThrottled(redis, options);
  const duplicate = redis.duplicate.bind(redis);
  (redis as { duplicate: ObservableRedis['duplicate'] }).duplicate = (override) =>
    observeRedisClient(duplicate({ commandTimeout: undefined, ...override }) as T, {
      ...options,
      label: '[redis] subscriber connection error',
    });
  return redis;
}
