import { isRedisUnavailableError } from '@stack/shared';

/**
 * Classifies an error as a transient DB blip — the kind that resolves
 * on the next 10s tick without intervention.
 *
 * Drizzle wraps the underlying postgres-js error with a `Failed query: ...`
 * prefix at the top level, so the classifier walks up to 4 levels of `cause`
 * (pg-pool → postgres-js → Drizzle → handler is the typical depth) and
 * inspects both code and message at each level.
 */

export const TRANSIENT_DB_ERROR_CODES = new Set([
  'CONNECT_TIMEOUT', 'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT',
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_SOCKET',
  '57P01', // postgres admin_shutdown
  '57P02', // crash_shutdown
  '57P03', // cannot_connect_now
  '08006', // connection_failure
  '08001', // sqlclient_unable_to_establish_sqlconnection
]);

export const TRANSIENT_MESSAGE_RE =
  /pgbouncer|connection (?:closed|reset|terminated)|connect.*timeout|server closed the connection/i;

export function isTransientDbError(err: unknown): boolean {
  let cur: unknown = err;
  for (let depth = 0; depth < 4 && cur && typeof cur === 'object'; depth++) {
    const e = cur as { code?: string; message?: string; cause?: unknown };
    if (e.code && TRANSIENT_DB_ERROR_CODES.has(e.code)) return true;
    if (typeof e.message === 'string' && TRANSIENT_MESSAGE_RE.test(e.message)) return true;
    cur = e.cause;
  }
  return false;
}

/**
 * True when the error, or anything in its cause chain, is the Redis client
 * reporting that it cannot reach the server. Redis being down is an outage
 * the worker waits out, not a bug in a job.
 */
export function isRedisOutageError(err: unknown): boolean {
  let cur: unknown = err;
  for (let depth = 0; depth < 4 && cur && typeof cur === 'object'; depth++) {
    if (isRedisUnavailableError(cur)) return true;
    cur = (cur as { cause?: unknown }).cause;
  }
  return false;
}

/** A database blip or a Redis outage: either resolves without intervention. */
export function isTransientDependencyError(err: unknown): boolean {
  return isTransientDbError(err) || isRedisOutageError(err);
}

/** The fixed code a job's thrown error is recorded under: an unreachable Redis or database, else a plain failure. */
export function workerJobFailureCode(err: unknown): string {
  if (isRedisOutageError(err)) return 'redis_unreachable';
  if (isTransientDbError(err)) return 'database_unreachable';
  return 'failed';
}
