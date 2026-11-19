import { and, isNotNull, lt, sql } from 'drizzle-orm';
import { oauthRefreshTokens, type Database } from '@stack/shared';

const OAUTH_RETRY_CLEANUP_INTERVAL_MS = 5 * 60 * 1_000;
const OAUTH_REFRESH_PRUNE_INTERVAL_MS = 60 * 60 * 1_000;

/**
 * A refresh keeps the presented row (reuse detection needs it) and adds a
 * successor, so rows pile up. A row only matters until its own expiry: a replay
 * after that is refused as expired whether or not the row exists. The week kept
 * after expiry is far longer than the 60 second retry window and the one hour
 * access-token life that a family's revocation has to outlast.
 */
export const OAUTH_REFRESH_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
export const OAUTH_REFRESH_PRUNE_BATCH = 1_000;
/** One run deletes at most this many batches; the next run carries on. */
const OAUTH_REFRESH_PRUNE_MAX_BATCHES = 20;

type CleanupRun = (db: Database) => Promise<number>;

export function createOAuthRetryCleanupGate(
  run: CleanupRun = cleanupExpiredOAuthRetryCiphertexts,
): (db: Database, now?: Date) => Promise<number> {
  let nextRunAt = Number.NEGATIVE_INFINITY;
  let inFlight = false;
  return async (db, now = new Date()) => {
    if (inFlight || now.getTime() < nextRunAt) return 0;
    inFlight = true;
    try {
      const count = await run(db);
      nextRunAt = now.getTime() + OAUTH_RETRY_CLEANUP_INTERVAL_MS;
      return count;
    } finally {
      inFlight = false;
    }
  };
}

export function createOAuthRefreshPruneGate(
  run: (db: Database) => Promise<number> = pruneExpiredOAuthRefreshTokens,
): (db: Database, now?: Date) => Promise<number> {
  let nextRunAt = Number.NEGATIVE_INFINITY;
  let inFlight = false;
  return async (db, now = new Date()) => {
    if (inFlight || now.getTime() < nextRunAt) return 0;
    inFlight = true;
    try {
      const count = await run(db);
      nextRunAt = now.getTime() + OAUTH_REFRESH_PRUNE_INTERVAL_MS;
      return count;
    } finally {
      inFlight = false;
    }
  };
}

/**
 * Delete refresh tokens that expired more than OAUTH_REFRESH_RETENTION_MS ago,
 * rotated, revoked or not, in batches that skip rows another machine has locked.
 * A live family is never touched: its head expires after every row before it.
 * Returns how many rows went.
 */
export async function pruneExpiredOAuthRefreshTokens(
  db: Database,
  now?: Date,
  options: { batchSize?: number } = {},
): Promise<number> {
  const batchSize = options.batchSize ?? OAUTH_REFRESH_PRUNE_BATCH;
  let cutoff = now ? new Date(now.getTime() - OAUTH_REFRESH_RETENTION_MS) : null;
  if (!cutoff) {
    const result = await db.execute(sql`select clock_timestamp() - (${OAUTH_REFRESH_RETENTION_MS} * interval '1 millisecond') as cutoff`);
    const value = (result as unknown as Array<{ cutoff: Date | string }>)[0]?.cutoff;
    if (!value) throw new Error('PostgreSQL did not return clock_timestamp()');
    cutoff = value instanceof Date ? value : new Date(value);
  }
  let total = 0;
  for (let batch = 0; batch < OAUTH_REFRESH_PRUNE_MAX_BATCHES; batch += 1) {
    const rows = await db.execute(sql`
      delete from oauth_refresh_tokens
      where token_hash in (
        select token_hash from oauth_refresh_tokens
        where expires_at < ${cutoff.toISOString()}::timestamptz
        limit ${batchSize}
        for update skip locked
      )
      returning token_hash`);
    const deleted = (rows as unknown as unknown[]).length;
    total += deleted;
    if (deleted < batchSize) break;
  }
  return total;
}

/**
 * Remove recoverable refresh successors after the fixed retry window.
 * Rows without a deadline are legacy rows. This sweep does not change them.
 */
export async function cleanupExpiredOAuthRetryCiphertexts(
  db: Database,
  now?: Date,
): Promise<number> {
  return db.transaction(async (tx) => {
    let cutoff = now;
    if (!cutoff) {
      const result = await tx.execute(sql`select clock_timestamp() as now`);
      const value = (result as unknown as Array<{ now: Date | string }>)[0]?.now;
      if (!value) throw new Error('PostgreSQL did not return clock_timestamp()');
      cutoff = value instanceof Date ? value : new Date(value);
    }
    const rows = await tx
      .update(oauthRefreshTokens)
      .set({ replacement_token_encrypted: null })
      .where(and(
        isNotNull(oauthRefreshTokens.replacement_token_encrypted),
        isNotNull(oauthRefreshTokens.replacement_retry_expires_at),
        lt(oauthRefreshTokens.replacement_retry_expires_at, cutoff),
      ))
      .returning({ token_hash: oauthRefreshTokens.token_hash });
    return rows.length;
  });
}
