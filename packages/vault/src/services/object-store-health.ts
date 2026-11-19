import type { Redis } from 'ioredis';
import { safeErrorSummary } from '@stack/shared';
import {
  ObjectStoreUnavailableError,
  type ObjectStore,
  type ObjectStoreFailureReason,
} from './object-store.js';

/** The processes that probe the audit object store and report to the admin room. */
export type ArchiveStoreSite = 'api' | 'worker';

export const ARCHIVE_STORE_SITES: readonly ArchiveStoreSite[] = ['api', 'worker'];

/**
 * A status outlives one missed probe but not a dead prober: probes run every
 * ten minutes, so an hour without a report reads as "unknown", not "ok".
 */
export const ARCHIVE_STORE_STATUS_TTL_SECONDS = 3600;

export const archiveStoreStatusKey = (site: ArchiveStoreSite): string => `archive_store_status:${site}`;

export interface ArchiveStoreProbeResult {
  ok: boolean;
  site: ArchiveStoreSite;
  checked_at: string;
  /** Present when `ok` is false. A fixed vocabulary, never provider text. */
  reason?: ObjectStoreFailureReason;
}

/**
 * Ask the store whether it is usable (HeadBucket on S3) and record the verdict
 * where the admin room reads it. Never throws: a store that is down or a
 * Redis that cannot take the status must not stop the boot or the tick that
 * called it. The provider's own error text goes to the log only.
 */
export async function probeObjectStore(deps: {
  store: ObjectStore;
  redis: Pick<Redis, 'set'>;
  site: ArchiveStoreSite;
  now?: () => Date;
}): Promise<ArchiveStoreProbeResult> {
  const { store, redis, site, now = () => new Date() } = deps;
  let result: ArchiveStoreProbeResult;
  try {
    await store.check();
    result = { ok: true, site, checked_at: now().toISOString() };
  } catch (err) {
    const failure = err instanceof ObjectStoreUnavailableError ? err.reason : 'unreachable';
    console.error(
      '[archive-store] site cannot use the audit object store:', site, failure,
      safeErrorSummary(err instanceof ObjectStoreUnavailableError && err.cause ? err.cause : err),
    );
    result = { ok: false, site, checked_at: now().toISOString(), reason: failure };
  }
  try {
    await redis.set(archiveStoreStatusKey(site), JSON.stringify(result), 'EX', ARCHIVE_STORE_STATUS_TTL_SECONDS);
  } catch (err) {
    console.warn('[archive-store] could not record the probe result', safeErrorSummary(err));
  }
  return result;
}

export interface ArchiveStoreStatus {
  status: 'ok' | 'failed' | 'unknown';
  /** The most recent probe across the sites, or null before any has reported. */
  checked_at: string | null;
  /** Each site that last reported failure, with the fixed reason. */
  failing: Array<{ site: ArchiveStoreSite; reason: ObjectStoreFailureReason }>;
}

/** The admin room's view: failed if any site failed, ok if one reported and none failed. */
export async function readArchiveStoreStatus(redis: Pick<Redis, 'mget'>): Promise<ArchiveStoreStatus> {
  const raw = await redis.mget(...ARCHIVE_STORE_SITES.map(archiveStoreStatusKey));
  const results: ArchiveStoreProbeResult[] = [];
  for (const value of raw) {
    if (!value) continue;
    try {
      const parsed = JSON.parse(value) as Partial<ArchiveStoreProbeResult>;
      if (typeof parsed.ok === 'boolean' && typeof parsed.checked_at === 'string'
        && (parsed.site === 'api' || parsed.site === 'worker')) {
        results.push(parsed as ArchiveStoreProbeResult);
      }
    } catch {
      // An unreadable value is no report; it never becomes an all-clear.
    }
  }
  if (results.length === 0) return { status: 'unknown', checked_at: null, failing: [] };
  const failing = results
    .filter((result) => !result.ok)
    .map((result) => ({ site: result.site, reason: result.reason ?? ('unreachable' as const) }));
  const checkedAt = results.map((result) => result.checked_at).sort().at(-1) ?? null;
  return { status: failing.length > 0 ? 'failed' : 'ok', checked_at: checkedAt, failing };
}
