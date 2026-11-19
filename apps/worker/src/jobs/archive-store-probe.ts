import * as Sentry from '@sentry/node';
import { probeObjectStore, type ArchiveStoreProbeResult, type ObjectStore } from '@stack/vault';
import type { WorkerRedis } from '../redis.js';

/** Probe cadence; one worker machine in the fleet takes each window. */
export const ARCHIVE_STORE_PROBE_INTERVAL_SECONDS = 600;
const LOCK_KEY = 'archive_store_probe:lock';

/**
 * HeadBucket on the audit object store, every ten minutes under a Redis lock
 * and once at boot. The verdict goes to Redis for the admin room's health
 * view; a failure also goes to Sentry, because an unusable store means the
 * cold archive and evidence-pack exports are failing. Never throws: a Redis
 * that cannot take the lock just skips this window.
 */
export async function maybeRunArchiveStoreProbe(deps: {
  archiveStore: ObjectStore;
  redis: WorkerRedis;
  sentryDsn?: string | undefined;
}): Promise<ArchiveStoreProbeResult | null> {
  const { archiveStore, redis } = deps;
  const sentryDsn = deps.sentryDsn ?? process.env['SENTRY_DSN'];
  try {
    const acquired = await redis.set(LOCK_KEY, new Date().toISOString(), 'EX', ARCHIVE_STORE_PROBE_INTERVAL_SECONDS, 'NX');
    if (acquired !== 'OK') return null;
  } catch {
    return null;
  }
  const result = await probeObjectStore({ store: archiveStore, redis, site: 'worker' });
  if (!result.ok && sentryDsn) {
    Sentry.captureMessage('Audit object store is not usable', {
      level: 'error',
      tags: { source: 'worker.archive_store_probe', kind: 'archive_store_unreachable', reason: result.reason ?? 'unreachable' },
    });
  }
  return result;
}
