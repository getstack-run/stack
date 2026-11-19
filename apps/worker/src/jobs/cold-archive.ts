import { safeErrorSummary } from '@stack/shared';
import { takeDailyLock } from '../daily-lock.js';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Move audit rows past the hot window into cold storage, at most once per UTC
 * day.
 *
 * Separate Redis lock from the prune so a slow archive does not block the
 * prune's own window, and so a failure in one is legible on its own. Failure
 * is logged and swallowed: the rows are still in Postgres and still correct,
 * and tomorrow's run picks them up. The one thing that must not happen is
 * rows deleted without a verified segment behind them, and that guard lives
 * inside AuditArchiveService rather than here.
 */
export async function maybeRunColdArchive(
  deps: Pick<WorkerRuntime, 'archive' | 'redis'>,
  outcome?: JobOutcome,
): Promise<void> {
  const { archive, redis } = deps;
  const today = new Date();
  const dateKey = `audit_archived:${today.toISOString().slice(0, 10)}`;
  if (!(await takeDailyLock(redis, dateKey))) return;

  try {
    const results = await archive.archiveAll();
    let segments = 0;
    let rows = 0;
    let deleted = 0;
    for (const r of Object.values(results)) {
      segments += r.segmentsWritten;
      rows += r.rowsArchived;
      deleted += r.rowsDeleted;
    }
    if (segments > 0 || deleted > 0) {
      console.log(
        `[ARCHIVE] ${segments} segment(s), ${rows} rows archived, ${deleted} deleted from Postgres.`,
      );
    }
    if (rows > 0 && deleted === 0) {
      console.warn(
        '[ARCHIVE] rows archived but none deleted:',
        'the object store is not durable. ' +
          'Set AUDIT_ARCHIVE_BUCKET or Postgres will keep growing.',
      );
    }
  } catch (err) {
    console.error('[ARCHIVE] Cold archive failed', safeErrorSummary(err));
    outcome?.failed();
  }
}
