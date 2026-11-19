import { AUDIT_RETENTION_DAYS, safeErrorSummary } from '@stack/shared';
import { takeDailyLock } from '../daily-lock.js';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Run the retention prune at most once per UTC day. Deletes audit_log and
 * security_events rows older than AUDIT_RETENTION_DAYS (an account's negotiated
 * override first, for the audit log), then cold segments past theirs.
 */
export async function maybeRunRetentionPrune(
  deps: Pick<WorkerRuntime, 'audit' | 'archive' | 'securityEventRepo' | 'redis'>,
  outcome?: JobOutcome,
): Promise<void> {
  const { audit, archive, securityEventRepo, redis } = deps;
  const today = new Date();
  const dateKey = `retention_pruned:${today.getUTCFullYear()}-${String(today.getUTCMonth() + 1).padStart(2, '0')}-${String(today.getUTCDate()).padStart(2, '0')}`;
  if (!(await takeDailyLock(redis, dateKey))) return;

  try {
    const auditCounts = await audit.pruneExpired(AUDIT_RETENTION_DAYS);
    const secTotal = await securityEventRepo.pruneExpired(AUDIT_RETENTION_DAYS);
    const coldCounts = await archive.pruneExpiredSegments(AUDIT_RETENTION_DAYS);
    const auditTotal = Object.values(auditCounts).reduce((a, b) => a + b, 0);
    if (auditTotal > 0 || secTotal > 0 || coldCounts.deleted > 0 || coldCounts.failed > 0) {
      console.log(
        `[RETENTION] Pruned ${auditTotal} audit rows, ${secTotal} security events, ` +
          `${coldCounts.deleted} cold segments. ${coldCounts.failed} cold segments will retry.`,
      );
    }
  } catch (err) {
    console.error('[RETENTION] Prune failed', safeErrorSummary(err));
    outcome?.failed();
  }
}
