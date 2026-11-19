import { AUDIT_RETENTION_DAYS, safeErrorSummary } from '@stack/shared';
import { takeDailyLock } from '../daily-lock.js';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Run the passport_claims retention prune (AUDIT_RETENTION_DAYS for every
 * account) at most once per UTC day. Mirror of maybeRunRetentionPrune; separate Redis lock so
 * the two prunes don't block each other on contention.
 */
export async function maybeRunClaimRetentionPrune(
  deps: Pick<WorkerRuntime, 'passportClaimsRepo' | 'stackSystemOperatorId' | 'redis'>,
  outcome?: JobOutcome,
): Promise<void> {
  const { passportClaimsRepo, stackSystemOperatorId, redis } = deps;
  const today = new Date();
  const dateKey = `claim_prune_lock:${today.getUTCFullYear()}-${String(today.getUTCMonth() + 1).padStart(2, '0')}-${String(today.getUTCDate()).padStart(2, '0')}`;
  if (!(await takeDailyLock(redis, dateKey))) return;

  try {
    const total = await passportClaimsRepo.pruneExpired(AUDIT_RETENTION_DAYS, stackSystemOperatorId);
    if (total > 0) {
      console.log(`[CLAIM_RETENTION] Pruned ${total} passport_claims rows.`);
    }
  } catch (err) {
    console.error('[CLAIM_RETENTION] Prune failed', safeErrorSummary(err));
    outcome?.failed();
  }
}
