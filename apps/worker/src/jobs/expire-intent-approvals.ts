import { IntentApprovalRepository } from '@stack/vault';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Flip intent approvals still pending past their time to `expired`, so the agent reads how its request ended and a
 * person can no longer approve one that ran out. Every tick; one statement that touches only rows past their time.
 */
export async function expireIntentApprovals(
  deps: Pick<WorkerRuntime, 'db'>,
  now: Date = new Date(),
): Promise<void> {
  const swept = await new IntentApprovalRepository(deps.db as never).sweepExpired(now);
  if (swept > 0) console.log(`Expired ${swept} intent approvals nobody decided in time`);
}
