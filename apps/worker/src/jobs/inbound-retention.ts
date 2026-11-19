import { INBOUND_WEBHOOK_DEDUPE_TTL_SECONDS, safeErrorSummary } from '@stack/shared';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/** One run per window across machines. Reads already hide expired messages. */
const WINDOW_SECONDS = 10 * 60;

/**
 * Inbound retention, every 10 minutes under a Redis lock: completed
 * inbound-webhook delivery receipts older than the 48-hour dedupe window are
 * deleted. Failed and in-progress receipts stay recoverable. The sweep catches
 * its own failure so it does not stop the tick.
 *
 * (STACK's hosted deployment also ages out the messages of its agent accounts,
 * in its own job at the same point of the tick.)
 */
export async function runInboundRetention(
  deps: Pick<WorkerRuntime, 'redis' | 'inboundReceiptsRepo'>,
  now: Date = new Date(),
  outcome?: JobOutcome,
): Promise<void> {
  const window = Math.floor(now.getTime() / (WINDOW_SECONDS * 1000));
  const acquired = await deps.redis.set(`inbound_retention_lock:${window}`, now.toISOString(), 'EX', WINDOW_SECONDS, 'NX');
  if (acquired !== 'OK') return;

  try {
    const cutoff = new Date(now.getTime() - INBOUND_WEBHOOK_DEDUPE_TTL_SECONDS * 1000);
    const deleted = await deps.inboundReceiptsRepo.sweepOlderThan(cutoff);
    if (deleted > 0) console.log(`[INBOUND_RETENTION] deleted ${deleted} completed inbound receipts`);
  } catch (err) {
    console.error('[INBOUND_RETENTION] inbound receipt sweep failed', safeErrorSummary(err));
    outcome?.failed();
  }
}
