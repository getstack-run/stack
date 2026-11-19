import { safeErrorSummary } from '@stack/shared';
import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';

/**
 * Mission auto-expiry sweep.
 *
 * Runs every 10s tick. Queries active missions whose `expires_at` has
 * passed and calls MissionService.complete({expired: true}) on each.
 * That emits a signed `mission` claim envelope with
 * terminal_state='completed_expired' AND updates the missions row
 * (completed_at + terminal_state + claim_id pointer) in one
 * transaction — the audit chain has the full lineage of the expiry
 * transition.
 *
 * Idempotency: MissionService.complete is itself idempotent (second
 * call returns transitioned=false). findExpiredActive's WHERE clause
 * excludes already-completed and already-revoked missions, so the
 * cross-tick race window is small but covered defensively. Per-mission
 * errors are caught + logged so one bad row doesn't stop the loop.
 * Cap at 100 missions per tick to keep the worker responsive — the
 * next tick picks up any remaining.
 */
export async function maybeRunMissionExpirySweep(
  deps: Pick<WorkerRuntime, 'missionRepo' | 'missionService'>,
  outcome?: JobOutcome,
): Promise<void> {
  const { missionRepo, missionService } = deps;
  let expired: Awaited<ReturnType<WorkerRuntime['missionRepo']['findExpiredActive']>>;
  try {
    expired = await missionRepo.findExpiredActive(new Date(), 100);
  } catch (err) {
    console.error('[MISSION_EXPIRY] findExpiredActive failed', safeErrorSummary(err));
    outcome?.failed();
    return;
  }
  if (expired.length === 0) return;

  let succeeded = 0;
  let failed = 0;
  for (const row of expired) {
    try {
      await missionService.complete(row.mission_id, { expired: true });
      succeeded += 1;
    } catch (err) {
      failed += 1;
      console.error('[MISSION_EXPIRY] complete failed', safeErrorSummary(err));
    }
  }
  if (failed > 0) outcome?.degraded('complete_failed');
  console.log(`[MISSION_EXPIRY] swept ${succeeded} expired missions (${failed} failed)`);
}
