import type { JobOutcome } from '../extension.js';
import type { WorkerRuntime } from '../runtime.js';
import { maybeRunColdArchive } from './cold-archive.js';
import { maybeRunRetentionPrune } from './retention-prune.js';

/** What the retention sequence, and a deployment's hook before it, work with. */
export type AuditRetentionRuntime = Pick<WorkerRuntime, 'db' | 'redis' | 'archive' | 'audit' | 'securityEventRepo'>;

/**
 * The daily audit-retention sequence: whatever a deployment keeps of the rows
 * first (`beforeArchive`; STACK's hosted deployment rolls up usage), then cold
 * archive, then retention prune. Archive before prune, in that order and never
 * the other way round.
 *
 * What a deployment keeps of the hot rows must be durable before the archive
 * can remove them, so neither the archive nor the prune runs in a tick whose
 * `beforeArchive` did not complete. The prune enforces the tier's retention
 * window; the archive is what makes a 24-month window affordable. Running the
 * prune first would delete rows the archive was about to preserve.
 *
 * Each step holds its own daily Redis lock, so a slow archive does not block
 * the prune's own window and a failure in one is legible on its own. The guard
 * that no row is deleted without a verified segment behind it lives inside
 * `AuditArchiveService` (`packages/vault/src/services/audit-archive-service.ts`),
 * not here.
 */
export async function runAuditRetention(
  deps: AuditRetentionRuntime,
  retention: { beforeArchive?(runtime: AuditRetentionRuntime): Promise<boolean> } = {},
  outcome?: JobOutcome,
): Promise<void> {
  // With no deployment hook there is nothing to keep first.
  const preserved = retention.beforeArchive ? await retention.beforeArchive(deps) : true;

  if (preserved) {
    await maybeRunColdArchive(deps, outcome);
    await maybeRunRetentionPrune(deps, outcome);
  } else {
    outcome?.failed('rollup_incomplete');
    console.error('[RETENTION] skipped as archive prerequisite incomplete:', 'what is kept of the audit rows before the archive did not complete.');
  }
}
