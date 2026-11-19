import type { CmekMigrationWorker } from '@stack/vault';
import type { WorkerState } from '../runtime.js';

/**
 * CMEK migration tick: re-encrypt operator ciphertext page-by-page for any
 * operator in `migrating` or `revoking` status. Per-operator errors are caught
 * inside `tick()` so one bad operator does not stop the loop, and cross-machine
 * de-dup is via Redis SETNX locks acquired inside the migration worker.
 */
export async function runCmekMigrationTick(deps: {
  cmekMigrationWorker: CmekMigrationWorker;
  state: WorkerState;
}): Promise<void> {
  await deps.cmekMigrationWorker.tick();
  deps.state.cmekTickLastRanAt = new Date();
}
