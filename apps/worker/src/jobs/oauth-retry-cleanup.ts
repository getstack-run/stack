import type { WorkerRuntime } from '../runtime.js';

/**
 * Clear expired OAuth refresh-retry ciphertext, at most every five minutes per
 * worker, and delete refresh tokens long past their expiry, at most hourly.
 */
export async function runOAuthRetryCleanup(
  deps: Pick<WorkerRuntime, 'db' | 'gates'>,
): Promise<void> {
  const oauthRetryCleanupCount = await deps.gates.oauthRetryCleanup(deps.db);
  if (oauthRetryCleanupCount > 0) {
    console.log(`Cleared ${oauthRetryCleanupCount} expired OAuth retry ciphertexts`);
  }
  const pruned = await deps.gates.oauthRefreshPrune(deps.db);
  if (pruned > 0) {
    console.log(`Pruned ${pruned} expired OAuth refresh tokens`);
  }
}
