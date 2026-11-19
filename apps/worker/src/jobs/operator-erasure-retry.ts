import type { WorkerRuntime } from '../runtime.js';

/** Claim due operator erasure jobs and retry them, at most every five minutes per worker. */
export async function runOperatorErasureRetry(deps: Pick<WorkerRuntime, 'gates'>): Promise<void> {
  const erasureResult = await deps.gates.operatorErasureRetry();
  if (erasureResult.claimed > 0) {
    console.log(
      `[ERASURE] ${erasureResult.completed} completed, ${erasureResult.pending} pending retry.`,
    );
  }
}
